"""Reverse proxy in front of DVWA. It is BOTH the log source and the
enforcement point: every request is logged to events.jsonl, and requests from
a blacklisted IP or matching an active WAF rule get a 403 before they ever
reach the app. Also serves the dashboard (/__dashboard) and its data (/__state).

# ponytail: demo proxy — no TLS, naive forwarding, single worker, body buffered
# in memory. Swap for Caddy + ModSecurity if it must survive real traffic.
"""
import asyncio
import json
import os
import re
from pathlib import Path
from urllib.parse import unquote_plus

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse

import store

DVWA_URL = os.environ.get("DVWA_URL", "http://localhost:80")
HONEYPOT_URL = os.environ.get("HONEYPOT_URL")  # decoy base url; divert disabled if unset
BASE = Path(__file__).resolve().parent

app = FastAPI()
client = httpx.AsyncClient(base_url=DVWA_URL, follow_redirects=False, timeout=15)
honeypot_client = (httpx.AsyncClient(base_url=HONEYPOT_URL, follow_redirects=False, timeout=15)
                   if HONEYPOT_URL else None)

# hop-by-hop headers we must not forward verbatim
HOP = {"connection", "keep-alive", "transfer-encoding", "te", "trailer",
       "upgrade", "proxy-authorization", "proxy-authenticate",
       "content-length", "host",
       # httpx already decompresses up.content, so a forwarded Content-Encoding
       # header would make the client double-decode. Strip it both ways.
       "content-encoding"}

# compiled-rule cache, refreshed when state.json's mtime changes
_cache = {"mtime": -1.0, "state": store.DEFAULT_STATE, "rules": []}


def get_state():
    try:
        m = store.STATE_FILE.stat().st_mtime
    except FileNotFoundError:
        return store.load_state(), []
    if m != _cache["mtime"]:
        st = store.load_state()
        compiled = []
        for r in st.get("rules", []):
            try:
                compiled.append((re.compile(r["pattern"], re.I), r.get("description", "")))
            except re.error:
                pass
        _cache.update(mtime=m, state=st, rules=compiled)
    return _cache["state"], _cache["rules"]


def _enforce_security_cookie(cookie_header, level):
    """Strip any client-chosen `security` cookie and pin it to `level`, leaving other
    cookies (PHPSESSID, …) intact. Closes the 'just set security=low' bypass after
    patch_vuln raises the enforced level; a null level means pass-through (handled by
    the caller, which only calls this when a level is set)."""
    pairs = [c.strip() for c in (cookie_header or "").split(";") if c.strip()]
    kept = [c for c in pairs if c.split("=", 1)[0].strip().lower() != "security"]
    kept.append(f"security={level}")
    return "; ".join(kept)


def source_ip(request: Request) -> str:
    # ponytail: trust X-Forwarded-For for source IP (demo — lets the "external"
    # attacker have a distinct IP from localhost). NEVER trust XFF in production.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _event(ip, method, path, qs, body, status, blocked, matched):
    # Decode for display + detection so URL-encoded payloads (%27 -> ') are
    # human-readable and matchable. Forwarding still uses the original bytes.
    return {
        "ts": store.now(), "ip": ip, "method": method, "path": "/" + path,
        "query": unquote_plus(qs),
        "body": unquote_plus(body.decode("utf-8", "ignore"))[:300],
        "status": status, "blocked": blocked, "matched": matched,
    }


@app.get("/__dashboard", response_class=HTMLResponse)
async def dashboard():
    return (BASE / "dashboard.html").read_text()


# Files whose mtime changing means "something happened" (for SSE push).
_WATCH = [store.EVENTS_FILE, store.STATE_FILE, store.INCIDENTS_FILE, store.ACTIONS_FILE,
          store.DVWA_LOG, store.PROXY_LOG, store.BLUE_LOG, store.RED_LOG]


def build_state():
    """Everything the dashboard renders, in one snapshot."""
    st, _ = get_state()
    return {
        "events": store.read_jsonl(store.EVENTS_FILE, limit=200)[::-1],
        "events_total": store.count_lines(store.EVENTS_FILE),
        "actions": store.read_jsonl(store.ACTIONS_FILE, limit=400)[::-1],
        "incidents": store.read_jsonl(store.INCIDENTS_FILE)[::-1],
        "denylist": st.get("denylist", []),
        "rules": st.get("rules", []),
        "logs": {
            "dvwa": store.tail_lines(store.DVWA_LOG),
            "proxy": store.tail_lines(store.PROXY_LOG),
            "blue": store.tail_lines(store.BLUE_LOG),
            "red": store.tail_lines(store.RED_LOG),
        },
    }


def _watch_sig():
    sig = []
    for p in _WATCH:
        try:
            sig.append(p.stat().st_mtime)
        except FileNotFoundError:
            sig.append(0.0)
    return tuple(sig)


@app.get("/__state")
async def state_api():
    return JSONResponse(build_state())


@app.get("/__stream")
async def stream_api():
    """Server-Sent Events: push a fresh snapshot whenever any watched file changes."""
    async def gen():
        last = None
        beat = 0
        while True:
            sig = _watch_sig()
            if sig != last:
                last = sig
                yield "data: " + json.dumps(build_state()) + "\n\n"
            else:
                beat += 1
                if beat % 20 == 0:  # ~10s keep-alive comment
                    yield ": keep-alive\n\n"
            await asyncio.sleep(0.5)
    return StreamingResponse(gen(), media_type="text/event-stream")


@app.api_route("/{path:path}",
               methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy(path: str, request: Request):
    ip = source_ip(request)
    body = await request.body()
    qs = request.url.query
    # Decode before WAF matching so rules written against readable payloads
    # (e.g. 'union\s+select') catch url-encoded attacks too.
    probe = f"{request.method} /{path}?{unquote_plus(qs)} {unquote_plus(body.decode('utf-8', 'ignore'))}"
    st, rules = get_state()

    # 0. Honeypot divert — DELIBERATELY takes precedence over the denylist AND WAF rules
    #    below. A studied attacker should keep reaching the decoy with ALL their traffic
    #    (even payloads that would otherwise 403): a block tips them off and ends the TTP
    #    harvest, a silent divert does not. To fully cut an IP off, undivert it first, then
    #    the denylist 403 applies. Logged as 'diverted' (blocked=False), never a block.
    if honeypot_client is not None and any(d["ip"] == ip for d in st.get("honeypot", [])):
        hp_headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP}
        hp_headers["accept-encoding"] = "identity"
        try:
            up = await honeypot_client.request(request.method, "/" + path,
                                               params=dict(request.query_params),
                                               content=body, headers=hp_headers)
        except httpx.HTTPError as e:
            store.append_jsonl(store.EVENTS_FILE,
                               _event(ip, request.method, path, qs, body, 502, False, "diverted"))
            return JSONResponse({"error": "upstream", "detail": str(e)}, status_code=502)
        store.append_jsonl(store.EVENTS_FILE,
                           _event(ip, request.method, path, qs, body, up.status_code, False, "diverted"))
        resp_headers = {k: v for k, v in up.headers.items() if k.lower() not in HOP}
        return Response(content=up.content, status_code=up.status_code, headers=resp_headers)

    # 1. IP denylist (skip entries whose TTL has expired — provisional reflex bans
    #    auto-lift; a null/absent 'expires' is a permanent ban)
    _now = store.now()
    if any(d["ip"] == ip and (not d.get("expires") or d["expires"] > _now)
           for d in st.get("denylist", [])):
        store.append_jsonl(store.EVENTS_FILE,
                           _event(ip, request.method, path, qs, body, 403, True, "denylist"))
        return JSONResponse({"error": "blocked",
                             "reason": "source IP blacklisted by blue-team agent"},
                            status_code=403)

    # 2. WAF rules (virtual patch)
    for rx, desc in rules:
        if rx.search(probe):
            store.append_jsonl(store.EVENTS_FILE,
                               _event(ip, request.method, path, qs, body, 403, True, desc))
            return JSONResponse({"error": "blocked", "reason": f"WAF rule: {desc}"},
                                status_code=403)

    # 3. forward to DVWA
    fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in HOP}
    fwd_headers["accept-encoding"] = "identity"  # no compression: keeps responses
    #                                              plaintext for logging/inspection
    level = st.get("enforced_security")          # set by patch_vuln on a confirmed raise
    if level:  # pin the server security posture; ignore the client's `security` cookie
        fwd_headers["cookie"] = _enforce_security_cookie(fwd_headers.get("cookie"), level)
    try:
        up = await client.request(request.method, "/" + path,
                                  params=dict(request.query_params),
                                  content=body, headers=fwd_headers)
    except httpx.HTTPError as e:
        store.append_jsonl(store.EVENTS_FILE,
                           _event(ip, request.method, path, qs, body, 502, False, None))
        return JSONResponse({"error": "upstream", "detail": str(e)}, status_code=502)

    store.append_jsonl(store.EVENTS_FILE,
                       _event(ip, request.method, path, qs, body, up.status_code, False, None))
    resp_headers = {k: v for k, v in up.headers.items() if k.lower() not in HOP}
    return Response(content=up.content, status_code=up.status_code, headers=resp_headers)
