"""Reverse proxy in front of DVWA. It is BOTH the log source and the
enforcement point: every request is logged to events.jsonl, and requests from
a blacklisted IP or matching an active WAF rule get a 403 before they ever
reach the app. Also serves the dashboard (/__dashboard) and its data (/__state).

# ponytail: demo proxy — no TLS, naive forwarding, single worker, body buffered
# in memory. Swap for Caddy + ModSecurity if it must survive real traffic.
"""
import os
import re
from pathlib import Path
from urllib.parse import unquote_plus

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response

import store

DVWA_URL = os.environ.get("DVWA_URL", "http://localhost:80")
BASE = Path(__file__).resolve().parent

app = FastAPI()
client = httpx.AsyncClient(base_url=DVWA_URL, follow_redirects=False, timeout=15)

# hop-by-hop headers we must not forward verbatim
HOP = {"connection", "keep-alive", "transfer-encoding", "te", "trailer",
       "upgrade", "proxy-authorization", "proxy-authenticate",
       "content-length", "host"}

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


@app.get("/__state")
async def state_api():
    st, _ = get_state()
    return JSONResponse({
        "events": store.read_jsonl(store.EVENTS_FILE, limit=200)[::-1],
        "incidents": store.read_jsonl(store.INCIDENTS_FILE)[::-1],
        "denylist": st.get("denylist", []),
        "rules": st.get("rules", []),
    })


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

    # 1. IP denylist
    if any(d["ip"] == ip for d in st.get("denylist", [])):
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
