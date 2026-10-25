"""Bounded ingress with optional inline Jev, authenticated management and durable events."""
import asyncio
import contextlib
import json
import os
import time
import uuid

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from bastion import rate_limit
from bastion import store
from bastion.classifier import AsyncClassifier
from bastion.dashboard_api import router as dashboard_router
from bastion.dashboard_ui import router as dashboard_ui_router
from bastion.audit import router as audit_router  # tamper-evident action log API
from bastion.privacy import request_view
from bastion.security import authorize, match_vpatch, source_ip as resolve_source
from bastion.settings import Settings

HOP = {"connection", "keep-alive", "transfer-encoding", "te", "trailer", "upgrade",
       "proxy-authorization", "proxy-authenticate", "content-length", "host", "content-encoding"}


def _enforce_security_cookie(cookie_header, level):
    kept = [p.strip() for p in (cookie_header or "").split(";") if p.strip() and p.split("=", 1)[0].strip().lower() != "security"]
    return "; ".join(kept + [f"security={level}"])


def get_state():
    return store.load_state()


def build_state():
    return store.snapshot()


def source_ip(request):
    return resolve_source(request, request.app.state.settings)


def create_app(settings=None, upstream_transport=None, classifier_transport=None):
    policy = settings or Settings.from_env()

    @contextlib.asynccontextmanager
    async def lifespan(app):
        policy.validate()
        if policy.dashboard_no_auth:
            print("[bastion] WARNING: DASHBOARD_NO_AUTH=1 \u2014 /__dash and /__api are UNAUTHENTICATED (dev only; do not expose port 8080)", flush=True)
        store.initialize()
        get_http()
        get_classifier()
        store.set_health("proxy", {"mode": policy.mode, "ready": True,
                                   "warning": "no payload protection" if policy.mode == "observe" else None})
        async def heartbeat():
            while True:
                await asyncio.sleep(10)
                await asyncio.to_thread(store.touch_health, "proxy")
        pulse = asyncio.create_task(heartbeat())
        try:
            yield
        finally:
            pulse.cancel()
            await asyncio.gather(pulse, return_exceptions=True)
            await app.state.http.aclose()
            await app.state.classifier.close()
            store.set_health("proxy", {"mode": policy.mode, "ready": False})

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = policy

    def get_http():
        if getattr(app.state, "http", None) is None or app.state.http.is_closed:
            app.state.http = httpx.AsyncClient(timeout=15, follow_redirects=False, transport=upstream_transport,
                                              limits=httpx.Limits(max_connections=32, max_keepalive_connections=16))
        return app.state.http

    def get_classifier():
        if getattr(app.state, "classifier", None) is None or app.state.classifier.client.is_closed:
            app.state.classifier = AsyncClassifier(policy, transport=classifier_transport)
        return app.state.classifier

    @app.middleware("http")
    async def management_boundary(request, call_next):
        # DASHBOARD_NO_AUTH=1 (dev convenience) leaves the whole /__ boundary open.
        if request.url.path.startswith("/__") and not policy.dashboard_no_auth:
            try:
                authorize(request, policy.management_token)
            except HTTPException as exc:
                return JSONResponse({"error": exc.detail}, status_code=exc.status_code, headers=exc.headers)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/__"):
            response.headers["Cache-Control"] = "no-store"
            response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        return response

    @app.get("/__health")
    async def health():
        return {"mode": policy.mode, "ready": True, "health": store.snapshot()["health"]}

    @app.get("/__state")
    async def state_api():
        return build_state()

    @app.get("/__stream")
    async def stream(request: Request):
        async def generate():
            last = None
            while not await request.is_disconnected():
                snapshot = json.dumps(build_state(), sort_keys=True)
                if snapshot != last:
                    last = snapshot
                    yield "data: " + snapshot + "\n\n"
                else:
                    yield ": keep-alive\n\n"
                await asyncio.sleep(1)
        return StreamingResponse(generate(), media_type="text/event-stream")

    app.include_router(dashboard_router)
    app.include_router(dashboard_ui_router)  # operator SPA at /__dash (auth + CSP inherited)
    app.include_router(audit_router)  # /__api/v1/audit/* (auth inherited from the /__ middleware)

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    async def forward(path: str, request: Request):
        if path.startswith("__"):
            raise HTTPException(404, "management route not found")
        ip = source_ip(request)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > policy.request_limit:
                return JSONResponse({"error": "request too large"}, status_code=413)
        raw_query = request.scope["query_string"]
        event = request_view(request.method, "/" + path, raw_query.decode("ascii", "replace"),
                             body.decode("utf-8", "replace"), request.headers.get("content-type", ""))
        event.update(ts=store.now(), ip=ip, request_id=uuid.uuid4().hex, blocked=False,
                     status=None, matched=None, mode=policy.mode, truncated=False)
        try:
            event_id = store.reserve_event(event, policy.queue_limit)
        except OverflowError:
            store.set_health("queue", {"available": False, "error": "capacity exhausted"})
            return JSONResponse({"error": "investigation capacity exhausted"}, status_code=503, headers={"Retry-After": "5"})
        event["case_id"] = str(event_id)
        started = time.monotonic()

        def result(response, matched=None, blocked=False):
            event.update(status=response.status_code, matched=matched, blocked=blocked,
                         duration_ms=round((time.monotonic() - started) * 1000))
            store.finalize_event(event_id, event, observe=policy.mode == "observe")
            response.headers["X-Request-ID"] = event["request_id"]
            return response

        st = store.load_state()
        honeypot_url = os.getenv("HONEYPOT_URL", "")
        divert = bool(honeypot_url and any(d["ip"] == ip for d in st.get("honeypot", [])))
        if not divert:
            if any(d["ip"] == ip and store.active_ban(d) for d in st.get("denylist", [])):
                return result(JSONResponse({"error": "blocked"}, status_code=403), "denylist", True)
            # Agent-authored virtual patch: deterministic rule blocking a confirmed exploit
            # pattern on a route, for ALL sources, in every mode. Match decoded query + body.
            from urllib.parse import unquote_plus
            if match_vpatch(st.get("vpatch", []), path,
                            unquote_plus(raw_query.decode("utf-8", "replace")) + "\n" +
                            unquote_plus(bytes(body).decode("utf-8", "replace"))):
                return result(JSONResponse({"error": "blocked by virtual patch"}, status_code=403), "vpatch", True)
            if rate_limit.limited(ip):
                return result(JSONResponse({"error": "capacity limit"}, status_code=429,
                                          headers={"Retry-After": str(rate_limit.retry_after())}), "rate_limit", True)
            if policy.mode == "inline":
                clf_instance = get_classifier()
                verdict = await clf_instance.classify(event)
                event["verdict"] = verdict
                if verdict.get("malicious") is True:
                    return result(JSONResponse({"error": "blocked by classifier"}, status_code=403), "classifier", True)
                if verdict.get("error") and policy.inline_failure == "reject":
                    return result(JSONResponse({"error": "classifier unavailable"}, status_code=503), "classifier_unavailable", True)

        target = honeypot_url if divert else os.getenv("DVWA_URL", "http://dvwa:80")
        headers = [(k, v) for k, v in request.headers.items() if k.lower() not in HOP and k.lower() not in {"cookie", "x-forwarded-for", "authorization"}]
        # Do not forward management credentials or untrusted attribution.
        headers.extend([("accept-encoding", "identity"), ("x-forwarded-for", ip)])
        cookie = request.headers.get("cookie", "")
        if st.get("enforced_security") and not divert:
            cookie = _enforce_security_cookie(cookie, st["enforced_security"])
        headers.append(("cookie", cookie))  # explicit even if empty: no shared client-cookie leakage
        upstream_ms = None
        try:
            url = httpx.URL(target).copy_with(path="/" + path, query=raw_query)
            http = get_http()
            upstream_started = time.monotonic()
            async with http.stream(request.method, url, headers=headers, content=bytes(body)) as up:
                content = bytearray()
                async for chunk in up.aiter_bytes():
                    content.extend(chunk)
                    if len(content) > policy.response_limit:
                        raise ValueError("upstream response too large")
                response = Response(bytes(content), status_code=up.status_code)
                # Preserve multiple Set-Cookie headers instead of collapsing into a dict.
                response.raw_headers.extend([(k, v) for k, v in up.headers.raw if k.decode().lower() not in HOP])
                upstream_ms = round((time.monotonic() - upstream_started) * 1000)
        except (httpx.HTTPError, ValueError):
            response = JSONResponse({"error": "upstream unavailable or response too large"}, status_code=502)
        if upstream_ms is not None and not divert:
            try:  # CONTRACTS §4.3: the decoy's passive learner; fire-and-forget, never affects forwarding
                from bastion import decoy
                decoy.observe(event["method"], event["path"], event["query"], response.status_code,
                              response.raw_headers, bytes(content[:decoy.BODY_LIMIT]), upstream_ms,
                              event["body"], event["content_type"],
                              malicious=bool((event.get("verdict") or {}).get("malicious")))
            except Exception:
                pass
        return result(response, "diverted" if divert else None)

    return app


app = create_app()
