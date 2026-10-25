"""Decoy web app. When the blue team confirms an attacker, the proxy diverts their traffic here
instead of the real app — they keep probing a convincing fake while we remediate. Every hit is
logged to the honeypot_hits stream so we bank their TTPs (paths, payloads, tooling).

The responses come from bastion.decoy (docs/DECOY.md): a shape model of the real app learned
passively from proxy traffic and, optionally, an active GET-only crawl; per-session cache →
learned template + fake data → time-boxed LLM synthesis → learned error page → identity-consistent fallback.
Nothing in this process ever forwards a request to the real app.
"""
import asyncio
import contextlib
import os
import threading
import time

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

from bastion import store
from bastion.decoy import CRAWL_FILE, data_dir
from bastion.decoy import record
from bastion.decoy.learn import crawl_forever
from bastion.decoy.session import Sessions
from bastion.decoy.shape import ShapeFiles
from bastion.decoy.synth import Decoy, DecoyRequest

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
RATE_MAX = int(os.getenv("DECOY_RATE_MAX", "120"))
RATE_WINDOW = float(os.getenv("DECOY_RATE_WINDOW", "10"))
MAX_BODY = 64 * 1024


class _RateLimiter:
    """Per-IP fixed window; the proxy's own limiter never sees diverted traffic."""

    def __init__(self, limit=RATE_MAX, window=RATE_WINDOW):
        self.limit, self.window = limit, window
        self.lock = threading.Lock()
        self.buckets = {}

    def limited(self, ip):
        now = time.monotonic()
        with self.lock:
            start, n = self.buckets.get(ip, (now, 0))
            if now - start >= self.window:
                start, n = now, 0
            n += 1
            self.buckets[ip] = (start, n)
            if len(self.buckets) > 10000:
                self.buckets = {k: v for k, v in self.buckets.items() if now - v[0] < self.window}
            return n > self.limit

    def retry_after(self):
        return int(self.window)


@contextlib.asynccontextmanager
async def lifespan(app):
    stop = threading.Event()
    target = os.getenv("DECOY_CRAWL_URL", "").strip()
    crawler = None
    if target:
        crawler = threading.Thread(
            target=crawl_forever, name="decoy-crawler", daemon=True,
            args=(target, data_dir() / CRAWL_FILE, int(os.getenv("DECOY_CRAWL_PAGES", "40")),
                  int(os.getenv("DECOY_CRAWL_INTERVAL", "900")), stop))
        crawler.start()
    try:
        yield
    finally:
        stop.set()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.state.shapes = None
app.state.sessions = Sessions()
app.state.decoy = None
app.state.limiter = _RateLimiter()


def _decoy():
    # store.DATA is read at call time so a test can monkeypatch it to a tempdir.
    if app.state.shapes is None or app.state.shapes.directory != data_dir():
        app.state.shapes = ShapeFiles(data_dir())
        app.state.decoy = Decoy(app.state.shapes.current, app.state.sessions)
    return app.state.decoy


def _ip(request: Request) -> str:
    # X-Forwarded-For first hop if present, else client host (matches proxy.source_ip).
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.get("/__health")
async def health():
    """Container healthcheck. The proxy never forwards `/__*` paths, so no visitor can reach this;
    it is not logged as a hit and never triggers synthesis."""
    engine = _decoy()
    return {"ok": True, "routes": len(engine.shape_fn().routes), "sessions": len(engine.sessions), **engine.stats}


@app.api_route("/{path:path}", methods=METHODS)
async def decoy(path: str, request: Request):
    body = (await request.body())[:MAX_BODY]
    ip = _ip(request)
    ua = request.headers.get("user-agent", "")
    ct = request.headers.get("content-type", "")
    query = request.url.query
    engine = _decoy()
    session = engine.sessions.get(ip, ua)
    form_pairs = record.form_view(body.decode("utf-8", "ignore")) if "application/x-www-form-urlencoded" in ct else []
    tags = record.tag_request(request.method, "/" + path, query, body.decode("utf-8", "ignore")[:4096],
                              ua, form_pairs, session)
    if app.state.limiter.limited(ip):
        record.log_hit(ip, request.method, "/" + path, query, body, ct, ua, session, 429, "rate_limit", tags)
        return JSONResponse({"error": "capacity limit"}, status_code=429,
                            headers={"Retry-After": str(app.state.limiter.retry_after())})
    req = DecoyRequest(request.method, "/" + path, query, body, ct, ua, ip)
    resp = await engine.respond(req, session)
    record.log_hit(ip, request.method, "/" + path, query, body, ct, ua, session, resp.status, resp.source, tags)
    delay = float(os.environ.get("HONEYPOT_DELAY", "0")) + resp.latency_ms / 1000.0
    if delay > 0:
        await asyncio.sleep(delay)  # tarpit + learned latency: stall the attacker without blocking the loop
    out = Response(resp.body, status_code=resp.status)
    out.raw_headers = [(k.lower().encode("latin-1"), v.encode("latin-1", "replace")) for k, v in resp.headers]
    return out


if __name__ == "__main__":
    # No uvicorn `server:` header: the learned Server fingerprint is emitted per response instead.
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("HONEYPOT_PORT", "9000")),
                server_header=False, date_header=True)
