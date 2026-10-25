"""Adaptive decoy: learn the protected app's shape, synthesise look-alike responses, record TTPs.
See docs/DECOY.md. The proxy only ever calls `observe()` (CONTRACTS §4.3)."""
import threading

from bastion import store as _store
from bastion.decoy.shape import BODY_LIMIT  # noqa: F401  (re-exported for the proxy hook)

PASSIVE_FILE = "passive.json"
CRAWL_FILE = "crawl.json"
_learner = None
_lock = threading.Lock()


def data_dir():
    return _store.DATA / "decoy"


def learner():
    """Process-wide passive learner (created lazily so importing the package has no side effects)."""
    global _learner
    with _lock:
        if _learner is None or _learner.path != data_dir() / PASSIVE_FILE:
            from bastion.decoy.learn import PassiveLearner
            _learner = PassiveLearner(data_dir() / PASSIVE_FILE)
        return _learner


def observe(method, path, query, status, headers, body, latency_ms=None, request_body="",
            request_content_type="", malicious=False):
    """Non-blocking: enqueue one forwarded (request facts, response) pair for learning.
    `query`/`request_body` must already be redacted (privacy.request_view output). Returns
    True if queued. Never raises on bad input beyond what the caller's guard swallows."""
    if malicious or status is None:
        return False
    if not isinstance(body, (bytes, bytearray)):
        body = str(body or "").encode("utf-8", "replace")
    sample = {"method": str(method), "path": str(path), "query": str(query or ""),
              "status": int(status), "headers": list(headers or ()), "body": bytes(body[:BODY_LIMIT]),
              "latency_ms": latency_ms, "request_body": str(request_body or "")[:4096],
              "request_content_type": str(request_content_type or "")}
    return learner().observe(sample)


def stats():
    lr = _learner
    if lr is None:
        return {"queued": 0, "learned": 0, "dropped": 0}
    return {"queued": lr.queue.qsize(), "learned": lr.learned, "dropped": lr.dropped,
            "routes": len(lr.store.routes)}
