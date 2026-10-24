"""Per-source-IP rate limiter: cap requests per sliding window so an attacker
can't hammer / brute-force / scrape the app even when no WAF rule matches.
Infrastructure-harm prevention, SEPARATE from the WAF (virtual patches).

Proxy contract (the owning session wires this in ONE line, positioned AFTER the
honeypot-divert and denylist checks — so diverted/banned IPs are handled first —
and before/around the WAF rules):

    if rate_limit.limited(ip):
        store.append_jsonl(store.EVENTS_FILE,
                           _event(ip, request.method, path, qs, body, 429, True, "rate_limit"))
        return JSONResponse({"error": "rate_limited", "reason": "too many requests"},
                            status_code=429,
                            headers={"Retry-After": str(rate_limit.retry_after())})

Calibration knobs (read from env at import):
    RATE_LIMIT_MAX     int    max requests per window (default 100)
    RATE_LIMIT_WINDOW  float  sliding window, seconds (default 10.0)
    RATE_LIMIT_ENABLED bool   env "RATE_LIMIT_ENABLED" != "0" (default enabled)

Internal state: _hits maps ip -> collections.deque of time.monotonic() stamps.
(The E2E test rewinds these stamps by >WINDOW to exercise window recovery.)
"""
import collections
import os
import time

RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX", "100"))
RATE_LIMIT_WINDOW = float(os.environ.get("RATE_LIMIT_WINDOW", "10.0"))
RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "1") != "0"

# ponytail: single async worker + in-memory dict → no lock needed (limited() runs
# to completion on the event loop, no await inside) and state dies on restart.
# _hits grows one deque per distinct IP with no eviction — fine at demo scale, but
# a multi-worker deploy (or unbounded distinct IPs) needs a shared store like Redis
# plus TTL/LRU eviction of idle IPs.
_hits = collections.defaultdict(collections.deque)


def limited(ip: str) -> bool:
    """True if `ip` exceeded RATE_LIMIT_MAX requests in the last RATE_LIMIT_WINDOW
    seconds (caller should 429); else records this request and returns False.
    Disabled → always False, records nothing. A rejected request is NOT recorded,
    so it doesn't extend the window (standard sliding window)."""
    if not RATE_LIMIT_ENABLED:
        return False
    now = time.monotonic()
    dq = _hits[ip]
    cutoff = now - RATE_LIMIT_WINDOW
    while dq and dq[0] <= cutoff:
        dq.popleft()
    if len(dq) >= RATE_LIMIT_MAX:
        return True
    dq.append(now)
    return False


def retry_after() -> int:
    """Seconds for the proxy's Retry-After header."""
    return int(RATE_LIMIT_WINDOW)


def reset():
    """Clear all state (for tests)."""
    _hits.clear()
