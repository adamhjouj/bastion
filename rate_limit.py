"""Bounded single-worker sliding-window capacity limiter, not attack detection.

Multi-worker deployments must use a shared limiter. This stack deliberately runs
one ingress worker; model spend is additionally enforced transactionally in SQLite.
"""
import collections
import os
import time

RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX", "100"))
RATE_LIMIT_WINDOW = float(os.getenv("RATE_LIMIT_WINDOW", "10"))
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "1") != "0"
MAX_IDENTITIES = int(os.getenv("RATE_LIMIT_IDENTITIES", "10000"))
_hits = collections.OrderedDict()


def limited(ip):
    if not RATE_LIMIT_ENABLED:
        return False
    now = time.monotonic()
    # Ordered by last activity; expire idle identities without unbounded growth.
    while _hits:
        _, stamps = next(iter(_hits.items()))
        if stamps and stamps[-1] > now - RATE_LIMIT_WINDOW:
            break
        _hits.popitem(last=False)
    dq = _hits.get(ip)
    if dq is None:
        if len(_hits) >= MAX_IDENTITIES:
            return True  # overload, not a maliciousness verdict
        dq = _hits[ip] = collections.deque()
    while dq and dq[0] <= now - RATE_LIMIT_WINDOW:
        dq.popleft()
    if len(dq) >= RATE_LIMIT_MAX:
        return True
    dq.append(now)
    _hits.move_to_end(ip)
    return False


def retry_after():
    import math
    return max(1, math.ceil(RATE_LIMIT_WINDOW))


def reset():
    _hits.clear()
