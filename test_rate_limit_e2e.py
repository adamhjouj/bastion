"""End-to-end test of the per-IP rate limiter, proving the contract the proxy
will wire in: an IP that exceeds the limit gets 429 + Retry-After, other IPs are
unaffected, the sliding window recovers, and the disabled path never limits.

Fully in-process: FastAPI + httpx.ASGITransport, no ports/docker/network. Does
NOT import or edit proxy.py — source_ip() is copied verbatim below, and the shim
faithfully mirrors proxy.py's future rate-limit branch (see rate_limit.py docstring).
"""
import asyncio

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

import rate_limit

# 1. Deterministic small limits (overriding the env-derived defaults) + clean slate.
rate_limit.RATE_LIMIT_MAX = 5
rate_limit.RATE_LIMIT_WINDOW = 10.0
rate_limit.RATE_LIMIT_ENABLED = True
rate_limit.reset()

ATTACKER = "10.13.37.7"
BYSTANDER = "203.0.113.9"


# --- source_ip(): copied VERBATIM from proxy.py (do not edit) -----------------
def source_ip(request: Request) -> str:
    # ponytail: trust X-Forwarded-For for source IP (demo — lets the "external"
    # attacker have a distinct IP from localhost). NEVER trust XFF in production.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# 2. Stub "real app" the proxy would forward to.
real_app = FastAPI()


@real_app.api_route("/{path:path}",
                    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def real(path: str):
    return PlainTextResponse("REAL-APP-OK")


# 3. Proxy rate-limit SHIM: mirrors proxy.py's future branch (per rate_limit.py docstring).
shim = FastAPI()


@shim.api_route("/{path:path}",
                methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy_shim(path: str, request: Request):
    ip = source_ip(request)
    if rate_limit.limited(ip):
        return JSONResponse({"error": "rate_limited", "reason": "too many requests"},
                            status_code=429,
                            headers={"Retry-After": str(rate_limit.retry_after())})
    body = await request.body()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=real_app),
                                 base_url="http://t") as up_client:
        up = await up_client.request(request.method, "/" + path, content=body)
    return Response(content=up.content, status_code=up.status_code)


async def get(client, ip, path="/login"):
    return await client.get(path, headers={"X-Forwarded-For": ip})


async def main():
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=shim),
                                 base_url="http://t") as c:
        # First RATE_LIMIT_MAX requests from attacker pass through to the real app.
        for i in range(1, rate_limit.RATE_LIMIT_MAX + 1):
            r = await get(c, ATTACKER)
            assert r.status_code == 200, \
                f"attacker req #{i}: expected 200, got {r.status_code}"
            assert r.text == "REAL-APP-OK", \
                f"attacker req #{i}: expected body 'REAL-APP-OK', got {r.text!r}"

        # The next one is over the limit -> 429 with a correct Retry-After header.
        r = await get(c, ATTACKER)
        assert r.status_code == 429, \
            f"attacker over-limit req: expected 429, got {r.status_code}"
        expected_ra = str(rate_limit.retry_after())
        assert r.headers.get("Retry-After") == expected_ra, \
            f"Retry-After: expected {expected_ra!r}, got {r.headers.get('Retry-After')!r}"

        # Per-IP isolation: a different IP is untouched by the attacker's limit.
        r = await get(c, BYSTANDER)
        assert r.status_code == 200, \
            f"bystander {BYSTANDER}: expected 200 (isolation), got {r.status_code}"
        assert r.text == "REAL-APP-OK", \
            f"bystander {BYSTANDER}: expected body 'REAL-APP-OK', got {r.text!r}"

        # Window recovery: rewind the attacker's stamps past the window, then it's clear.
        import collections
        rate_limit._hits[ATTACKER] = collections.deque(
            t - (rate_limit.RATE_LIMIT_WINDOW + 1) for t in rate_limit._hits[ATTACKER])
        r = await get(c, ATTACKER)
        assert r.status_code == 200, \
            f"attacker after window slid: expected 200, got {r.status_code}"
        assert r.text == "REAL-APP-OK", \
            f"attacker after window slid: expected body 'REAL-APP-OK', got {r.text!r}"

        # Disabled path: no limiting regardless of volume.
        rate_limit.RATE_LIMIT_ENABLED = False
        rate_limit.reset()
        for i in range(1, 21):
            r = await get(c, ATTACKER)
            assert r.status_code == 200, \
                f"disabled req #{i}: expected 200 (no limiting), got {r.status_code}"
            assert r.text == "REAL-APP-OK", \
                f"disabled req #{i}: expected body 'REAL-APP-OK', got {r.text!r}"
        rate_limit.RATE_LIMIT_ENABLED = True  # restore

    print("rate_limit E2E: ALL PASSED")


if __name__ == "__main__":
    asyncio.run(main())
