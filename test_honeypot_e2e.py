"""End-to-end verification of the honeypot DIVERT flow — fully in-process.

Proves the contract the REAL proxy will implement: a diverted attacker IP lands
on the decoy while everyone else reaches the real app. No ports, docker, or
network — FastAPI + httpx.ASGITransport only.

We do NOT edit proxy.py; we replicate its future divert branch here as a SHIM.
source_ip() below is copied verbatim from proxy.source_ip (XFF first hop) so the
shim resolves IPs "exactly like" the real proxy without importing a file that
other sessions are editing.

Run: .venv/bin/python test_honeypot_e2e.py
"""
import asyncio
import tempfile
from pathlib import Path

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, Response

import store

# 1. Isolate state + logs into a throwaway tempdir BEFORE any divert/decoy call,
#    so the real data/ dir is never touched. Both globals are read at call time.
_TMP = Path(tempfile.mkdtemp(prefix="honeypot_e2e_"))
store.DATA = _TMP
store.STATE_FILE = _TMP / "state.json"

import honeypot_tools  # noqa: E402  (after store is redirected)
from honeypot_app import app as decoy_app  # noqa: E402

HITS = _TMP / "honeypot_hits.jsonl"

ATTACKER = "10.13.37.7"
NORMAL = "203.0.113.9"


# 2b. Stub "real app": catch-all with a distinct marker body.
real_app = FastAPI()


@real_app.api_route("/{path:path}",
                    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def real(path: str, request: Request):
    return PlainTextResponse("REAL-APP-OK")


# source_ip — copied verbatim from proxy.source_ip (do not import proxy.py).
def source_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


# 3. PROXY-DIVERT SHIM — faithful replica of the proxy's future divert branch.
shim = FastAPI()


@shim.api_route("/{path:path}",
                methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def divert_branch(path: str, request: Request):
    ip = source_ip(request)
    st = store.load_state()
    diverted = any(d["ip"] == ip for d in st.get("honeypot", []))
    target = decoy_app if diverted else real_app

    body = await request.body()
    headers = {}
    xff = request.headers.get("x-forwarded-for")
    if xff:
        headers["x-forwarded-for"] = xff  # pass through so decoy logs the same IP

    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=target),
                                 base_url="http://t") as up_client:
        up = await up_client.request(request.method, "/" + path,
                                     params=dict(request.query_params),
                                     content=body, headers=headers)
    return Response(content=up.content, status_code=up.status_code)


def hits():
    return store.read_jsonl(HITS)


async def get(client, path, ip=None, query=None):
    headers = {} if ip is None else {"X-Forwarded-For": ip}
    return await client.get(path, params=query, headers=headers)


async def main():
    transport = httpx.ASGITransport(app=shim)
    async with httpx.AsyncClient(transport=transport, base_url="http://proxy") as c:
        # --- Baseline: attacker IP reaches the REAL app (not yet diverted) ---
        r = await get(c, "/login.php", ip=ATTACKER)
        assert r.status_code == 200, f"baseline status: expected 200, got {r.status_code}"
        assert "REAL-APP-OK" in r.text, \
            f"baseline: expected REAL app, got body={r.text[:120]!r}"
        assert not hits(), f"baseline must not log a honeypot hit; got {hits()}"

        # --- Divert the attacker, then the SAME IP must hit the DECOY ---
        honeypot_tools.divert_to_honeypot(ATTACKER, "confirmed sqli")
        r = await get(c, "/secret-admin", ip=ATTACKER, query={"x": "1"})
        assert r.status_code == 200, f"diverted status: expected 200, got {r.status_code}"
        assert "Acme Internal Portal" in r.text, \
            f"after divert: expected DECOY page, got body={r.text[:120]!r}"

        # --- ...and the decoy logged that exact request ---
        h = hits()
        assert len(h) == 1, f"honeypot_hits.jsonl: expected 1 line, got {len(h)} ({h})"
        e = h[0]
        assert e["ip"] == ATTACKER, f"logged ip: expected {ATTACKER}, got {e['ip']!r}"
        assert e["method"] == "GET", f"logged method: expected GET, got {e['method']!r}"
        assert e["path"] == "/secret-admin", \
            f"logged path: expected /secret-admin, got {e['path']!r}"
        assert e["query"] == "x=1", f"logged query: expected x=1, got {e['query']!r}"

        # --- A normal IP is NEVER diverted (per-IP routing), even while attacker is ---
        r = await get(c, "/login.php", ip=NORMAL)
        assert "REAL-APP-OK" in r.text, \
            f"normal IP must hit REAL app, got body={r.text[:120]!r}"
        assert len(hits()) == 1, \
            f"normal IP must not add a honeypot hit; hits={len(hits())}"

        # --- Idempotency: re-diverting the same IP keeps exactly one entry ---
        honeypot_tools.divert_to_honeypot(ATTACKER, "confirmed sqli again")
        hp = store.load_state().get("honeypot", [])
        n = sum(1 for d in hp if d["ip"] == ATTACKER)
        assert n == 1, f"idempotency: expected 1 honeypot entry for {ATTACKER}, got {n} ({hp})"

        # --- undivert: the IP routes back to the REAL app ---
        honeypot_tools.undivert(ATTACKER)
        r = await get(c, "/login.php", ip=ATTACKER)
        assert "REAL-APP-OK" in r.text, \
            f"after undivert: expected REAL app, got body={r.text[:120]!r}"
        assert store.load_state().get("honeypot", []) == [], \
            f"after undivert: honeypot list should be empty, got {store.load_state().get('honeypot')}"

        # --- Edge: empty / unknown XFF still passes through to REAL, never errors ---
        r = await get(c, "/", ip="")  # empty XFF header
        assert r.status_code == 200 and "REAL-APP-OK" in r.text, \
            f"empty XFF: expected REAL app 200, got {r.status_code} body={r.text[:120]!r}"
        r = await get(c, "/", ip=None)  # no XFF header at all
        assert r.status_code == 200 and "REAL-APP-OK" in r.text, \
            f"unknown XFF: expected REAL app 200, got {r.status_code} body={r.text[:120]!r}"

    print("honeypot E2E: ALL PASSED")


if __name__ == "__main__":
    asyncio.run(main())
