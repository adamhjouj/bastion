"""CONTRACTS §4.3 — the proxy's single guarded observe-hook: redacted facts only, non-blocking,
skipped for diverted/malicious/failed upstream traffic, and harmless when the decoy fails."""
import asyncio
import json
import time

import httpx

from bastion import decoy, store
from bastion.decoy.shape import ShapeStore
from bastion.proxy import create_app
from bastion.settings import Settings


def _policy(**kw):
    base = dict(mode="observe", management_token="x" * 32, inline_failure="reject",
                demo_identity=True, trusted_proxies="", request_limit=65536,
                response_limit=2097152, timeout=5.0, concurrency=8,
                budget_per_minute=9999, queue_limit=10000, allow_destructive=False)
    base.update(kw)
    return Settings(**base)


async def _run(policy, scenario, upstream=None, classifier_transport=None):
    async def default_upstream(req):
        return httpx.Response(200, headers=[("content-type", "text/html"), ("server", "Apache"),
                                            ("set-cookie", "SID=secretvalue; path=/")],
                              text="<html><title>Home &ndash; Site</title><body>REAL APP</body></html>")
    app = create_app(settings=policy, upstream_transport=httpx.MockTransport(upstream or default_upstream),
                     classifier_transport=classifier_transport)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy") as client:
        await scenario(client)


def test_hook_passes_only_redacted_request_facts(monkeypatch):
    seen = []
    monkeypatch.setattr(decoy, "observe", lambda *a, **kw: seen.append((a, kw)) or True)

    async def scenario(client):
        r = await client.post("/login?next=/x&token=abc", headers={"X-Forwarded-For": "10.0.0.1",
                                                                   "Authorization": "Bearer zzz",
                                                                   "Cookie": "sid=mine"},
                              data={"username": "alice", "password": "s3cr3t"})
        assert r.status_code == 200 and r.text.endswith("</html>")
    asyncio.run(_run(_policy(), scenario))
    assert len(seen) == 1
    args, kwargs = seen[0]
    method, path, query, status, headers, body, latency_ms, req_body, req_ct = args
    assert (method, path, status) == ("POST", "/login", 200)
    assert "abc" not in query and "next=%2Fx" in query
    assert "s3cr3t" not in req_body and "username=alice" in req_body
    assert isinstance(latency_ms, int) and body.startswith(b"<html>") and len(body) <= decoy.BODY_LIMIT
    flat = json.dumps([[k.decode(), v.decode()] for k, v in headers])
    assert "secretvalue" in flat  # response headers are passed raw…
    assert kwargs == {"malicious": False}
    # …and the learner keeps only the cookie *name*, never the value or the request headers.
    st = ShapeStore()
    st.learn(method, path, query, status, headers, body, latency_ms=latency_ms, request_body=req_body)
    dumped = json.dumps(st.to_dict())
    assert "secretvalue" not in dumped and "zzz" not in dumped and "mine" not in dumped
    assert st.fingerprint["cookies"] == ["SID"]


def test_hook_failure_never_breaks_forwarding(monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("decoy broken")
    monkeypatch.setattr(decoy, "observe", boom)

    async def scenario(client):
        r = await client.get("/page", headers={"X-Forwarded-For": "10.0.0.2"})
        assert r.status_code == 200 and "REAL APP" in r.text
    asyncio.run(_run(_policy(), scenario))
    events = store.read_jsonl(store.EVENTS_FILE)
    assert any(e.get("path") == "/page" for e in events)


def test_hook_skipped_for_diverted_and_failed_upstream(monkeypatch):
    seen = []
    monkeypatch.setattr(decoy, "observe", lambda *a, **kw: seen.append(a) or True)
    store.save_state({"denylist": [], "honeypot": [{"ip": "10.1.1.1", "reason": "test"}]})
    monkeypatch.setenv("HONEYPOT_URL", "http://honeypot")

    async def upstream(req):
        if req.url.path == "/down":
            raise httpx.ConnectError("down")
        return httpx.Response(200, text="OK")

    async def scenario(client):
        await client.get("/page", headers={"X-Forwarded-For": "10.1.1.1"})   # diverted → not learned
        r = await client.get("/down", headers={"X-Forwarded-For": "10.2.2.2"})
        assert r.status_code == 502                                             # failed → not learned
        await client.get("/ok", headers={"X-Forwarded-For": "10.2.2.2"})
    asyncio.run(_run(_policy(), scenario, upstream=upstream))
    assert [a[1] for a in seen] == ["/ok"]


def test_hook_marks_malicious_verdict(monkeypatch):
    seen = []
    monkeypatch.setattr(decoy, "observe", lambda *a, **kw: seen.append(kw) or True)
    malicious = {"answers": {"malicious": {"noul": 0.95}, "attack_type": {
        "choice": "sql_injection", "confidence": 0.9,
        "probabilities": {"sql_injection": 0.9, "benign": 0.05, "xss": 0.03, "command_injection": 0.01,
                          "path_traversal": 0.01, "other": 0.0}}}}
    benign = {"answers": {"malicious": {"noul": 0.02}, "attack_type": {
        "choice": "benign", "confidence": 0.99,
        "probabilities": {"benign": 0.99, "sql_injection": 0.01, "xss": 0.0, "command_injection": 0.0,
                          "path_traversal": 0.0, "other": 0.0}}}}
    answers = iter([benign])

    async def jev(req):
        return httpx.Response(200, json=next(answers, malicious))

    async def scenario(client):
        assert (await client.get("/a", headers={"X-Forwarded-For": "10.0.0.3"})).status_code == 200
        assert (await client.get("/b", headers={"X-Forwarded-For": "10.0.0.3"})).status_code == 403
    asyncio.run(_run(_policy(mode="inline"), scenario, classifier_transport=httpx.MockTransport(jev)))
    assert seen == [{"malicious": False}]  # the blocked request never reaches the hook


def test_observe_is_non_blocking_and_learns_into_data_dir(tmp_path):
    started = time.monotonic()
    for i in range(50):
        decoy.observe("GET", f"/p{i % 3}", "", 200, [("content-type", "text/html")],
                      b"<html><title>T &ndash; S</title><body>x</body></html>", 5)
    assert time.monotonic() - started < 0.5
    decoy.learner().drain()
    assert (tmp_path / "decoy" / "passive.json").exists()
    assert len(ShapeStore.load(tmp_path / "decoy" / "passive.json").routes) == 3
    assert decoy.observe("GET", "/evil", "", 200, [], b"x", malicious=True) is False
    assert decoy.stats()["routes"] == 3


def test_proxy_boots_without_decoy_package(monkeypatch):
    import builtins
    import sys
    real_import = builtins.__import__

    def no_decoy(name, *a, **kw):
        if name == "bastion.decoy" or name.startswith("bastion.decoy."):
            raise ImportError("decoy absent")
        return real_import(name, *a, **kw)
    import bastion
    monkeypatch.delitem(sys.modules, "bastion.decoy", raising=False)
    monkeypatch.delattr(bastion, "decoy", raising=False)
    monkeypatch.setattr(builtins, "__import__", no_decoy)

    async def scenario(client):
        r = await client.get("/page", headers={"X-Forwarded-For": "10.0.0.4"})
        assert r.status_code == 200 and "REAL APP" in r.text
    asyncio.run(_run(_policy(), scenario))
