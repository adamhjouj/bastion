"""Proxy enforcement, inline classification and event logging — real ASGI app."""
import asyncio
import json

import httpx
import pytest

from bastion import store
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
        return httpx.Response(200, text="REAL APP")
    app = create_app(settings=policy, upstream_transport=httpx.MockTransport(upstream or default_upstream),
                     classifier_transport=classifier_transport)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://proxy") as client:
        await scenario(client)


def test_observe_mode_forwards_all():
    async def scenario(client):
        for query in ("hello", "id=1 UNION SELECT 1", "<script>"):
            r = await client.get("/page", params={"q": query},
                                 headers={"X-Forwarded-For": "10.0.0.1",
                                          "Authorization": "x" * 32})
            # Authorization to the app is stripped by the proxy.
            assert r.status_code == 200
    asyncio.run(_run(_policy(), scenario))


def test_marketing_home_is_public_with_marketing_csp():
    """The /__home marketing page is public (no token) and served with a marketing CSP, while the
    dashboard stays authenticated and strict. Assets resolve under the trailing-slash form."""
    async def scenario(client):
        r = await client.get("/__home")  # redirect to trailing slash so relative assets resolve
        assert r.status_code == 308 and r.headers["location"] == "/__home/"
        r = await client.get("/__home/")
        assert r.status_code == 200 and b"Bastion" in r.content          # no management token needed
        csp = r.headers.get("content-security-policy", "")
        assert "fonts.googleapis.com" in csp and "sha256-" in csp and "script-src 'self'" in csp
        assert (await client.get("/__home/site.css")).status_code == 200
        assert (await client.get("/__home/assets/logo.png")).status_code == 200
        assert (await client.get("/__home/nope.env")).status_code == 404   # unknown extension
        dash = await client.get("/__dash")                                 # still gated
        assert dash.status_code >= 400
    asyncio.run(_run(_policy(), scenario))


def test_active_ban_blocks():
    store.save_state({"denylist": [{"ip": "10.0.0.1", "expires": None}], "honeypot": []})

    async def scenario(client):
        r = await client.get("/", headers={"X-Forwarded-For": "10.0.0.1"})
        assert r.status_code == 403
    asyncio.run(_run(_policy(), scenario))


def test_expired_ban_does_not_block():
    store.save_state({"denylist": [{"ip": "10.0.0.1", "expires": store.now_plus(-1)}], "honeypot": []})

    async def scenario(client):
        r = await client.get("/", headers={"X-Forwarded-For": "10.0.0.1"})
        assert r.status_code == 200
    asyncio.run(_run(_policy(), scenario))


def test_rate_limit_429(monkeypatch):
    from bastion import rate_limit as rl
    monkeypatch.setattr(rl, "RATE_LIMIT_MAX", 2)
    monkeypatch.setattr(rl, "RATE_LIMIT_WINDOW", 60.0)
    monkeypatch.setattr(rl, "RATE_LIMIT_ENABLED", True)
    rl.reset()

    async def scenario(client):
        for _ in range(2):
            await client.get("/", headers={"X-Forwarded-For": "10.0.0.2"})
        r = await client.get("/", headers={"X-Forwarded-For": "10.0.0.2"})
        assert r.status_code == 429
        assert "Retry-After" in r.headers
    asyncio.run(_run(_policy(), scenario))
    rl.reset()


def test_divert_routing_selects_honeypot(monkeypatch):
    """The divert flag correctly routes diverted IPs to the honeypot env var target."""
    store.save_state({"denylist": [], "honeypot": [{"ip": "10.1.1.1", "reason": "test"}]})
    monkeypatch.setenv("HONEYPOT_URL", "http://honeypot")
    monkeypatch.setenv("DVWA_URL", "http://dvwa")

    targets = []

    async def upstream(req):
        targets.append(str(req.url.host))
        return httpx.Response(200, text="OK")

    async def scenario(client):
        await client.get("/page", headers={"X-Forwarded-For": "10.1.1.1"})
        await client.get("/page", headers={"X-Forwarded-For": "10.2.2.2"})

    asyncio.run(scenario(
        httpx.AsyncClient(transport=httpx.ASGITransport(
            create_app(settings=_policy(), upstream_transport=httpx.MockTransport(upstream))),
                          base_url="http://proxy")))
    # Both requests reach the unified mock; the URL host reflects the routing target.
    assert "honeypot" in targets[0]
    assert "dvwa" in targets[1]


def test_inline_mode_blocks_on_malicious():
    malicious_response = {"answers": {
        "malicious": {"noul": 0.95}, "attack_type": {
            "choice": "sql_injection", "confidence": 0.9,
            "probabilities": {"sql_injection": 0.9, "benign": 0.05, "xss": 0.03,
                              "command_injection": 0.01, "path_traversal": 0.01, "other": 0.0}}}}

    async def jev(req):
        return httpx.Response(200, json=malicious_response)

    async def scenario(client):
        r = await client.get("/page", headers={"X-Forwarded-For": "10.0.0.3"})
        assert r.status_code == 403

    asyncio.run(_run(_policy(mode="inline"), scenario, classifier_transport=httpx.MockTransport(jev)))


def test_inline_mode_allows_benign():
    benign_response = {"answers": {
        "malicious": {"noul": 0.02}, "attack_type": {
            "choice": "benign", "confidence": 0.99,
            "probabilities": {"benign": 0.99, "sql_injection": 0.01, "xss": 0.0,
                              "command_injection": 0.0, "path_traversal": 0.0, "other": 0.0}}}}

    async def jev(req):
        return httpx.Response(200, json=benign_response)

    async def scenario(client):
        r = await client.get("/page", headers={"X-Forwarded-For": "10.0.0.4"})
        assert r.status_code == 200

    asyncio.run(_run(_policy(mode="inline"), scenario, classifier_transport=httpx.MockTransport(jev)))


def test_inline_reject_on_classifier_error():
    async def jev(req):
        raise httpx.ConnectError("timeout")

    async def scenario(client):
        r = await client.get("/page", headers={"X-Forwarded-For": "10.0.0.5"})
        assert r.status_code == 503

    asyncio.run(_run(_policy(mode="inline", inline_failure="reject"),
                     scenario, classifier_transport=httpx.MockTransport(jev)))


def test_inline_allow_on_classifier_error():
    async def jev(req):
        raise httpx.ConnectError("timeout")

    forwarded = []

    async def upstream(req):
        forwarded.append(req)
        return httpx.Response(200, text="OK")

    async def scenario(client):
        r = await client.get("/page", headers={"X-Forwarded-For": "10.0.0.6"})
        assert r.status_code == 200

    asyncio.run(_run(_policy(mode="inline", inline_failure="allow"),
                     scenario, upstream=upstream,
                     classifier_transport=httpx.MockTransport(jev)))
    assert len(forwarded) == 1


def test_events_logged_to_store():
    async def scenario(client):
        await client.get("/test", headers={"X-Forwarded-For": "10.0.0.7"})
    asyncio.run(_run(_policy(), scenario))
    events = store.read_jsonl(store.EVENTS_FILE)
    assert any(e.get("path") == "/test" and e.get("ip") == "10.0.0.7" for e in events)


def test_events_do_not_contain_raw_credentials():
    async def scenario(client):
        await client.post("/login", headers={"X-Forwarded-For": "10.0.0.8"},
                          data={"username": "alice", "password": "s3cr3t"}, follow_redirects=False)
    asyncio.run(_run(_policy(), scenario))
    events = store.read_jsonl(store.EVENTS_FILE)
    for event in events:
        assert "s3cr3t" not in json.dumps(event)


def test_response_too_large_returns_502():
    async def huge_upstream(req):
        return httpx.Response(200, content=b"x" * 10)

    async def scenario(client):
        r = await client.get("/big", headers={"X-Forwarded-For": "10.0.0.9"})
        assert r.status_code == 502

    asyncio.run(_run(_policy(response_limit=5), scenario, upstream=huge_upstream))


def test_request_too_large_returns_413():
    async def scenario(client):
        r = await client.post("/upload", headers={"X-Forwarded-For": "10.0.0.10"},
                              content=b"x" * 20)
        assert r.status_code == 413

    asyncio.run(_run(_policy(request_limit=10), scenario))


def test_security_header_present():
    async def scenario(client):
        r = await client.get("/", headers={"X-Forwarded-For": "10.0.0.11"})
        assert "X-Content-Type-Options" in r.headers
    asyncio.run(_run(_policy(), scenario))


def test_security_cookie_pinned():
    store.save_state({"denylist": [], "honeypot": [], "enforced_security": "impossible"})
    received_cookies = []

    async def upstream(req):
        received_cookies.append(req.headers.get("cookie", ""))
        return httpx.Response(200)

    async def scenario(client):
        await client.get("/page", headers={"X-Forwarded-For": "10.0.0.12",
                                           "Cookie": "security=low; PHPSESSID=abc"})
    asyncio.run(_run(_policy(), scenario, upstream=upstream))
    assert received_cookies and "security=impossible" in received_cookies[0]
    assert "security=low" not in received_cookies[0]
    assert "PHPSESSID=abc" in received_cookies[0]


def test_authorization_not_forwarded():
    received = []

    async def upstream(req):
        received.append(dict(req.headers))
        return httpx.Response(200)

    async def scenario(client):
        await client.get("/page", headers={"X-Forwarded-For": "10.0.0.13",
                                           "Authorization": "Bearer secret"})
    asyncio.run(_run(_policy(), scenario, upstream=upstream))
    assert received and "authorization" not in received[0]


def test_request_id_in_response():
    async def scenario(client):
        r = await client.get("/", headers={"X-Forwarded-For": "10.0.0.14"})
        assert "X-Request-ID" in r.headers
    asyncio.run(_run(_policy(), scenario))


def test_multiple_set_cookie_preserved():
    async def upstream(req):
        return httpx.Response(200, headers=[("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")])

    async def scenario(client):
        r = await client.get("/", headers={"X-Forwarded-For": "10.0.0.15"})
        cookies = [v for k, v in r.headers.multi_items() if k.lower() == "set-cookie"]
        assert len(cookies) == 2
    asyncio.run(_run(_policy(), scenario, upstream=upstream))
