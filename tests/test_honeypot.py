"""Honeypot app logging and divert tool state contract."""
import asyncio
import json
import tempfile
from pathlib import Path

import httpx
import pytest

from bastion import store


@pytest.fixture(autouse=True)
def _isolated_honeypot(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DATA", tmp_path)
    monkeypatch.setattr(store, "STATE_FILE", tmp_path / "state.json")
    import os
    monkeypatch.setenv("BASTION_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("DECOY_LLM", "0")  # never reach a provider from unit tests
    store.initialize()


def test_honeypot_app_logs_request(tmp_path, monkeypatch):
    from bastion.honeypot_app import app
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://decoy") as client:
            r = await client.get("/admin", headers={"X-Forwarded-For": "10.0.0.1",
                                                    "User-Agent": "curl/8.0"})
            assert r.status_code == 200
            # Cold start serves a brand-less holding page — never the old hard-coded 'Acme' fake.
            assert "Acme" not in r.text
            assert "honeypot" not in r.text.lower()
    asyncio.run(scenario())
    hits = store.read_jsonl(store.DATA / "honeypot_hits.jsonl")
    assert hits and hits[0]["ip"] == "10.0.0.1"


def test_honeypot_app_redacts_sensitive_body(tmp_path, monkeypatch):
    import json
    from bastion.honeypot_app import app
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://decoy") as client:
            await client.post("/login", data={"username": "admin", "password": "s3cr3t"})
    asyncio.run(scenario())
    hits = store.read_jsonl(store.DATA / "honeypot_hits.jsonl")
    assert hits
    assert "s3cr3t" not in json.dumps(hits)


def test_honeypot_xff_first_hop(tmp_path, monkeypatch):
    from bastion.honeypot_app import app
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://decoy") as client:
            await client.get("/", headers={"X-Forwarded-For": "203.0.113.9, 10.0.0.1"})
    asyncio.run(scenario())
    hits = store.read_jsonl(store.DATA / "honeypot_hits.jsonl")
    assert hits[0]["ip"] == "203.0.113.9"


def test_divert_idempotent():
    from bastion.honeypot_tools import divert_to_honeypot, undivert
    divert_to_honeypot("10.0.0.1", "test")
    divert_to_honeypot("10.0.0.1", "test again")
    assert sum(1 for d in store.load_state().get("honeypot", []) if d["ip"] == "10.0.0.1") == 1


def test_undivert_removes_entry():
    from bastion.honeypot_tools import divert_to_honeypot, undivert
    divert_to_honeypot("10.0.0.2", "test")
    undivert("10.0.0.2")
    assert not any(d["ip"] == "10.0.0.2" for d in store.load_state().get("honeypot", []))


def test_undivert_missing_is_safe():
    from bastion.honeypot_tools import undivert
    result = undivert("10.0.0.3")
    assert isinstance(result, str)


def test_register_shape():
    from bastion.honeypot_tools import REGISTER
    assert isinstance(REGISTER, list)
    for entry in REGISTER:
        assert set(entry) == {"name", "schema", "fn"}
        assert entry["name"] == entry["schema"]["name"]
        assert callable(entry["fn"])
    assert {e["name"] for e in REGISTER} == {"divert_to_honeypot", "undivert"}


# ---- adaptive decoy (docs/DECOY.md) through the ASGI app ----------------------------------
LEARNED_HDRS = [("server", "Apache"), ("x-powered-by", "PHP/8.2.35"), ("set-cookie", "APPSESS398=ef19; path=/"),
                ("content-type", "text/html; charset=UTF-8")]


def _learn_into(tmp_path, name="passive.json"):
    from bastion.decoy.shape import ShapeStore
    st = ShapeStore()
    st.learn("GET", "/", "", 200, LEARNED_HDRS,
             b'<html><head><title>Home &ndash; Helios Intranet</title></head><body><p>Ref <strong>7731</strong></p></body></html>',
             latency_ms=5)
    st.learn("GET", "/nope", "", 404, LEARNED_HDRS,
             b'<html><head><title>Not found &ndash; Helios Intranet</title></head><body>No such page.</body></html>')
    (tmp_path / "decoy").mkdir(exist_ok=True)
    st.save(tmp_path / "decoy" / name)


def _client(app):
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://decoy")


def test_honeypot_serves_learned_shape_with_fingerprint_headers(tmp_path, monkeypatch):
    monkeypatch.setenv("DECOY_LLM", "0")
    _learn_into(tmp_path)
    from bastion.honeypot_app import app
    app.state.shapes = None  # force a reload against this test's data dir

    async def scenario():
        async with _client(app) as client:
            r = await client.get("/", headers={"X-Forwarded-For": "10.0.0.1", "User-Agent": "curl/8.0"})
            assert r.status_code == 200 and "Helios Intranet" in r.text and "7731" not in r.text
            assert r.headers["server"] == "Apache" and r.headers["x-powered-by"] == "PHP/8.2.35"
            assert r.headers["set-cookie"].startswith("APPSESS398=") and "ef19" not in r.headers["set-cookie"]
            again = await client.get("/", headers={"X-Forwarded-For": "10.0.0.1", "User-Agent": "curl/8.0"})
            assert again.text == r.text
            nf = await client.get("/wp-admin/", headers={"X-Forwarded-For": "10.0.0.1", "User-Agent": "sqlmap/1.7"})
            assert nf.status_code == 404 and "No such page" in nf.text
    asyncio.run(scenario())
    hits = store.read_jsonl(store.DATA / "honeypot_hits.jsonl")
    assert [h["source"] for h in hits] == ["template", "cache", "error_template"]
    assert {"scanner_ua", "path_probe"} <= set(hits[2]["tags"]) and hits[0]["visitor"] == hits[1]["visitor"]
    assert all("honeypot" not in json.dumps(h).lower() or k == "source" for h in hits for k in h)


def test_honeypot_rate_limits_like_the_proxy(tmp_path, monkeypatch):
    from bastion import honeypot_app
    monkeypatch.setattr(honeypot_app.app.state, "limiter", honeypot_app._RateLimiter(limit=2, window=60))

    async def scenario():
        async with _client(honeypot_app.app) as client:
            for _ in range(2):
                assert (await client.get("/", headers={"X-Forwarded-For": "10.9.9.9"})).status_code == 200
            r = await client.get("/", headers={"X-Forwarded-For": "10.9.9.9"})
            assert r.status_code == 429 and r.json() == {"error": "capacity limit"} and "Retry-After" in r.headers
            assert (await client.get("/", headers={"X-Forwarded-For": "10.9.9.8"})).status_code == 200
    asyncio.run(scenario())
    hits = store.read_jsonl(store.DATA / "honeypot_hits.jsonl")
    assert any(h.get("status") == 429 and h.get("source") == "rate_limit" for h in hits)


def test_honeypot_never_contacts_the_real_app(tmp_path, monkeypatch):
    """Every network transport raises: a diverted request must be answered locally."""
    import socket
    import bastion.honeypot_app as hp

    def refuse(*a, **kw):
        raise AssertionError("decoy made an outbound network request")
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", refuse)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setenv("DECOY_LLM", "0")
    _learn_into(tmp_path)
    hp.app.state.shapes = None

    async def scenario():
        async with _client(hp.app) as client:
            r = await client.get("/console/lookup?id=1%27%20OR%201%3D1", headers={"X-Forwarded-For": "10.0.0.1"})
            assert r.status_code == 404
            r = await client.post("/console/netcheck", data={"userid": "a", "credential": "b"},
                                  headers={"X-Forwarded-For": "10.0.0.1"})
            assert r.status_code in (200, 302, 404)
    asyncio.run(scenario())


def test_honeypot_health_is_not_a_hit():
    from bastion.honeypot_app import app

    async def scenario():
        async with _client(app) as client:
            r = await client.get("/__health")
            assert r.status_code == 200 and r.json()["ok"] is True
    asyncio.run(scenario())
    assert store.read_jsonl(store.DATA / "honeypot_hits.jsonl") == []
