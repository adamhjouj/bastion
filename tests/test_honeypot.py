"""Honeypot app logging and divert tool state contract."""
import asyncio
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
    store.initialize()


def test_honeypot_app_logs_request(tmp_path, monkeypatch):
    from bastion.honeypot_app import app
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://decoy") as client:
            r = await client.get("/admin", headers={"X-Forwarded-For": "10.0.0.1",
                                                    "User-Agent": "curl/8.0"})
            assert r.status_code == 200
            assert "Acme" in r.text
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
