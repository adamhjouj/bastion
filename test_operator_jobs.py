"""Operator demo controls: reset, the fixed job allow-list, and a start/stop cycle.

A harmless local job is monkeypatched into the registry so the start/stop path is exercised
without an LLM key or network. The real jobs are only launched from the dashboard.
"""
import sys
import time

import httpx
import pytest
from fastapi.testclient import TestClient

import log_store
import operator_controls as oc
import store
from proxy import create_app
from settings import Settings

AUTH = {"Authorization": "Bearer " + "x" * 32}


@pytest.fixture
def client():
    async def upstream(request):
        return httpx.Response(200, text="OK")
    app = create_app(Settings(management_token="x" * 32), upstream_transport=httpx.MockTransport(upstream))
    with TestClient(app, headers=AUTH) as c:
        yield c


@pytest.fixture
def harmless(monkeypatch):
    """A fast, output-producing local job that needs no key or network."""
    job = {"label": "echo probe", "source": "red", "timeout": 10,
           "argv": [sys.executable, "-c", "print('probe line one'); print('probe line two')"]}
    monkeypatch.setitem(oc.JOBS, "test-echo", job)
    # reset module state between tests
    monkeypatch.setattr(oc, "_current", None)
    monkeypatch.setattr(oc, "_last", None)
    return job


def test_reset_clears_the_board():
    store.append_jsonl(store.EVENTS_FILE, {"ts": store.now(), "ip": "1.2.3.4", "path": "/x", "status": 200})
    store.append_jsonl(store.INCIDENTS_FILE, {"ts": store.now(), "source_ip": "1.2.3.4", "severity": "high"})
    with store.state_lock:
        st = store.load_state(); st["denylist"].append({"ip": "1.2.3.4", "reason": "t"}); store.save_state(st)

    result = oc.reset()

    assert result["cleared"]["events"] == 1 and result["cleared"]["incidents"] == 1
    assert result["target"]["ok"] is False      # no actuator in tests: reported, board still cleared
    assert store.load_state()["denylist"] == []
    with store.connection() as db:
        assert db.execute("SELECT COUNT(*) FROM records WHERE kind='events'").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM records WHERE kind='incidents'").fetchone()[0] == 0
    # exactly one audit action remains, naming the reset
    actions = [r for r in store.read_jsonl(store.ACTIONS_FILE)]
    assert len(actions) == 1 and actions[0]["tool"] == "operator_reset"


def test_unknown_job_rejected():
    with pytest.raises(oc.Unknown):
        oc.start("no-such-job")


def test_llm_job_unavailable_without_key(monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert oc._have_llm() is False
    with pytest.raises(oc.Unavailable):
        oc.start("attack-sqli")
    # and the dashboard reports it as unavailable rather than hiding it
    snap = oc.snapshot()
    assert snap["llm"] is False
    assert all(j["available"] is False for j in snap["jobs"])


def test_start_captures_output_and_finishes(harmless):
    oc.start("test-echo")
    assert oc.snapshot()["running"] is True
    with pytest.raises(oc.Busy):   # one at a time
        oc.start("test-echo")

    for _ in range(100):
        if not oc.snapshot()["running"]:
            break
        time.sleep(0.1)
    snap = oc.snapshot()
    assert snap["running"] is False
    assert snap["last"]["status"] == "ok"

    text = " ".join(e["text"] for e in log_store.page("red", 0)["entries"])
    assert "probe line one" in text and "probe line two" in text


def test_stop_is_safe_when_idle(harmless):
    assert oc.stop()["running"] is False


def test_endpoints_require_auth():
    app = create_app(Settings(management_token="x" * 32))
    with TestClient(app) as noauth:
        for method, path in [("get", "/__api/v1/control/status"), ("post", "/__api/v1/control/reset"),
                             ("post", "/__api/v1/control/stop")]:
            assert getattr(noauth, method)(path).status_code == 401


def test_run_rejects_unknown_job_body(client):
    assert client.post("/__api/v1/control/run", json={"job": "; rm -rf /"}).status_code == 422
    assert client.get("/__api/v1/control/status").json()["running"] is False


def test_every_attack_job_runs_a_real_red_objective():
    """Each dashboard attack button launches a red-agent objective that actually exists."""
    import red_agent
    attacks = {k: j for k, j in oc.JOBS.items() if k.startswith("attack-")}
    assert set(attacks) == {"attack-sqli", "attack-cmdi", "attack-lfi", "attack-xss"}
    for key, job in attacks.items():
        assert job["argv"][-2:] == ["red_agent.py", key.removeprefix("attack-")]
        assert key.removeprefix("attack-") in red_agent.GOALS


def test_reset_restores_the_target_and_clears_virtual_patches(monkeypatch):
    """Reset undoes Bastion's fixes too: the target is restored first, then every proxy-side
    defense (bans, diversions, virtual patches) is cleared, and the audit line says so."""
    restored = []
    monkeypatch.setattr(oc, "_restore_target", lambda: restored.append(1) or {"ok": True, "level": "medium"})
    with store.state_lock:
        st = store.load_state()
        st["vpatch"] = [{"id": "r1", "path": "/hub/directory", "pattern": "<script", "attack_type": "xss"}]
        st["honeypot"] = [{"ip": "203.0.113.9", "reason": "t"}]
        st["enforced_security"] = "impossible"
        store.save_state(st)
    result = oc.reset()
    assert restored == [1] and result["target"]["level"] == "medium"
    st = store.load_state()
    assert st["vpatch"] == [] and st["honeypot"] == [] and "enforced_security" not in st
    audit = store.read_jsonl(store.ACTIONS_FILE)[-1]
    assert audit["outcome"] == "ok" and "target restored to medium" in audit["result"]
