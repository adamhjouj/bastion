"""One-click reversibility: annotation, compensating actions, guardrails (CONTRACTS §3.1)."""
import httpx
import pytest
from fastapi.testclient import TestClient

from bastion import actuator_client
from bastion import rollback
from bastion import store
from bastion.proxy import create_app
from bastion.security import canonical_vpatch
from bastion.settings import Settings


@pytest.fixture
def client():
    async def upstream(request):
        return httpx.Response(200, text="OK")
    app = create_app(Settings(management_token="x" * 32), upstream_transport=httpx.MockTransport(upstream))
    with TestClient(app, headers={"Authorization": "Bearer " + "x" * 32}) as c:
        yield c


def action(tool, inp, outcome="ok", case_id="7", **extra):
    return store.append_jsonl(store.ACTIONS_FILE, {"ts": store.now(), "kind": "action", "tool": tool, "input": inp,
                                                    "result": "done", "outcome": outcome, "case_id": case_id, **extra})


def actions_rows():
    with store.connection() as db:
        return [dict(r) for r in db.execute("SELECT id,data FROM records WHERE kind='actions' ORDER BY id")]


# ---- annotation (pure) ----

def test_annotate_derives_reversible_reverted_by_and_reverts():
    records = [
        {"id": 1, "kind": "action", "tool": "blacklist_ip", "outcome": "ok", "input": {"ip": "192.0.2.1"}},
        {"id": 2, "kind": "action", "tool": "blacklist_ip", "outcome": "ok", "input": {"ip": "192.0.2.2"}},
        {"id": 3, "kind": "action", "tool": "rollback", "outcome": "ok", "input": {"reverts": 2, "tool": "blacklist_ip"}},
        {"id": 4, "kind": "action", "tool": "blacklist_ip", "outcome": "ok", "input": {"ip": "192.0.2.3"}},
        {"id": 5, "kind": "action", "tool": "rollback", "outcome": "error", "input": {"reverts": 4, "tool": "blacklist_ip"}},
        {"id": 6, "kind": "action", "tool": "blacklist_ip", "outcome": "rejected", "input": {"ip": "192.0.2.4"}},
        {"id": 7, "kind": "action", "tool": "rotate_secret", "outcome": "ok", "input": {"target": "dvwa"}},
        {"id": 8, "kind": "action", "tool": "inspect_target", "outcome": "ok", "input": {"path": "/"}},
        {"id": 9, "kind": "triage", "case_id": "1", "outcome": "ok", "jev": {"malicious": True}},
        {"id": 10, "kind": "error", "case_id": "1", "error": "boom"},
    ]
    by_id = {r["id"]: r for r in rollback.annotate(records)}
    assert by_id[1] == {**records[0], "reversible": True, "reverted_by": None, "reverts": None}
    assert by_id[2]["reversible"] is False and by_id[2]["reverted_by"] == 3
    assert by_id[3]["reverts"] == 2 and by_id[3]["reversible"] is False
    # A failed rollback attempt does not count as a reversal: the original stays reversible.
    assert by_id[4]["reversible"] is True and by_id[4]["reverted_by"] is None
    assert by_id[5]["reverts"] == 4
    assert by_id[6]["reversible"] is False      # outcome != ok
    assert by_id[7]["reversible"] is False      # irreversible tool
    assert by_id[8]["reversible"] is False      # read-only tool: no inverse
    assert by_id[9]["reversible"] is False and by_id[9]["reverts"] is None   # triage
    assert by_id[10]["reversible"] is False and by_id[10]["reverts"] is None  # error
    assert records[0] == {"id": 1, "kind": "action", "tool": "blacklist_ip", "outcome": "ok", "input": {"ip": "192.0.2.1"}}


def test_annotate_honours_reversals_outside_the_page():
    original = {"id": 1, "kind": "action", "tool": "divert_to_honeypot", "outcome": "ok", "input": {"ip": "192.0.2.1"}}
    assert rollback.annotate([original])[0]["reversible"] is True
    annotated = rollback.annotate([original], {1: 99})[0]
    assert annotated["reversible"] is False and annotated["reverted_by"] == 99


def test_is_reversible_requires_action_kind_ok_outcome_and_inverse():
    assert rollback.is_reversible({"kind": "action", "tool": "quarantine_container", "outcome": "ok"})
    assert not rollback.is_reversible({"kind": "action", "tool": "quarantine_container", "outcome": "ok"}, reverted_by=5)
    assert not rollback.is_reversible({"kind": "triage", "tool": "blacklist_ip", "outcome": "ok"})
    assert not rollback.is_reversible({"kind": "error", "tool": "blacklist_ip", "outcome": "ok"})
    assert not rollback.is_reversible({"kind": "action", "tool": "blacklist_ip", "outcome": "error"})
    assert not rollback.is_reversible({"kind": "action", "tool": "kill_process", "outcome": "ok"})
    assert set(rollback.IRREVERSIBLE).isdisjoint(rollback.INVERSE)


# ---- surfaces carry the annotation ----

def test_actions_incident_and_snapshot_surfaces_are_annotated(client):
    event = store.append_jsonl(store.EVENTS_FILE, {"ts": store.now(), "ip": "192.0.2.1", "path": "/x"})
    case = str(event)
    ban = action("blacklist_ip", {"ip": "192.0.2.1"}, case_id=case)
    store.append_jsonl(store.ACTIONS_FILE, {"ts": store.now(), "kind": "triage", "case_id": case, "ip": "192.0.2.1",
                                            "jev": {"malicious": True}, "escalated": True, "outcome": "escalated"})
    iid = store.append_jsonl(store.INCIDENTS_FILE, {"ts": store.now(), "case_id": case, "severity": "high", "summary": "s"})
    for items in (client.get("/__api/v1/actions").json()["items"],
                  client.get(f"/__api/v1/incidents/{iid}").json()["actions"],
                  client.get("/__api/v1/overview").json()["actions"]):
        by_id = {i["id"]: i for i in items}
        assert by_id[ban]["reversible"] is True and by_id[ban]["reverted_by"] is None and by_id[ban]["reverts"] is None
        triage = [i for i in items if i.get("kind") == "triage"][0]
        assert triage["reversible"] is False and triage["reverts"] is None
    single = client.get(f"/__api/v1/actions/{ban}").json()["item"]
    assert single["id"] == ban and single["reversible"] is True
    assert client.get("/__api/v1/actions/999999").status_code == 404
    assert client.get(f"/__api/v1/actions/{ban}", headers={"Authorization": ""}).status_code == 401


def test_capabilities_expose_inverse_map_and_irreversible_set(client):
    data = client.get("/__api/v1/rollback/capabilities").json()
    assert data["inverse"]["blacklist_ip"] == "unban_ip"
    assert data["inverse"]["bulk_blacklist_ip"] == "unban_ip"
    assert data["inverse"]["divert_to_honeypot"] == "undivert"
    assert data["inverse"]["quarantine_container"] == "release_container"
    assert data["inverse"]["isolate_egress"] == "reconnect_egress"
    assert "virtual_patch" in data["inverse"] and "patch_vuln" in data["inverse"]
    assert set(data["irreversible"]) == {"kill_process", "kill_session", "rotate_secret"}


# ---- successful rollbacks ----

def test_rollback_ban_releases_ip_and_records_compensating_action(client):
    store.save_state({"denylist": [{"ip": "192.0.2.1", "reason": "x", "ts": store.now(), "expires": None}], "honeypot": []})
    ban = action("blacklist_ip", {"ip": "192.0.2.1", "reason": "sqli"}, case_id="41")
    rows_before = actions_rows()
    response = client.post(f"/__api/v1/actions/{ban}/rollback", json={"reason": "false positive"})
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["ok"] is True and data["reverted"] == ban
    comp = data["action"]
    assert comp["tool"] == "rollback" and comp["outcome"] == "ok" and comp["case_id"] == "41"
    assert comp["input"] == {"reverts": ban, "tool": "blacklist_ip", "inverse": "unban_ip",
                             "reason": "false positive", "ip": "192.0.2.1"}
    assert comp["reverts"] == ban and comp["reversible"] is False and comp["reverted_by"] is None
    assert store.load_state()["denylist"] == []
    # Original flipped (derived), original row untouched, exactly one new row appended.
    original = client.get(f"/__api/v1/actions/{ban}").json()["item"]
    assert original["reversible"] is False and original["reverted_by"] == comp["id"]
    rows_after = actions_rows()
    assert rows_after[:len(rows_before)] == rows_before and len(rows_after) == len(rows_before) + 1
    # Visible everywhere the contract names.
    overview = {a["id"]: a for a in client.get("/__api/v1/overview").json()["actions"]}
    assert overview[ban]["reverted_by"] == comp["id"] and overview[comp["id"]]["reverts"] == ban


def test_rollback_bulk_ban_divert_and_vpatch_use_proxy_state(client):
    pattern = canonical_vpatch("sql_injection")
    store.save_state({"denylist": [{"ip": "192.0.2.1", "ts": store.now()}, {"ip": "192.0.2.2", "ts": store.now()},
                                   {"ip": "192.0.2.9", "ts": store.now()}],
                      "honeypot": [{"ip": "198.51.100.5", "reason": "r", "ts": store.now()}],
                      "vpatch": [{"id": "a", "path": "/lookup", "pattern": pattern, "attack_type": "sql_injection"},
                                 {"id": "b", "path": "/other", "pattern": pattern, "attack_type": "sql_injection"}]})
    bulk = action("bulk_blacklist_ip", {"ips": ["192.0.2.2", "192.0.2.1"], "reason": "campaign"})
    divert = action("divert_to_honeypot", {"ip": "198.51.100.5"})
    patch = action("virtual_patch", {"path": "/lookup", "attack_type": "sql_injection", "reason": "confirmed"})
    assert client.post(f"/__api/v1/actions/{bulk}/rollback").status_code == 200
    assert [d["ip"] for d in store.load_state()["denylist"]] == ["192.0.2.9"]
    assert client.post(f"/__api/v1/actions/{divert}/rollback", json={}).status_code == 200
    assert store.load_state()["honeypot"] == []
    assert client.post(f"/__api/v1/actions/{patch}/rollback").status_code == 200
    assert [r["id"] for r in store.load_state()["vpatch"]] == ["b"]
    comp = client.get("/__api/v1/actions?case_id=7").json()["items"]
    inverses = {c["reverts"]: c["input"]["inverse"] for c in comp if c["tool"] == "rollback"}
    assert inverses == {bulk: "unban_ip", divert: "undivert", patch: "remove_vpatch"}


def test_rollback_privileged_actions_go_through_actuator_client(client, monkeypatch):
    calls = []

    def fake_call_tool(name, params, action_id=None):
        calls.append((name, params))
        return f"{params['target']} released"
    monkeypatch.setattr(actuator_client, "call_tool", fake_call_tool)
    quarantine = action("quarantine_container", {"target": "dvwa"})
    egress = action("isolate_egress", {"target": "dvwa"})
    assert client.post(f"/__api/v1/actions/{quarantine}/rollback").json()["action"]["input"]["inverse"] == "release_container"
    assert client.post(f"/__api/v1/actions/{egress}/rollback").json()["action"]["result"] == "dvwa released"
    assert calls == [("release_container", {"target": "dvwa"}), ("reconnect_egress", {"target": "dvwa"})]


def test_rollback_patch_vuln_restores_prior_level(client, monkeypatch):
    calls = []
    monkeypatch.setattr(actuator_client, "call_tool", lambda name, params, action_id=None: calls.append((name, params)) or "Target security level raised to 'high'")
    first = action("patch_vuln", {"level": "high"})
    second = action("patch_vuln", {"level": "impossible"})
    assert client.post(f"/__api/v1/actions/{second}/rollback").status_code == 200
    assert client.post(f"/__api/v1/actions/{first}/rollback").status_code == 200
    assert calls == [("patch_vuln", {"level": "high"}), ("patch_vuln", {"level": rollback.LAB_DEFAULT_LEVEL})]


# ---- guardrails ----

def test_second_rollback_is_rejected_with_409(client):
    ban = action("blacklist_ip", {"ip": "192.0.2.1"})
    assert client.post(f"/__api/v1/actions/{ban}/rollback").status_code == 200
    repeat = client.post(f"/__api/v1/actions/{ban}/rollback")
    assert repeat.status_code == 409
    assert repeat.json()["ok"] is False and "already reverted" in repeat.json()["error"]
    assert sum(1 for r in actions_rows() if '"rollback"' in r["data"]) == 1


def test_unknown_action_is_404(client):
    assert client.post("/__api/v1/actions/424242/rollback").status_code == 404


def test_irreversible_not_ok_triage_and_error_records_are_409(client):
    rotate = action("rotate_secret", {"target": "dvwa"})
    failed = action("blacklist_ip", {"ip": "192.0.2.1"}, outcome="error")
    rejected = action("quarantine_container", {"target": "dvwa"}, outcome="rejected")
    triage = store.append_jsonl(store.ACTIONS_FILE, {"ts": store.now(), "kind": "triage", "case_id": "1", "ip": "192.0.2.1",
                                                     "jev": {"malicious": True}, "escalated": True, "outcome": "escalated"})
    error = store.append_jsonl(store.ACTIONS_FILE, {"ts": store.now(), "kind": "error", "case_id": "1", "error": "boom"})
    read_only = action("inspect_target", {"path": "/"})
    for rid in (rotate, failed, rejected, triage, error, read_only):
        response = client.post(f"/__api/v1/actions/{rid}/rollback")
        assert response.status_code == 409, rid
        assert response.json()["ok"] is False and response.json()["error"]
        assert client.get(f"/__api/v1/actions/{rid}").json()["item"]["reversible"] is False
    assert not any('"rollback"' in r["data"] for r in actions_rows())


def test_downstream_failure_is_502_and_recorded_as_error(client, monkeypatch):
    monkeypatch.setattr(actuator_client, "call_tool", lambda name, params, action_id=None: "ERROR: actuator unavailable or request rejected")
    quarantine = action("quarantine_container", {"target": "dvwa"})
    response = client.post(f"/__api/v1/actions/{quarantine}/rollback", json={"reason": "demo over"})
    assert response.status_code == 502
    data = response.json()
    assert data["ok"] is False and data["error"].startswith("ERROR")
    attempt = data["action"]
    assert attempt["tool"] == "rollback" and attempt["outcome"] == "error" and attempt["reverts"] == quarantine
    assert attempt["input"]["reason"] == "demo over"
    assert client.get(f"/__api/v1/actions/{attempt['id']}").json()["item"]["outcome"] == "error"
    # The failed attempt did not revert anything: the original stays reversible and can be retried.
    original = client.get(f"/__api/v1/actions/{quarantine}").json()["item"]
    assert original["reversible"] is True and original["reverted_by"] is None
    monkeypatch.setattr(actuator_client, "call_tool", lambda name, params, action_id=None: "dvwa released (unpaused)")
    assert client.post(f"/__api/v1/actions/{quarantine}/rollback").status_code == 200


def test_rollback_requires_authentication(client):
    ban = action("blacklist_ip", {"ip": "192.0.2.1"})
    assert client.post(f"/__api/v1/actions/{ban}/rollback", headers={"Authorization": ""}).status_code == 401
    assert client.get("/__api/v1/rollback/capabilities", headers={"Authorization": ""}).status_code == 401


def test_operator_unban_and_undivert_share_the_rollback_inverse_code(client):
    store.save_state({"denylist": [{"ip": "192.0.2.1", "ts": store.now()}], "honeypot": [{"ip": "192.0.2.1", "ts": store.now()}]})
    assert client.post("/__api/v1/defenses/unban", json={"ip": "192.0.2.1"}).json()["removed"] == 1
    assert client.post("/__api/v1/defenses/undivert", json={"ip": "192.0.2.1"}).json()["released"] == 1
    assert store.load_state()["denylist"] == [] and store.load_state()["honeypot"] == []
