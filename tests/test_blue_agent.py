"""Agent bans, tool execution, idempotency, swarm and supervisor dispatch."""
import json
import types

import pytest

from bastion import blue_agent as agent
from bastion import store


def _block(**kw):
    return types.SimpleNamespace(**kw)


class StubMessages:
    def __init__(self, calls):
        self._calls = list(calls)
        self.call_count = 0

    def create(self, **_):
        self.call_count += 1
        if not self._calls:
            return _block(stop_reason="end_turn", content=[_block(type="text", text="done")],
                          usage=_block(input_tokens=10, output_tokens=5))
        turn_tools = self._calls.pop(0)
        return _block(stop_reason="tool_use" if turn_tools else "end_turn",
                      content=[_block(type="tool_use", id=f"t{i}", name=n, input=inp)
                                for i, (n, inp) in enumerate(turn_tools)],
                      usage=_block(input_tokens=10, output_tokens=5))


class StubClient:
    def __init__(self, calls):
        self.messages = StubMessages(calls)

    def with_options(self, **_):
        return self


def test_blacklist_ip_permanent():
    agent.do_blacklist_ip("192.0.2.1", "test")
    bans = [d["ip"] for d in store.load_state()["denylist"]]
    assert "192.0.2.1" in bans


def test_blacklist_ip_invalid_address():
    with pytest.raises(Exception):
        agent.do_blacklist_ip("not-an-ip", "test")


def test_virtual_patch_installs_canonical_rule():
    out = agent.do_virtual_patch("/ops/directory", attack_type="xss", reason="confirmed reflected XSS")
    rules = store.load_state()["vpatch"]
    rule = next((r for r in rules if r["path"] == "/ops/directory"), None)
    assert rule and rule["attack_type"] == "xss" and "script" in rule["pattern"]
    assert "Virtual patch" in out
    # idempotent: same (path, resolved pattern) is not duplicated
    agent.do_virtual_patch("/ops/directory", attack_type="xss", reason="again")
    assert sum(r["path"] == "/ops/directory" for r in store.load_state()["vpatch"]) == 1


def test_virtual_patch_resolves_aliases():
    agent.do_virtual_patch("/ops/records", attack_type="sqli", reason="SQLi")   # alias -> sql_injection
    rule = next(r for r in store.load_state()["vpatch"] if r["path"] == "/ops/records")
    assert "union" in rule["pattern"].lower()


def test_virtual_patch_requires_type_or_pattern():
    out = agent.do_virtual_patch("/x", reason="no class, no pattern")
    assert out.startswith("REJECTED")
    assert not any(r["path"] == "/x" for r in store.load_state()["vpatch"])


def test_virtual_patch_custom_pattern_override():
    out = agent.do_virtual_patch("/y", reason="novel sink", pattern=r"evilthing")
    assert "Virtual patch" in out
    assert any(r["path"] == "/y" and r["pattern"] == "evilthing" for r in store.load_state()["vpatch"])


def test_virtual_patch_rejects_bad_regex():
    out = agent.do_virtual_patch("/z", reason="bad", pattern="(")
    assert out.startswith("REJECTED")
    assert not any(r["path"] == "/z" for r in store.load_state()["vpatch"])


def test_backstop_contains_patched_malicious_source(monkeypatch):
    agent._CONTEXT.patched = True
    monkeypatch.setattr(agent, "_lacks_malicious_verdict", lambda ip: ip != "203.0.113.9")  # only .9 malicious
    called = []
    monkeypatch.setitem(agent.DISPATCH, "divert_to_honeypot", lambda ip, reason: called.append(ip) or "diverted")
    agent._enforce_contain_and_patch([{"ip": "203.0.113.9"}, {"ip": "198.51.100.1"}], "c1")
    assert called == ["203.0.113.9"]            # malicious source contained, benign one left alone


def test_backstop_noop_without_patch(monkeypatch):
    agent._CONTEXT.patched = False
    called = []
    monkeypatch.setattr(agent, "_lacks_malicious_verdict", lambda ip: False)
    monkeypatch.setitem(agent.DISPATCH, "divert_to_honeypot", lambda ip, reason: called.append(ip))
    agent._enforce_contain_and_patch([{"ip": "203.0.113.9"}], "c1")
    assert called == []                          # no patch this case -> no auto-contain


def test_backstop_skips_already_contained(monkeypatch):
    agent._CONTEXT.patched = True
    agent.do_blacklist_ip("203.0.113.8", "prior ban")
    monkeypatch.setattr(agent, "_lacks_malicious_verdict", lambda ip: False)
    called = []
    monkeypatch.setitem(agent.DISPATCH, "divert_to_honeypot", lambda ip, reason: called.append(ip))
    agent._enforce_contain_and_patch([{"ip": "203.0.113.8"}], "c1")
    assert called == []                          # already banned -> not double-contained


def test_blacklist_strengthens_only():
    agent.do_blacklist_ip("192.0.2.2", "provisional", expires=store.now_plus(60))
    agent.do_blacklist_ip("192.0.2.2", "confirmed")
    entry = next(d for d in store.load_state()["denylist"] if d["ip"] == "192.0.2.2")
    assert entry["expires"] is None  # upgraded to permanent


def test_blacklist_does_not_weaken_permanent():
    agent.do_blacklist_ip("192.0.2.3", "permanent")
    agent.do_blacklist_ip("192.0.2.3", "ttl", expires=store.now_plus(60))
    entry = next(d for d in store.load_state()["denylist"] if d["ip"] == "192.0.2.3")
    assert entry["expires"] is None


def test_unban_ip():
    agent.do_blacklist_ip("192.0.2.4", "test")
    agent.do_unban_ip("192.0.2.4", "false positive")
    assert not any(d["ip"] == "192.0.2.4" for d in store.load_state()["denylist"])


def test_bulk_blacklist():
    agent.do_bulk_blacklist_ip(["192.0.2.5", "192.0.2.6"], "campaign")
    ips = {d["ip"] for d in store.load_state()["denylist"]}
    assert {"192.0.2.5", "192.0.2.6"} <= ips


def test_bulk_blacklist_deduplicates():
    agent.do_bulk_blacklist_ip(["192.0.2.7", "192.0.2.7"], "dupe")
    assert sum(1 for d in store.load_state()["denylist"] if d["ip"] == "192.0.2.7") == 1


def test_bulk_blacklist_too_many_rejected():
    with pytest.raises(ValueError):
        agent.do_bulk_blacklist_ip(["1.2.3.4"] * 201, "overflow")


def test_inspect_target_returns_facts():
    result = json.loads(agent.do_inspect_target("/login", "POST", "user=alice", "pass=x"))
    assert result["path"] == "/login" and result["method"] == "POST"
    assert "note" in result and "signature" not in result["note"].lower()


def test_raise_alert_records_incident():
    agent.do_raise_alert("high", "sql_injection", "192.0.2.8", "evidence", "summary")
    incidents = store.read_jsonl(store.INCIDENTS_FILE)
    assert any(i.get("attack_type") == "sql_injection" for i in incidents)


def test_alert_evidence_truncated():
    # Evidence is a human-readable string; very long values are capped.
    agent.do_raise_alert("high", "sql_injection", "192.0.2.9",
                         "x" * 3000, "summary")
    incidents = store.read_jsonl(store.INCIDENTS_FILE)
    assert incidents and len(incidents[-1]["evidence"]) <= 2000


def test_execute_tool_validates_schema():
    result = agent.execute_tool("blacklist_ip", {"ip": "not-an-ip"}, "case1")
    assert "REJECTED" in result


def test_execute_tool_unknown():
    result = agent.execute_tool("nonexistent", {}, "case2")
    assert "REJECTED" in result


def test_execute_tool_idempotent():
    store.append_jsonl(store.ACTIONS_FILE, {"kind": "triage", "ip": "192.0.2.10", "path": "/x",
                       "jev": {"malicious": True, "malicious_score": 0.97}})
    r1 = agent.execute_tool("blacklist_ip", {"ip": "192.0.2.10", "reason": "test"}, "case3")
    r2 = agent.execute_tool("blacklist_ip", {"ip": "192.0.2.10", "reason": "test"}, "case3")
    assert r1 == r2
    assert sum(1 for d in store.load_state()["denylist"] if d["ip"] == "192.0.2.10") == 1


def test_agent_loop_calls_tool():
    store.append_jsonl(store.ACTIONS_FILE, {"kind": "triage", "ip": "192.0.2.11", "path": "/x",
                       "jev": {"malicious": True, "malicious_score": 0.95}})
    client = StubClient([[("blacklist_ip", {"ip": "192.0.2.11", "reason": "confirmed"})], []])
    event = store.enqueue_event({"ip": "192.0.2.11", "path": "/x", "method": "GET",
                                 "query": "", "body": "", "ts": store.now()})
    store.claim_events()
    agent.analyse(client, [{"ip": "192.0.2.11", "path": "/x", "id": event}])
    assert any(d["ip"] == "192.0.2.11" for d in store.load_state()["denylist"])


def test_agent_loop_max_turns_respected():
    # Every turn returns another tool call — must terminate at MAX_TURNS.
    class Infinite:
        class messages:
            @staticmethod
            def create(**_):
                return _block(stop_reason="tool_use",
                              content=[_block(type="tool_use", id="t0", name="inspect_target",
                                             input={"path": "/"})],
                              usage=_block(input_tokens=1, output_tokens=1))
        @staticmethod
        def with_options(**_):
            return Infinite

    with pytest.raises(Exception):  # TimeoutError
        agent._run_agent(Infinite, "system", "user", case_id="c1")


def test_sig_preserves_case_and_whitespace():
    e1 = {"method": "GET", "path": "/x", "query": "A=1", "body": ""}
    e2 = {"method": "get", "path": "/x", "query": "a=1", "body": ""}
    assert agent._sig(e1) != agent._sig(e2)


def test_dedupe_by_exact_content():
    events = [
        {"ip": "10.0.0.1", "method": "GET", "path": "/x", "query": "q=1", "body": ""},
        {"ip": "10.0.0.2", "method": "GET", "path": "/x", "query": "q=1", "body": ""},
        {"ip": "10.0.0.1", "method": "GET", "path": "/x", "query": "q=2", "body": ""},
    ]
    deduped = agent._dedupe(events)
    assert len(deduped) == 3  # different ip+content combos all kept


def test_swarm_routes_to_supervisor():
    called = []

    def mock_supervise(client, evs, kwargs):
        called.append(len(evs))

    import unittest.mock as mock
    with mock.patch.object(agent, "supervise", mock_supervise):
        events = [{"ip": f"10.0.0.{i}", "method": "GET", "path": "/x",
                   "query": "q=1", "body": "", "id": i} for i in range(agent.SUPERVISOR_MIN + 1)]
        agent.dispatch_swarm(None, events, {})
    assert called


def test_swarm_per_ip_below_threshold():
    analysed = []

    def mock_analyse(client, evs, kwargs):
        analysed.extend(e.get("ip") for e in evs)

    import unittest.mock as mock
    with mock.patch.object(agent, "analyse", mock_analyse):
        events = [{"ip": f"10.0.0.{i}", "method": "GET", "path": "/x",
                   "query": f"q={i}", "body": "", "id": i} for i in range(2)]
        agent.dispatch_swarm(None, events, {})
    assert len(set(analysed)) == 2


def test_process_batch_observe_mode():
    from bastion.settings import Settings
    policy = Settings(mode="observe", management_token="x" * 32, inline_failure="reject",
                      demo_identity=False, trusted_proxies="", request_limit=65536,
                      response_limit=2097152, timeout=5.0, concurrency=8,
                      budget_per_minute=9999, queue_limit=10000, allow_destructive=False)
    eid = store.enqueue_event({"ip": "10.0.0.1", "path": "/x", "method": "GET",
                               "query": "", "body": "", "ts": store.now()})
    events = store.claim_events()
    agent.process_batch(events, policy, client=None)
    # Event is consumed without any bans.
    assert not store.load_state()["denylist"]
    assert store.claim_events() == []


# --- containment guard: never ban/divert a source the classifier scored benign ---
def test_containment_refused_for_classifier_benign_source():
    from bastion import store, blue_agent
    store.append_jsonl(store.ACTIONS_FILE, {"kind": "triage", "ip": "198.51.100.50", "path": "/p",
                       "jev": {"malicious": False, "malicious_score": 0.02}})
    r = blue_agent.execute_tool("divert_to_honeypot",
                                {"ip": "198.51.100.50", "reason": "looks like a campaign"}, "c1")
    assert r.startswith("REJECTED")
    assert "198.51.100.50" not in [d["ip"] for d in store.load_state().get("honeypot", [])]


def test_containment_allowed_for_classifier_malicious_source():
    from bastion import store, blue_agent
    store.append_jsonl(store.ACTIONS_FILE, {"kind": "triage", "ip": "203.0.113.9", "path": "/p",
                       "jev": {"malicious": True, "malicious_score": 0.98}})
    r = blue_agent.execute_tool("blacklist_ip", {"ip": "203.0.113.9", "reason": "confirmed sqli"}, "c2")
    assert not r.startswith("REJECTED")
    assert "203.0.113.9" in [d["ip"] for d in store.load_state().get("denylist", [])]


def test_containment_refused_when_classifier_has_no_verdict():
    from bastion import store, blue_agent
    # no malicious verdict on record (classifier hasn't judged this source) -> containment refused,
    # which also closes the timing hole where the agent sees a not-yet-classified benign request.
    r = blue_agent.execute_tool("blacklist_ip", {"ip": "203.0.113.10", "reason": "manual"}, "c3")
    assert r.startswith("REJECTED")
    assert "203.0.113.10" not in [d["ip"] for d in store.load_state().get("denylist", [])]


def test_case_voided_by_lab_reset_leaves_no_trace(monkeypatch):
    """A case still open when the operator resets the lab must not re-apply defenses or file
    incidents onto the cleared board: once its events are gone, every mutating tool is refused,
    the agent stops, and the contain-and-patch backstop does nothing."""
    from bastion import operator_controls
    monkeypatch.setattr(operator_controls, "_restore_target", lambda: {"ok": True, "level": "medium"})
    event_id = store.append_jsonl(store.EVENTS_FILE, {"ts": store.now(), "ip": "198.51.100.15",
                                                      "path": "/hub/directory", "status": 200})
    case = str(event_id)
    assert agent._case_is_stale(case) is False
    operator_controls.reset()                    # operator presses Reset mid-case
    assert agent._case_is_stale(case) is True
    client = StubClient([[("virtual_patch", {"path": "/hub/directory", "attack_type": "xss", "reason": "late"})],
                         [("divert_to_honeypot", {"ip": "198.51.100.15", "reason": "late"})]])
    agent._run_agent(client, agent.SYSTEM, "{}", {}, case)
    agent._enforce_contain_and_patch([{"ip": "198.51.100.15"}], case)
    state = store.load_state()
    assert state.get("vpatch", []) == [] and state.get("honeypot", []) == []
    assert client.messages.call_count == 1       # stopped right after the refused tool
    assert [a["tool"] for a in store.read_jsonl(store.ACTIONS_FILE)] == ["operator_reset"]


# --- triage never waits on an investigation ---

def _agent_policy():
    from bastion.settings import Settings
    return Settings(mode="agent", management_token="x" * 32, inline_failure="reject",
                    demo_identity=False, trusted_proxies="", request_limit=65536,
                    response_limit=2097152, timeout=5.0, concurrency=8,
                    budget_per_minute=9999, queue_limit=10000, allow_destructive=False)


def _event(ip, path):
    store.enqueue_event({"ip": ip, "path": path, "method": "GET", "query": "", "body": "", "ts": store.now()})
    return store.claim_events()


def test_jev_keeps_triaging_while_bastion_investigates(monkeypatch):
    import threading
    release, started = threading.Event(), threading.Event()
    def slow_case(client, cases, kwargs):
        started.set(); release.wait(5)
    monkeypatch.setattr(agent, "dispatch_swarm", slow_case)
    monkeypatch.setattr(agent, "real_key", lambda name: True)
    monkeypatch.setattr(agent.classifier, "classify_request",
                        lambda e, timeout=5: {"malicious": e["path"] == "/attack", "malicious_score": .9, "attack_type": "sqli"})
    triaged = []
    monkeypatch.setattr(agent, "record_triage", lambda e, escalated, outcome: triaged.append((e["ip"], escalated)))
    lane, policy = agent.CaseLane(), _agent_policy()
    agent.process_batch(_event("10.0.0.9", "/attack"), policy, client=object(), lane=lane)
    assert started.wait(2)                      # the case is running in the background
    agent.process_batch(_event("10.0.0.8", "/home"), policy, client=object(), lane=lane)
    assert triaged == [("10.0.0.9", True), ("10.0.0.8", False)]   # scored while the case is still open
    assert not release.is_set()
    release.set()


def test_batch_is_classified_concurrently(monkeypatch):
    import threading, time
    live, peak, lock = [0], [0], threading.Lock()
    def classify(e, timeout=5):
        with lock:
            live[0] += 1; peak[0] = max(peak[0], live[0])
        time.sleep(.05)
        with lock:
            live[0] -= 1
        return {"malicious": False, "malicious_score": .01}
    monkeypatch.setattr(agent, "real_key", lambda name: True)
    monkeypatch.setattr(agent.classifier, "classify_request", classify)
    for i in range(6):
        store.enqueue_event({"ip": f"10.0.1.{i}", "path": "/", "method": "GET", "query": "", "body": "", "ts": store.now()})
    agent.process_batch(store.claim_events(), _agent_policy(), client=None)
    assert peak[0] > 1
    assert store.claim_events() == []
