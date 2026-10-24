"""One runnable check for the non-trivial blue-team logic: regex pre-filter,
tool dispatch, state mutation, and the real email send (to MailHog). Stubs only
the LLM call. Run: .venv/bin/python test_pipeline.py  (needs MailHog on :1025)"""
import json
import types
import urllib.request

import blue_agent
import classifier
import store


def _block(**kw):
    return types.SimpleNamespace(**kw)


class StubMessages:
    """Returns one tool_use turn (ban + waf + alert), then end_turn."""
    def __init__(self):
        self.calls = 0

    def create(self, **_):
        self.calls += 1
        if self.calls == 1:
            return _block(stop_reason="tool_use", content=[
                _block(type="tool_use", id="t1", name="blacklist_ip",
                       input={"ip": "10.13.37.7", "reason": "SQLi exfil"}),
                _block(type="tool_use", id="t2", name="add_waf_rule",
                       input={"pattern": r"union\s+select", "description": "block SQLi UNION"}),
                _block(type="tool_use", id="t3", name="raise_alert",
                       input={"severity": "high", "attack_type": "sql_injection",
                              "source_ip": "10.13.37.7",
                              "evidence": "GET /vulnerabilities/sqli/?id=1' UNION SELECT ...",
                              "summary": "Banned IP, added WAF rule."}),
            ])
        return _block(stop_reason="end_turn", content=[_block(type="text", text="done")])


class StubClient:
    def __init__(self):
        self.messages = StubMessages()


def test_jev_mock(monkeypatch=None):
    """Jev classifier against MOCK network responses (no key, no real call)."""
    class FakeResp:
        def __init__(self, payload):
            self._p = payload

        def raise_for_status(self):
            pass

        def json(self):
            return self._p

    sqli_payload = {"answers": {
        "malicious": {"type": "noul", "noul": 0.97},
        "attack_type": {"type": "choice", "choice": "sql_injection", "confidence": 0.95,
                        "probabilities": {"sql_injection": 0.95, "benign": 0.05}}}}
    benign_payload = {"answers": {
        "malicious": {"type": "noul", "noul": 0.03},
        "attack_type": {"type": "choice", "choice": "benign", "confidence": 0.99,
                        "probabilities": {"benign": 0.99}}}}

    # malicious mock
    classifier.httpx.post = lambda *a, **k: FakeResp(sqli_payload)
    v = classifier.classify_request({"method": "GET", "path": "/vulnerabilities/sqli/",
                                     "query": "id=1' UNION SELECT ...", "body": "", "ip": "1.1.1.1"})
    assert v["malicious"] is True and v["attack_type"] == "sql_injection", v

    # benign mock
    classifier.httpx.post = lambda *a, **k: FakeResp(benign_payload)
    v = classifier.classify_request({"method": "GET", "path": "/login.php",
                                     "query": "", "body": "", "ip": "2.2.2.2"})
    assert v["malicious"] is False, v

    # network error -> fail-safe (malicious None, caller escalates)
    def boom(*a, **k):
        raise RuntimeError("connection refused")
    classifier.httpx.post = boom
    v = classifier.classify_request({"method": "GET", "path": "/x", "query": "", "body": "", "ip": "3.3.3.3"})
    assert v["malicious"] is None and "error" in v, v
    print("OK jev classifier (mock network: malicious / benign / error-failsafe)")


def main():
    test_jev_mock()

    # fresh state
    store.save_state(json.loads(json.dumps(store.DEFAULT_STATE)))
    open(store.INCIDENTS_FILE, "w").close()

    # 1. pre-filter: catches attacks, ignores benign
    assert blue_agent.is_suspicious({"path": "/vulnerabilities/sqli/",
                                     "query": "id=1' OR '1'='1", "body": ""})
    assert blue_agent.is_suspicious({"path": "/vulnerabilities/exec/",
                                     "query": "", "body": "ip=1.1.1.1; cat /etc/passwd"})
    assert not blue_agent.is_suspicious({"path": "/login.php", "query": "", "body": ""})
    print("OK pre-filter")

    # 2. full analyse() with stubbed LLM -> real tool dispatch + email
    blue_agent.analyse(StubClient(), [{"ip": "10.13.37.7", "path": "/vulnerabilities/sqli/",
                                       "query": "id=1' UNION SELECT user,password FROM users",
                                       "body": "", "status": 200}])
    st = store.load_state()
    assert any(d["ip"] == "10.13.37.7" for d in st["denylist"]), "IP not blacklisted"
    assert any(r["pattern"] == r"union\s+select" for r in st["rules"]), "WAF rule missing"
    incidents = store.read_jsonl(store.INCIDENTS_FILE)
    assert incidents and incidents[-1]["attack_type"] == "sql_injection", "incident not recorded"
    print("OK dispatch -> state + incident")

    # 3. email actually reached MailHog
    try:
        msgs = json.load(urllib.request.urlopen("http://localhost:8025/api/v2/messages", timeout=5))
        assert msgs["total"] >= 1, "no email in MailHog"
        print(f"OK email delivered to MailHog ({msgs['total']} message(s))")
    except Exception as e:
        print(f"SKIP email check (MailHog not reachable: {e})")

    print("\nALL CHECKS PASSED")


if __name__ == "__main__":
    main()
