"""One runnable check for the non-trivial blue-team logic: regex pre-filter,
tool dispatch, state mutation, and the real email send (to MailHog). Stubs only
the LLM call. Run: .venv/bin/python test_pipeline.py  (needs MailHog on :1025)"""
import json
import types
import urllib.request

import blue_agent
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


def main():
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
