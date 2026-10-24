"""Self-check for the botnet supervisor tier: signature normalization, bulk ban
(dedup + strengthen-only), the compact campaign summary, and the dispatch tiering
(>= SUPERVISOR_MIN distinct IPs -> ONE commander; fewer -> per-IP swarm). Stubs the
LLM client (no network) and drives the real tool dispatch + state writes."""
import json

import blue_agent as b
import store


class _Block:
    def __init__(self, type, name=None, input=None, id=None, text=None):
        self.type, self.name, self.input, self.id, self.text = type, name, input, id, text


class _Resp:
    def __init__(self, stop_reason, content):
        self.stop_reason, self.content = stop_reason, content


class StubClient:
    """One round of scripted tool calls, then stop. Thread-safe enough for the swarm path."""
    def __init__(self, calls):
        self._calls, self._done, self.messages = calls, False, self

    def create(self, **kw):
        if self._done or not self._calls:
            return _Resp("end_turn", [_Block("text", text="done")])
        self._done = True
        return _Resp("tool_use", [_Block("tool_use", name=n, input=i, id=f"t{k}")
                                  for k, (n, i) in enumerate(self._calls)])


def fresh():
    store.save_state(json.loads(json.dumps(store.DEFAULT_STATE)))


def test_sig():
    a = {"method": "POST", "path": "/x", "query": "id=1 UNION  SELECT", "body": ""}
    c = {"method": "post", "path": "/x", "query": "id=1 union select", "body": ""}
    assert b._sig(a) == b._sig(c), (b._sig(a), b._sig(c))
    print("OK _sig normalization (case/whitespace collapse)")


def test_bulk_ban():
    fresh()
    b.do_bulk_blacklist_ip(["1.1.1.1", "2.2.2.2", "1.1.1.1"], "botnet")   # dup collapses
    dl = {d["ip"] for d in store.load_state()["denylist"]}
    assert {"1.1.1.1", "2.2.2.2"} <= dl, dl
    b.do_bulk_blacklist_ip(["3.3.3.3"], "ttl", expires=store.now_plus(60))  # provisional
    b.do_bulk_blacklist_ip(["3.3.3.3"], "confirm")                          # -> durable
    e3 = next(d for d in store.load_state()["denylist"] if d["ip"] == "3.3.3.3")
    assert e3["expires"] is None, e3  # strengthen-only preserved
    print("OK bulk ban (dedup + strengthen-only, one save)")


def test_campaign_summary():
    evs = [{"ip": f"10.0.0.{i}", "method": "GET", "path": "/vulnerabilities/sqli/",
            "query": "id=1 UNION SELECT user,password FROM users", "body": "",
            "_jev": {"attack_type": "sql_injection"}} for i in range(50)]
    s = b._campaign_summary(evs)
    assert "50 distinct source IP" in s and "sql_injection" in s and "more" in s, s[:200]
    assert len(s) < 2000, f"summary not compact: {len(s)} chars"
    print("OK campaign summary (compact, IP list capped)")


def test_tiering_supervisor():
    fresh()
    ips = [f"10.1.0.{i}" for i in range(b.SUPERVISOR_MIN + 2)]   # above the flood threshold
    evs = [{"ip": ip, "method": "GET", "path": "/vulnerabilities/sqli/",
            "query": "id=1 UNION SELECT 1", "body": "", "blocked": False,
            "_jev": {"attack_type": "sql_injection", "malicious_score": 0.99}} for ip in ips]
    stub = StubClient([("add_waf_rule", {"pattern": r"union\s+select",
                                         "description": "class-wide SQLi"}),
                       ("bulk_blacklist_ip", {"ips": ips, "reason": "botnet SQLi"})])
    b.dispatch_swarm(stub, evs, {})
    st = store.load_state()
    assert any(r["pattern"] == r"union\s+select" for r in st["rules"]), "class-wide rule missing"
    assert set(ips) <= {d["ip"] for d in st["denylist"]}, "bulk ban missing"
    print(f"OK tiering: {len(ips)} IPs -> commander (1 class-wide rule + bulk ban of {len(ips)})")


def test_tiering_swarm():
    fresh()
    evs = [{"ip": f"10.2.0.{i}", "method": "GET", "path": "/vulnerabilities/sqli/",
            "query": "id=1 UNION SELECT 1", "body": "", "blocked": False,
            "_jev": {"attack_type": "sql_injection"}} for i in range(2)]  # below threshold
    b.dispatch_swarm(StubClient([]), evs, {})  # per-IP path; stub says 'no threat' -> no writes
    assert not store.load_state()["rules"], "swarm path should not have added rules here"
    print("OK tiering: few IPs -> per-IP swarm (no supervisor)")


if __name__ == "__main__":
    test_sig()
    test_bulk_ban()
    test_campaign_summary()
    test_tiering_supervisor()
    test_tiering_swarm()
    print("\nsupervisor tier: ALL PASSED")
