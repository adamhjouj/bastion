"""Unit checks for the scoring harness — pure logic, manifest parsing, and the
store-reading extractor. No live stack, no provider key (mirrors test_benign_eval.py)."""
from evals import score_campaign as sc

# A real instance manifest (the fork writes this to /var/www/data/MUTATION.md at boot).
MANIFEST = """# Instance mutation manifest
| Property | DVWA original | This instance |
|---|---|---|
| App name | Damn Vulnerable Web Application | Helios Intranet |
| Login path | /login.php | /ops/records |
| SQLi path | /vulnerabilities/sqli/ | /ops/profile |
| Cmd-injection path | /vulnerabilities/exec/ | /ops/logon |
| LFI path | /vulnerabilities/fi/ | /ops/docs |
| XSS path | /vulnerabilities/xss_r/ | /ops/directory |
| SQLi id param | id | record |
| SQLi submit param | Submit | submit_btn |
| Cmdi host param | ip | host |
| LFI file param | page | doc |
| XSS query param | name | term |
| CSRF field | user_token | req_token |
| Login user field | username | userid |
| Login pass field | password | credential |
| Users table | users | accounts |
| username column | user | account |
| password column | password | cred_hash |
| Default creds | admin / password | m.okafor / harbor-lantern-21 |
"""


def test_parse_manifest():
    inst = sc.parse_manifest(MANIFEST)
    assert inst["login_path"] == "/ops/records"
    assert inst["sqli_path"] == "/ops/profile" and inst["sqli_param"] == "record"
    assert inst["cmdi_path"] == "/ops/logon" and inst["cmdi_param"] == "host"
    assert inst["lfi_path"] == "/ops/docs" and inst["file_param"] == "doc"
    assert inst["xss_path"] == "/ops/directory" and inst["q_param"] == "term"
    assert inst["table"] == "accounts" and inst["col_cred"] == "cred_hash"
    assert inst["user"] == "m.okafor" and inst["password"] == "harbor-lantern-21"


def test_build_goals_uses_instance_names():
    goals = sc.build_goals(sc.parse_manifest(MANIFEST))
    sqli = goals["sqli"]
    assert sqli["path"] == "/ops/profile"
    assert sqli["params"]["record"] == "0 UNION SELECT account, cred_hash FROM accounts"
    assert goals["cmdi"]["path"] == "/ops/logon"
    assert goals["cmdi"]["params"]["host"] == "127.0.0.1 | cat /etc/passwd"
    assert goals["lfi"]["path"] == "/ops/docs"
    assert goals["lfi"]["params"]["doc"] == "....//....//....//....//....//....//etc/passwd"
    assert goals["xss"]["path"] == "/ops/directory"
    assert goals["xss"]["params"]["term"] == sc.XSS_PAYLOAD


def test_parse_manifest_rejects_incomplete():
    import pytest
    with pytest.raises(ValueError):
        sc.parse_manifest("| Property | orig | this |\n|--|--|--|\n| App name | x | y |\n")


def test_outcome_truth_table():
    assert sc.classify_outcome(True, False) == "BREACH"        # got the data, no contain
    assert sc.classify_outcome(True, True) == "BREACH"         # got the data despite a contain
    assert sc.classify_outcome(False, True) == "CONTAINED"     # goal denied, source contained
    assert sc.classify_outcome(False, False) == "INCONCLUSIVE"  # exploit never landed


def test_goal_signatures():
    assert sc.SIGNATURES["sqli"].search("account: j.reyes | cred_hash: 5f4dcc3b5aa765d61d8327deb882cf99")
    assert not sc.SIGNATURES["sqli"].search("<p>No matching record.</p>")
    assert sc.SIGNATURES["cmdi"].search("root:x:0:0:root:/root:/bin/bash")
    assert not sc.SIGNATURES["cmdi"].search("PING 127.0.0.1: 56 data bytes")
    assert sc.SIGNATURES["lfi"].search("root:x:0:0:root:/root:/bin/bash")
    assert not sc.SIGNATURES["lfi"].search("Operations notice\nMaintenance window")
    # XSS: matches the reflected raw tag, not its HTML-escaped (inert) form
    assert sc.SIGNATURES["xss"].search("&ldquo;<img src=x onerror=alert('BASTIONXSS9f')>&rdquo;")
    assert not sc.SIGNATURES["xss"].search("&lt;img src=x onerror=alert(&#039;BASTIONXSS9f&#039;)&gt;")


def test_hidden_value():
    html = '<input type="hidden" name="req_token" value="deadbeef00">'
    assert sc._hidden_value(html, "req_token") == "deadbeef00"
    assert sc._hidden_value(html, "nonce") == ""


def test_targets_ip():
    assert sc._targets_ip({"ip": "203.0.113.77"}, "203.0.113.77")
    assert sc._targets_ip({"ips": ["1.2.3.4", "203.0.113.77"]}, "203.0.113.77")
    assert not sc._targets_ip({"ip": "9.9.9.9"}, "203.0.113.77")
    assert not sc._targets_ip({}, "203.0.113.77")


def test_seconds():
    assert sc._seconds("2026-01-01T00:00:00Z", "2026-01-01T00:00:05Z") == 5.0
    assert sc._seconds("2026-01-01T00:00:10Z", "2026-01-01T00:00:00Z") == 0.0  # clamped


def test_detection_and_containment(monkeypatch):
    ip = "203.0.113.77"
    pages = {
        "requests": [
            {"ip": "198.51.100.5", "ts": "2026-01-01T00:00:01Z", "verdict": {"malicious": False}},
            {"ip": ip, "ts": "2026-01-01T00:00:04Z", "verdict": {"malicious": True}},  # detection
            {"ip": ip, "ts": "2026-01-01T00:00:02Z", "verdict": {"malicious": False}},
        ],
        "actions": [
            {"kind": "triage", "ip": ip, "ts": "2026-01-01T00:00:06Z", "jev": {"malicious": True}},
            {"kind": "action", "tool": "blacklist_ip", "outcome": "ok",
             "input": {"ip": ip}, "ts": "2026-01-01T00:00:09Z"},                       # containment
            {"kind": "action", "tool": "inspect_target", "outcome": "ok",
             "input": {"ip": ip}, "ts": "2026-01-01T00:00:03Z"},                        # not a contain tool
        ],
    }
    monkeypatch.setattr(sc.eval_live, "_api_pages",
                        lambda base, token, kind, start: iter(pages[kind]))
    det, cont = sc.detection_and_containment(ip, "2026-01-01T00:00:00Z", "2026-01-01T00:00:20Z")
    assert det == "2026-01-01T00:00:04Z"   # earliest malicious recognition (request verdict)
    assert cont == "2026-01-01T00:00:09Z"  # the blacklist_ip action, not inspect_target


def test_containment_ignores_other_source(monkeypatch):
    ip = "203.0.113.77"
    pages = {"requests": [], "actions": [
        {"kind": "action", "tool": "blacklist_ip", "outcome": "ok",
         "input": {"ip": "8.8.8.8"}, "ts": "2026-01-01T00:00:05Z"},  # a different source banned
    ]}
    monkeypatch.setattr(sc.eval_live, "_api_pages",
                        lambda base, token, kind, start: iter(pages[kind]))
    det, cont = sc.detection_and_containment(ip, "2026-01-01T00:00:00Z", "2026-01-01T00:00:20Z")
    assert det is None and cont is None
