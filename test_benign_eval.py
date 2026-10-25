"""Benign traffic generator corpus + live-eval scorer.

Deterministic tests exercise the new logic (corpus cleanliness, verdict read-back, the
confusion matrix) against an in-process temp DB. The real end-to-end proof against a
running stack + real Jev is the opt-in test_live_eval (RUN_LIVE_EVAL=1)."""
import os

import pytest

import benign_agent
import eval_live
import store

TS = "2030-01-01T00:00:00Z"  # fixed timestamp so the scoring window is deterministic

# Unambiguous execution payloads. Must NOT match benign English that legitimately
# contains words like "union", "select", "drop", or a lone ";".
ATTACK_MARKERS = ["../", "..\\", "<script", "onerror=", "onload=", "javascript:",
                  "/etc/passwd", "union select", "drop table", "sleep(", "$(", "`"]


def _seed_triage(ip, malicious, score, path="/vulnerabilities/sqli/"):
    store.append_jsonl(store.ACTIONS_FILE, {
        "ts": TS, "kind": "triage", "case_id": ip, "ip": ip, "path": path,
        "jev": {"malicious": malicious, "malicious_score": score},
        "escalated": False, "outcome": "benign" if not malicious else "classifier_contained"})


def _seed_event_verdict(ip, malicious, score, path="/vulnerabilities/sqli/"):
    store.append_jsonl(store.EVENTS_FILE, {
        "ts": TS, "ip": ip, "path": path,
        "verdict": {"malicious": malicious, "malicious_score": score}})


def _fake_target():
    """The lab target's page shapes with one boot's randomized names, served in-process."""
    import httpx
    from urllib.parse import parse_qs
    session = {"in": False}
    def page(body):
        return httpx.Response(200, text=f"<html><body><main>{body}</main></body></html>")
    def tool(title, path, param, extra=""):
        return page(f'<div class="card"><h2>{title}</h2><form method="get" action="{path}">'
                    f'<input type="text" id="x" name="{param}" value="">'
                    f'<input type="hidden" name="go" value="1"><button>Go</button></form>{extra}</div>')
    tools = {"/ops/rec": ("Record lookup", "ref"), "/ops/ping": ("Network diagnostics", "target"),
             "/ops/docs": ("Document viewer", "name"), "/ops/people": ("Staff directory", "term")}
    def app(request):
        p = request.url.path
        if p == "/":
            if session["in"]:
                links = "".join(f'<li><a href="{k}">{v[0]}</a></li>' for k, v in tools.items())
                return page(f"<ul>{links}</ul>")
            return page('<a href="/hub/enter">Sign in</a> &middot; see the <a href="/hub/guide">operator handbook</a>.')
        if p == "/hub/guide":
            return page("<p>Operator ID: <strong>j.reyes</strong><br>Passphrase: <strong>ember-87</strong></p>")
        if p == "/hub/enter":
            if request.method == "POST":
                form = parse_qs(request.content.decode())
                if form.get("login") == ["j.reyes"] and form.get("secret") == ["ember-87"] and form.get("req_token") == ["t0k"]:
                    session["in"] = True
                    return httpx.Response(302, headers={"Location": "/"})
            return page('<form method="post" action="/hub/enter"><input type="hidden" name="req_token" value="t0k">'
                        '<input type="text" name="login"><input type="password" name="secret">'
                        '<input type="hidden" name="sub" value="1"></form>')
        if p in tools and session["in"]:
            extra = '<p class="muted">Available: notice.txt, changelog.txt</p>' if p == "/ops/docs" else ""
            return tool(*tools[p][:1], p, tools[p][1], extra)
        return httpx.Response(404)
    return httpx.MockTransport(app)


def _site(monkeypatch):
    import httpx
    transport = _fake_target()
    monkeypatch.setattr(benign_agent, "_client", lambda proxy, ip: httpx.Client(
        base_url="http://target", transport=transport, follow_redirects=True))
    return benign_agent.discover("http://target")


def test_discovers_the_running_instance(monkeypatch):
    """Routes, field names and demo credentials are learned by browsing, not hard-coded."""
    site = _site(monkeypatch)
    assert (site.signin, site.handbook, site.user, site.password) == ("/hub/enter", "/hub/guide", "j.reyes", "ember-87")
    assert (site.user_field, site.pass_field) == ("login", "secret")
    assert {k: (t["path"], t["param"]) for k, t in site.tools.items()} == {
        "lookup": ("/ops/rec", "ref"), "netcheck": ("/ops/ping", "target"),
        "fileview": ("/ops/docs", "name"), "search": ("/ops/people", "term")}
    assert site.docs == ["notice.txt", "changelog.txt"]


def test_benign_corpus_is_clean(monkeypatch):
    """Every generated benign request hits a discovered route and carries no attack payload."""
    site = _site(monkeypatch)
    for _ in range(25):  # cover the randomized name/host/id choices
        for method, path, query, body in benign_agent.benign_requests(site):
            assert path in site.paths()
            haystack = f"{query} {body}".lower()
            for marker in ATTACK_MARKERS:
                assert marker not in haystack, f"attack payload {marker!r} in benign corpus"


def test_journey_signs_in_and_uses_every_tool(monkeypatch):
    site = _site(monkeypatch)
    random_state = benign_agent.random.getstate()
    benign_agent.random.seed(1)
    try:
        assert benign_agent.journey(site, "http://target", "198.51.100.9") >= 7   # sign-in (2) + 5 requests
    finally:
        benign_agent.random.setstate(random_state)


def test_score_counts_confusion_matrix_from_triage():
    _seed_triage("198.51.100.5", False, 0.02)   # benign, clean   -> TN
    _seed_triage("198.51.100.6", True, 0.91)    # benign, flagged -> FP (false positive)
    _seed_triage(eval_live.ATTACKER_IP, True, 0.95)   # attack, flagged -> TP
    _seed_triage(eval_live.ATTACKER_IP, False, 0.10)  # attack, missed  -> FN
    _seed_triage("8.8.8.8", True, 0.99)         # unknown source  -> excluded

    m = eval_live.score(eval_live.read_verdicts_db(TS, TS))

    assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (1, 1, 1, 1)
    assert m["n"] == 4  # the 8.8.8.8 row is excluded
    assert m["precision"] == 0.5 and m["recall"] == 0.5
    assert m["fp_rate"] == 0.5
    assert [f["ip"] for f in m["false_positives"]] == ["198.51.100.6"]
    assert [f["ip"] for f in m["false_negatives"]] == [eval_live.ATTACKER_IP]


def test_score_reads_inline_event_verdicts_when_no_triage():
    _seed_event_verdict("198.51.100.7", False, 0.03)
    _seed_event_verdict(eval_live.ATTACKER_IP, True, 0.97)

    m = eval_live.score(eval_live.read_verdicts_db(TS, TS))

    assert (m["tp"], m["fp"], m["tn"], m["fn"]) == (1, 0, 1, 0)
    assert m["recall"] == 1.0 and m["precision"] == 1.0


def test_score_falls_back_to_threshold_when_only_a_score():
    # verdict boolean absent -> predict by score vs classifier threshold
    store.append_jsonl(store.ACTIONS_FILE, {
        "ts": TS, "kind": "triage", "ip": eval_live.ATTACKER_IP, "path": "/x",
        "jev": {"malicious": None, "malicious_score": 0.88}})
    m = eval_live.score(eval_live.read_verdicts_db(TS, TS))
    assert m["tp"] == 1 and m["fn"] == 0


@pytest.mark.skipif(os.getenv("RUN_LIVE_EVAL") != "1",
                    reason="needs the running stack (DEMO_IDENTITY=1, real TYPESAFE_API_KEY)")
def test_live_eval():
    eval_live.preflight()
    phases = eval_live.run_scenario(before=15, during=30, after=15)
    start, end = phases["overall"]
    m = eval_live.score(eval_live.read_verdicts_api(start, end))
    eval_live.print_report("overall", m)
    assert m["n"] > 0, "no verdicts captured — is the stack in classifier-contain/agent mode?"
    assert m["fp_rate"] <= 0.10, f"benign false-positive rate too high: {m['fp_rate']:.1%}"
    assert m["recall"] >= 0.80, f"attack recall too low: {m['recall']:.1%}"
