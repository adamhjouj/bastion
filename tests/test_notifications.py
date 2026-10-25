"""Resend transport and real SQLite outbox tests. No live emails are sent."""
import json

import httpx
import pytest

from bastion import mail_worker
from bastion import notifications as mail
from bastion import store


@pytest.fixture(autouse=True)
def email_config(monkeypatch):
    monkeypatch.setenv("RESEND_API_KEY", "re_test_only_not_real")
    monkeypatch.setenv("ALERT_FROM", "Bastion Alerts <alerts@bastion0.dev>")
    monkeypatch.setenv("ALERT_TO", "recipient@example.com")


def incident(**changes):
    return {"severity": "high", "attack_type": "sql_injection", "source_ip": "192.0.2.1",
            "ts": "2026-01-01T00:00:00Z", "case_id": "test-case", "summary": "Confirmed lab test",
            "evidence": "<script>untrusted</script>", **changes}


def test_resend_payload_and_auth():
    requests = []

    def api(request):
        requests.append(request)
        return httpx.Response(200, json={"id": "email-123"})
    result = mail.send_email(incident(), transport=httpx.MockTransport(api))
    assert result == {"provider": "resend", "provider_id": "email-123", "status": "accepted"}
    request = requests[0]
    assert str(request.url) == "https://api.resend.com/emails"
    assert request.headers["Authorization"] == "Bearer re_test_only_not_real"
    payload = json.loads(request.content)
    assert payload["from"] == "Bastion Alerts <alerts@bastion0.dev>"
    assert payload["to"] == ["recipient@example.com"]
    assert "Bastion security incident" in payload["subject"]
    assert "&lt;script&gt;" in payload["html"]
    assert "<script>untrusted</script>" not in payload["html"]
    assert "re_test" not in request.content.decode()


def test_multiple_recipient_addresses(monkeypatch):
    monkeypatch.setenv("ALERT_TO", "one@example.com, Two <two@example.com>, one@example.com")
    assert mail.prepare_message(incident())["to"] == ["one@example.com", "two@example.com"]


@pytest.mark.parametrize("field,value", [("ALERT_TO", "invalid"), ("ALERT_FROM", ""),
                                        ("ALERT_TO", "a@example.com\r\nBcc: b@example.com")])
def test_bad_addresses_rejected(monkeypatch, field, value):
    monkeypatch.setenv(field, value)
    with pytest.raises(mail.MailError):
        mail.prepare_message(incident())


def test_missing_key_uses_local_fallback_not_resend(monkeypatch, tmp_path, capsys):
    # Local demo, no RESEND_API_KEY: must not drop the alert and must not crash;
    # it lands in a local sink (file + stdout) instead of hitting Resend.
    monkeypatch.delenv("RESEND_API_KEY")
    monkeypatch.setattr(mail, "LOCAL_OUTBOX", tmp_path / "local_mail.jsonl")

    def fail_if_called(request):
        pytest.fail("must not call Resend when no key is configured")
    result = mail.send_email(incident(), transport=httpx.MockTransport(fail_if_called))
    assert result["provider"] == "local" and result["status"] == "accepted"
    lines = (tmp_path / "local_mail.jsonl").read_text().splitlines()
    assert len(lines) == 1
    record = json.loads(lines[0])
    assert record["to"] == ["recipient@example.com"]
    assert "Bastion security incident" in record["subject"]
    out = capsys.readouterr().out
    assert "no RESEND_API_KEY" in out and "Bastion security incident" in out


def test_blank_key_is_not_a_config_error_but_bad_key_is(monkeypatch):
    monkeypatch.delenv("RESEND_API_KEY")
    assert mail.validate_config() is None
    monkeypatch.setenv("RESEND_API_KEY", "not-a-real-key")
    with pytest.raises(mail.MailError, match="RESEND_API_KEY"):
        mail.validate_config()


@pytest.mark.parametrize("code,retry", [(401, False), (403, False), (422, False), (429, True), (500, True)])
def test_error_messages_dont_expose_response_or_keys(code, retry):
    transport = httpx.MockTransport(lambda req: httpx.Response(code, json={"message": "re_secret_do_not_log"},
                                                             headers={"retry-after": "3"}))
    with pytest.raises(mail.MailError) as error:
        mail.send_email(incident(), transport=transport)
    assert error.value.retryable == retry
    assert error.value.retry_after == 3
    assert "re_secret" not in str(error.value)


def test_network_failure_is_retryable():
    def fail(request):
        raise httpx.ConnectError("secret diagnostic that must not be logged")
    with pytest.raises(mail.MailError) as error:
        mail.send_email(incident(), transport=httpx.MockTransport(fail))
    assert error.value.retryable
    assert "secret diagnostic" not in str(error.value)


def test_malformed_success_is_retryable():
    with pytest.raises(mail.MailError):
        mail.send_email(incident(), transport=httpx.MockTransport(lambda _: httpx.Response(200, json={})))


def test_outbox_retries_same_payload_and_idempotency_key(monkeypatch):
    store.queue_mail("stable-key", incident())
    requests = []

    def api(request):
        requests.append(request)
        return httpx.Response(500 if len(requests) == 1 else 200, json={"id": "mail-123"})
    send = lambda item: mail.send_email(item, transport=httpx.MockTransport(api))
    assert store.deliver_mail(send)["status"] == "pending"
    monkeypatch.setenv("ALERT_TO", "different@example.com")
    with store.connection(write=True) as db:
        db.execute("UPDATE outbox SET available=0")
    assert store.deliver_mail(send)["status"] == "accepted"
    assert requests[0].content == requests[1].content
    assert requests[0].headers["Idempotency-Key"] == requests[1].headers["Idempotency-Key"]
    assert store.deliver_mail(send) is None
    with store.connection() as db:
        receipt = db.execute("SELECT * FROM mail_receipts").fetchone()
    assert receipt["provider_id"] == "mail-123" and receipt["status"] == "accepted"


def test_permanent_error_dead_letters_without_silent_fallback():
    store.queue_mail("bad-config", incident())
    transport = httpx.MockTransport(lambda _: httpx.Response(403, json={"message": "sensitive provider response"}))
    result = store.deliver_mail(lambda item: mail.send_email(item, transport=transport))
    assert result["status"] == "dead"
    assert "sensitive" not in result["error"]
    assert store.deliver_mail(lambda _: pytest.fail("must not retry permanent failure")) is None


def test_test_command_sends_only_its_synthetic_message(monkeypatch, capsys):
    store.queue_mail("unrelated-real-alert", incident())
    sent = []
    monkeypatch.setattr(mail_worker, "send_email", lambda item: sent.append(item) or {
        "provider": "resend", "status": "accepted", "provider_id": "test-id"})
    assert mail_worker.main(["--test"]) == 0
    assert len(sent) == 1 and sent[0]["attack_type"] == "notification_test"
    assert sent[0]["_mail"]["subject"].startswith("[TEST]")
    assert "re_test" not in capsys.readouterr().out
    with store.connection() as db:
        assert db.execute("SELECT status FROM outbox WHERE key='unrelated-real-alert'").fetchone()[0] == "pending"


def test_check_command_does_not_send(monkeypatch):
    monkeypatch.setattr(mail_worker, "send_email", lambda _: pytest.fail("check must not send"))
    assert mail_worker.main(["--check"]) == 0


def test_atomic_incident_and_mail_queue_on_config_error(monkeypatch):
    from bastion import blue_agent
    monkeypatch.setenv("ALERT_TO", "")
    with pytest.raises(mail.MailError):
        blue_agent.do_raise_alert("high", "test", "192.0.2.1", "evidence", "summary")
    assert store.read_jsonl(store.INCIDENTS_FILE) == []


# ---- the emailed report as the human review surface (PLAN B6, CONTRACTS 3.4) ----

def raise_case_with_actions(monkeypatch):
    """One investigated case: triage verdict, three actions, then the incident the agent raises."""
    from bastion import blue_agent
    event_id = store.enqueue_event({"ts": store.now(), "ip": "192.0.2.1", "path": "/lookup", "verdict": {"malicious": 1}})
    case_id = str(event_id)
    store.append_jsonl(store.ACTIONS_FILE, {"ts": store.now(), "kind": "triage", "case_id": case_id, "ip": "192.0.2.1",
                       "path": "/lookup", "jev": {"malicious": 1, "malicious_score": 0.97, "attack_type": "sql_injection",
                                                    "type_confidence": 0.9}, "escalated": True, "outcome": "escalated"})
    monkeypatch.setattr(blue_agent._CONTEXT, "case_id", case_id, raising=False)
    blue_agent.record_action("get_defenses", {}, "read-only")
    blue_agent.record_action("divert_to_honeypot", {"ip": "192.0.2.1", "reason": "confirmed SQLi"}, "diverted")
    blue_agent.do_virtual_patch("/lookup", "sql_injection", "confirmed SQLi")
    blue_agent.record_action("virtual_patch", {"path": "/lookup", "attack_type": "sql_injection", "reason": "confirmed SQLi"}, "installed")
    blue_agent.do_raise_alert("high", "sql_injection", "192.0.2.1", "GET /lookup?id=1' OR 1=1 <script>x</script>", "SQLi confirmed")
    blue_agent.record_action("raise_alert", {"severity": "high", "token": "must-not-appear"}, "queued")
    with store.connection() as db:
        incident_id = db.execute("SELECT id FROM records WHERE kind='incidents'").fetchone()[0]
    return case_id, incident_id


def deliver_through_worker(api):
    """Run the outbox the way the daemon does: first-attempt enrichment, then the transport."""
    return store.deliver_mail(lambda item: mail.send_email(mail_worker.enrich_outbox_item(item), transport=httpx.MockTransport(api)))


def test_report_carries_actions_deep_link_and_audit_head(monkeypatch):
    from bastion import audit
    monkeypatch.setenv("PUBLIC_DASHBOARD_URL", "https://soc.example.com/")
    case_id, incident_id = raise_case_with_actions(monkeypatch)
    requests = []
    assert deliver_through_worker(lambda r: requests.append(r) or httpx.Response(200, json={"id": "m1"}))["status"] == "accepted"
    payload = json.loads(requests[0].content)
    text, body = payload["text"], payload["html"]
    # what it saw
    assert "Classifier verdict: malicious (score 0.97, type sql_injection" in text
    assert "Evidence excerpt: GET /lookup?id=1' OR 1=1" in text
    # what it did: humanized, chronological, with parameters, outcome and reversibility
    assert text.index("Reviewed active defenses") < text.index("Diverted source to honeypot") < text.index("Virtual-patched route") < text.index("Raised this incident")
    assert "Diverted source to honeypot — ip=192.0.2.1; reason=confirmed SQLi — outcome: ok — reversible (inverse: undivert)" in text
    assert "Virtual-patched route at the proxy — path=/lookup; attack_type=sql_injection" in text
    assert "reversible (inverse: remove_vpatch)" in text
    assert "Reviewed active defenses — outcome: ok — not applicable (read-only)" in text
    assert "Raised this incident — severity=high; " not in text and "must-not-appear" not in text
    # what changed
    assert "Proxy virtual patches: /lookup [sql_injection] active" in text
    # how to verify: the live audit head
    head = audit.head()
    assert head["head"] and f"Audit chain: {head['length']} chained action(s); head sha256 {head['head']}" in text
    # review and roll back: the authenticated case file, no action links
    link = f"https://soc.example.com/__dash#/incidents/{incident_id}"
    assert link in text and f'<a href="{link}">' in body
    assert "/rollback" not in body and body.count("<a ") == 1
    assert "<img" not in body and "<script>" not in body and "&lt;script&gt;" in body
    assert "incident(s) in the last 30 days versus" in text
    assert payload["subject"] == "[HIGH] Bastion security incident"


def test_report_renders_without_audit_and_rollback_modules(monkeypatch):
    monkeypatch.setattr(mail, "audit", None)
    monkeypatch.setattr(mail, "rollback", None)
    raise_case_with_actions(monkeypatch)
    requests = []
    assert deliver_through_worker(lambda r: requests.append(r) or httpx.Response(200, json={"id": "m1"}))["status"] == "accepted"
    text = json.loads(requests[0].content)["text"]
    assert "Audit chain: not available in this deployment." in text
    assert "Diverted source to honeypot — ip=192.0.2.1; reason=confirmed SQLi — outcome: ok — reversibility unknown" in text
    assert "One-click rollback is not available in this deployment." in text
    assert "http://localhost:8080/__dash#/incidents/" in text


def test_report_with_empty_action_list():
    store.queue_mail("no-actions", incident(case_id="orphan-case"))
    requests = []
    assert deliver_through_worker(lambda r: requests.append(r) or httpx.Response(200, json={"id": "m1"}))["status"] == "accepted"
    text = json.loads(requests[0].content)["text"]
    assert "WHAT IT DID (0 ACTION(S), CHRONOLOGICAL)\nNo actions are recorded for this case yet" in text
    assert "Classifier verdict: none recorded for this case" in text
    assert "Bans: none" in text and "Quarantine: none" in text
    assert "http://localhost:8080/__dash#/incidents\n" in text  # unknown incident id: the list, never a guess


def test_enrichment_is_frozen_on_first_attempt_so_retries_keep_the_payload(monkeypatch):
    from bastion import blue_agent
    raise_case_with_actions(monkeypatch)
    requests = []

    def api(request):
        requests.append(request)
        return httpx.Response(500 if len(requests) == 1 else 200, json={"id": "m1"})
    assert deliver_through_worker(api)["status"] == "pending"
    with store.connection() as db:
        stored = json.loads(db.execute("SELECT data FROM outbox").fetchone()["data"])
        db.execute("UPDATE outbox SET available=0")
    assert stored["_mail"]["enriched"] is True and "_mail_key" not in stored
    blue_agent.record_action("blacklist_ip", {"ip": "192.0.2.1", "reason": "later"}, "banned")  # moves the audit head
    assert deliver_through_worker(api)["status"] == "accepted"
    assert requests[0].content == requests[1].content
    assert requests[0].headers["Idempotency-Key"] == requests[1].headers["Idempotency-Key"]
    assert "Banned source" not in json.loads(requests[1].content)["text"]


def test_enrichment_skips_rows_already_offered_to_the_provider(monkeypatch):
    raise_case_with_actions(monkeypatch)
    with store.connection(write=True) as db:
        db.execute("UPDATE outbox SET attempts=1")  # queued and attempted before this worker version ran
    requests = []
    assert deliver_through_worker(lambda r: requests.append(r) or httpx.Response(200, json={"id": "m1"}))["status"] == "accepted"
    text = json.loads(requests[0].content)["text"]
    assert "WHAT IT DID" not in text and "Evidence: GET /lookup" in text


def test_enrichment_failure_falls_back_to_raise_time_message(monkeypatch, capsys):
    raise_case_with_actions(monkeypatch)
    def broken(_incident):
        raise RuntimeError("db secret detail")
    monkeypatch.setattr(mail_worker, "report_context", broken)
    requests = []
    assert deliver_through_worker(lambda r: requests.append(r) or httpx.Response(200, json={"id": "m1"}))["status"] == "accepted"
    assert "Evidence: GET /lookup" in json.loads(requests[0].content)["text"]
    out = capsys.readouterr().out
    assert "report enrichment failed" in out and "db secret detail" not in out


def test_trend_line_compares_last_30_days_with_the_previous_30(monkeypatch):
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    stamp = lambda days: (now - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")  # noqa: E731
    for days in (1, 5, 40, 45, 50, 55, 100):
        store.append_jsonl(store.INCIDENTS_FILE, incident(ts=stamp(days), case_id=f"c{days}"))
    context = mail.report_context(incident(ts=now.strftime("%Y-%m-%dT%H:%M:%SZ"), case_id="c1"))
    assert context["trend"] == {"days": 30, "recent": 2, "previous": 4}
    assert "2 incident(s) in the last 30 days versus 4 in the 30 days before (down 50%)." in mail.prepare_message(incident(), context)["text"]


def test_prepare_message_without_context_is_the_raise_time_alert():
    message = mail.prepare_message(incident())
    assert "enriched" not in message and "WHAT IT DID" not in message["text"]
    assert "Evidence: <script>untrusted</script>" in message["text"]
    assert set(message) == {"provider", "from", "to", "subject", "text", "html"}
