"""Resend transport and real SQLite outbox tests. No live emails are sent."""
import json

import httpx
import pytest

import mail_worker
import notifications as mail
import store


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


def test_missing_key_never_uses_another_transport(monkeypatch):
    monkeypatch.delenv("RESEND_API_KEY")
    with pytest.raises(mail.MailError, match="RESEND_API_KEY") as error:
        mail.send_email(incident())
    assert not error.value.retryable


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
    import blue_agent
    monkeypatch.setenv("ALERT_TO", "")
    with pytest.raises(mail.MailError):
        blue_agent.do_raise_alert("high", "test", "192.0.2.1", "evidence", "summary")
    assert store.read_jsonl(store.INCIDENTS_FILE) == []
