"""Operator mutation endpoints: unban, undivert, policy toggle, retry, test email, webhook."""
import asyncio
import hashlib
import hmac
import base64
import json
import time

import httpx
import pytest

from bastion import store
from bastion.proxy import create_app
from bastion.settings import Settings


@pytest.fixture
def client():
    async def upstream(request):
        return httpx.Response(200, text="OK")
    app = create_app(Settings(management_token="x" * 32), upstream_transport=httpx.MockTransport(upstream))

    async def run(scenario):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://proxy",
                                     headers={"Authorization": "Bearer " + "x" * 32}) as c:
            await scenario(c)
    return run


def test_unban_removes_ban(client):
    store.save_state({"denylist": [{"ip": "10.0.0.1", "expires": None}], "honeypot": []})

    async def scenario(c):
        r = await c.post("/__api/v1/defenses/unban", json={"ip": "10.0.0.1", "reason": "false positive"})
        assert r.status_code == 200
        assert r.json()["removed"] == 1
        assert not any(d["ip"] == "10.0.0.1" for d in store.load_state()["denylist"])
    asyncio.run(client(scenario))


def test_unban_bad_ip_rejected(client):
    async def scenario(c):
        r = await c.post("/__api/v1/defenses/unban", json={"ip": "not-an-ip", "reason": "x"})
        assert r.status_code == 422
    asyncio.run(client(scenario))


def test_undivert_releases_honeypot(client):
    store.save_state({"denylist": [], "honeypot": [{"ip": "10.0.0.2", "reason": "test", "ts": store.now()}]})

    async def scenario(c):
        r = await c.post("/__api/v1/defenses/undivert", json={"ip": "10.0.0.2"})
        assert r.status_code == 200
        assert r.json()["released"] == 1
        assert not any(d["ip"] == "10.0.0.2" for d in store.load_state().get("honeypot", []))
    asyncio.run(client(scenario))


def test_undivert_missing_ip_is_safe(client):
    async def scenario(c):
        r = await c.post("/__api/v1/defenses/undivert", json={"ip": "10.0.0.9"})
        assert r.status_code == 200
        assert r.json()["released"] == 0
    asyncio.run(client(scenario))


def test_policy_toggle_allow_destructive(client):
    async def scenario(c):
        r = await c.post("/__api/v1/defenses/policy", json={"allow_destructive": True})
        assert r.status_code == 200
        assert store.get_policy("allow_destructive") is True
        r = await c.post("/__api/v1/defenses/policy", json={"allow_destructive": False})
        assert r.status_code == 200
        assert store.get_policy("allow_destructive") is False
    asyncio.run(client(scenario))


def test_policy_toggle_is_audited(client):
    async def scenario(c):
        await c.post("/__api/v1/defenses/policy", json={"allow_destructive": True})
        actions = store.read_jsonl(store.ACTIONS_FILE)
        assert any(a.get("tool") == "operator_policy" for a in actions)
    asyncio.run(client(scenario))


def test_retry_notification_marks_pending(client):
    store.queue_mail("dead-key", {"ts": store.now(), "severity": "high"})
    with store.connection(write=True) as db:
        db.execute("UPDATE outbox SET status='dead'")
    with store.connection() as db:
        row = db.execute("SELECT id FROM outbox").fetchone()
    nid = row["id"]

    async def scenario(c):
        r = await c.post("/__api/v1/notifications/retry", json={"id": nid})
        assert r.status_code == 200
        with store.connection() as db:
            status = db.execute("SELECT status FROM outbox WHERE id=?", (nid,)).fetchone()["status"]
        assert status == "pending"
    asyncio.run(client(scenario))


def test_retry_nonexistent_notification(client):
    async def scenario(c):
        r = await c.post("/__api/v1/notifications/retry", json={"id": 999999})
        assert r.status_code == 404
    asyncio.run(client(scenario))


def test_retry_delivered_notification_rejected(client):
    store.queue_mail("delivered-key", {"ts": store.now(), "severity": "high"})
    with store.connection(write=True) as db:
        db.execute("UPDATE outbox SET status='accepted'")
    with store.connection() as db:
        nid = db.execute("SELECT id FROM outbox").fetchone()["id"]

    async def scenario(c):
        r = await c.post("/__api/v1/notifications/retry", json={"id": nid})
        assert r.status_code == 409
    asyncio.run(client(scenario))


def test_test_notification_sends_synthetic_email(monkeypatch, client):
    sent = []
    from bastion import store as _store

    def fake_send(item):
        sent.append(item)
        return {"provider": "resend", "provider_id": "test-id", "status": "accepted"}

    original_deliver = _store.deliver_mail
    monkeypatch.setattr(_store, "deliver_mail", lambda fn, key=None: original_deliver(fake_send, key))

    async def scenario(c):
        r = await c.post("/__api/v1/notifications/test")
        assert r.status_code == 200
        assert r.json()["status"] == "accepted"
        assert len(sent) == 1
        assert sent[0]["attack_type"] == "notification_test"
    asyncio.run(client(scenario))


def test_test_notification_does_not_drain_real_alerts(monkeypatch, client):
    store.queue_mail("real-alert", {"ts": store.now(), "severity": "critical", "attack_type": "sql_injection"})
    drained = []
    from bastion import store as _store
    original_deliver = _store.deliver_mail
    monkeypatch.setattr(_store, "deliver_mail", lambda fn, key=None: (drained.append(key) or original_deliver(lambda item: {"provider": "resend", "provider_id": "x", "status": "accepted"}, key)))

    async def scenario(c):
        await c.post("/__api/v1/notifications/test")
        with store.connection() as db:
            real_status = db.execute("SELECT status FROM outbox WHERE key='real-alert'").fetchone()
        assert real_status["status"] == "pending"
    asyncio.run(client(scenario))


def test_webhook_no_secret_returns_501(client):
    async def scenario(c):
        r = await c.post("/__api/v1/__webhooks/resend", content=b"{}", headers={"content-type": "application/json"})
        assert r.status_code == 501
    asyncio.run(client(scenario))


def test_webhook_invalid_signature_rejected(client):
    store.set_policy("resend_webhook_secret", "webhook-secret-value")

    async def scenario(c):
        r = await c.post("/__api/v1/__webhooks/resend", content=b"{}",
                         headers={"content-type": "application/json", "svix-id": "x",
                                  "svix-timestamp": "123", "svix-signature": "v1,invalidsig"})
        assert r.status_code == 401
    asyncio.run(client(scenario))


def test_webhook_valid_signature_accepted(client):
    secret = "webhook-secret-value"
    store.set_policy("resend_webhook_secret", secret)
    body = json.dumps({"type": "email.delivered", "data": {"email_id": "provider-test-id"}}).encode()
    store.queue_mail("webhook-test", {"ts": store.now(), "severity": "high"})
    with store.connection(write=True) as db:
        db.execute("UPDATE outbox SET status='accepted'")
        db.execute("INSERT OR REPLACE INTO mail_receipts VALUES(1,'resend','provider-test-id','accepted',NULL,?)", (store.now(),))
    svix_id = "svix-msg-123"
    svix_ts = str(int(time.time()))
    signed = f"{svix_id}.{svix_ts}.{body.decode()}".encode()
    sig = "v1," + base64.b64encode(hmac.new(secret.encode(), signed, hashlib.sha256).digest()).decode()

    async def scenario(c):
        r = await c.post("/__api/v1/__webhooks/resend", content=body,
                         headers={"content-type": "application/json", "svix-id": svix_id,
                                  "svix-timestamp": svix_ts, "svix-signature": sig})
        assert r.status_code == 200
        assert r.json()["event_type"] == "email.delivered"
        with store.connection() as db:
            status = db.execute("SELECT status FROM mail_receipts WHERE provider_id='provider-test-id'").fetchone()
        assert status["status"] == "delivered"
    asyncio.run(client(scenario))


def test_duplicate_alert_suppressed():
    from bastion.blue_agent import do_raise_alert, _recent_incident_exists, _CONTEXT
    _CONTEXT.case_id = "test-case"
    r1 = do_raise_alert("high", "sql_injection", "10.0.0.1", "evidence", "first alert")
    assert "Incident recorded" in r1
    r2 = do_raise_alert("high", "sql_injection", "10.0.0.1", "more evidence", "second alert")
    assert "already recorded" in r2
    incidents = store.read_jsonl(store.INCIDENTS_FILE)
    assert sum(1 for i in incidents if i.get("source_ip") == "10.0.0.1") == 1


def test_different_attack_type_not_suppressed():
    from bastion.blue_agent import do_raise_alert, _CONTEXT
    _CONTEXT.case_id = "test-case-2"
    do_raise_alert("high", "sql_injection", "10.0.0.2", "evidence", "sqli alert")
    r = do_raise_alert("high", "command_injection", "10.0.0.2", "evidence", "cmdi alert")
    assert "Incident recorded" in r


def test_different_source_ip_not_suppressed():
    from bastion.blue_agent import do_raise_alert, _CONTEXT
    _CONTEXT.case_id = "test-case-3"
    do_raise_alert("high", "sql_injection", "10.0.0.3", "evidence", "first ip")
    r = do_raise_alert("high", "sql_injection", "10.0.0.4", "evidence", "second ip")
    assert "Incident recorded" in r


def test_snapshot_includes_allow_destructive(client):
    store.set_policy("allow_destructive", True)

    async def scenario(c):
        r = await c.get("/__api/v1/overview")
        assert r.status_code == 200
        assert r.json()["allow_destructive"] is True
    asyncio.run(client(scenario))
