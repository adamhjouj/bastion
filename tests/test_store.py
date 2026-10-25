"""SQLite store: state, events, idempotency, ban lifecycle, mail outbox."""
import time

import pytest

from bastion import store


def test_state_roundtrip():
    store.save_state({"denylist": [{"ip": "1.2.3.4", "expires": None}], "honeypot": []})
    assert store.load_state()["denylist"][0]["ip"] == "1.2.3.4"


def test_state_removes_legacy_rules():
    store.save_state({"denylist": [], "rules": [{"pattern": ".*"}]})
    assert "rules" not in store.load_state()


def test_active_ban_permanent():
    assert store.active_ban({"ip": "1.2.3.4", "expires": None})


def test_active_ban_future_ttl():
    assert store.active_ban({"ip": "1.2.3.4", "expires": store.now_plus(60)})


def test_active_ban_expired():
    assert not store.active_ban({"ip": "1.2.3.4", "expires": store.now_plus(-1)})


def test_events_queue_and_claim():
    eid = store.enqueue_event({"ip": "192.0.2.1", "path": "/x"})
    events = store.claim_events(limit=10)
    assert len(events) == 1 and events[0]["id"] == eid


def test_finish_event_done():
    eid = store.enqueue_event({"ip": "192.0.2.1", "path": "/x"})
    store.claim_events()
    store.finish_event(eid)
    assert store.claim_events() == []


def test_finish_event_retry():
    eid = store.enqueue_event({"ip": "192.0.2.1", "path": "/x"})
    store.claim_events()
    store.finish_event(eid, error="transient")
    # Retry fires immediately after delay passes; force available to now.
    with store.connection(write=True) as db:
        db.execute("UPDATE records SET available=0 WHERE id=?", (eid,))
    events = store.claim_events()
    assert any(e["id"] == eid for e in events)


def test_finish_event_dead_letter():
    eid = store.enqueue_event({"ip": "192.0.2.1", "path": "/x"})
    for _ in range(3):
        store.claim_events()
        store.finish_event(eid, error="persistent", max_attempts=3)
    assert store.claim_events() == []


def test_execute_once_idempotent():
    calls = []
    fn = lambda: calls.append(1) or "ok"
    r1 = store.execute_once("k1", fn)
    r2 = store.execute_once("k1", fn)
    assert r1 == r2 == "ok" and len(calls) == 1


def test_execute_once_unknown_after_crash():
    import sqlite3
    with store.connection(write=True) as db:
        db.execute("INSERT INTO executions VALUES('k2','started',NULL,?)", (store.now(),))
    result = store.execute_once("k2", lambda: "late")
    assert "UNKNOWN" in result


def test_budget_enforcement():
    assert store.spend("test", 2)
    assert store.spend("test", 2)
    assert not store.spend("test", 2)


def test_queue_overflow():
    with pytest.raises(OverflowError):
        for _ in range(3):
            store.reserve_event({"ip": "192.0.2.1"}, limit=2)


def test_mail_outbox_delivered():
    delivered = []
    store.queue_mail("m1", {"severity": "high"})
    store.deliver_mail(lambda inc: delivered.append(inc))
    assert len(delivered) == 1


def test_mail_outbox_idempotent():
    store.queue_mail("m1", {"severity": "high"})
    store.queue_mail("m1", {"severity": "high"})
    delivered = []
    store.deliver_mail(lambda inc: delivered.append(inc))
    store.deliver_mail(lambda inc: delivered.append(inc))
    assert len(delivered) == 1


def test_retain_removes_old_done():
    eid = store.enqueue_event({"ip": "192.0.2.1", "path": "/x"})
    store.claim_events()
    store.finish_event(eid)
    import sqlite3, time as t
    with store.connection(write=True) as db:
        db.execute("UPDATE records SET ts=? WHERE id=?",
                   (store.now_plus(-40 * 86400), eid))
    removed = store.retain(days=30)
    assert removed >= 1


def test_snapshot_keys():
    snap = store.snapshot()
    for key in ("events", "incidents", "denylist", "honeypot", "queue", "mail", "funnel", "health"):
        assert key in snap


def test_snapshot_excludes_expired_bans():
    store.save_state({"denylist": [
        {"ip": "1.1.1.1", "expires": store.now_plus(60)},
        {"ip": "2.2.2.2", "expires": store.now_plus(-60)},
    ], "honeypot": []})
    snap = store.snapshot()
    assert any(d["ip"] == "1.1.1.1" for d in snap["denylist"])
    assert not any(d["ip"] == "2.2.2.2" for d in snap["denylist"])
