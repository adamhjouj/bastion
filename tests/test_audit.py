"""Tamper-evident action log (docs/CONTRACTS.md §3.2): chaining in store, verify/head in audit."""
import hashlib
import json
import threading
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from bastion import audit, store


def record(i, **extra):
    return store.append_jsonl(store.ACTIONS_FILE, {"ts": store.now(), "kind": "action", "tool": "blacklist_ip",
                                                    "input": {"ip": f"203.0.113.{i}"}, "result": "banned",
                                                    "outcome": "ok", "case_id": str(i), **extra})


def rows():
    with store.connection() as db:
        return [(r["id"], json.loads(r["data"])) for r in
                db.execute("SELECT id,data FROM records WHERE kind='actions' ORDER BY id")]


def insert_legacy(data):
    with store.connection(write=True) as db:
        db.execute("INSERT INTO records(kind,ts,data,status) VALUES('actions',?,?,'done')",
                   (store.now(), json.dumps(data)))


def test_chain_links_sequential_inserts_per_contract():
    for i in range(3):
        record(i)
    chain = rows()
    prev = "0" * 64
    for _, data in chain:
        body = {k: v for k, v in data.items() if k != "audit"}
        canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        assert data["audit"]["prev"] == prev
        assert data["audit"]["hash"] == hashlib.sha256((prev + "\n" + canonical).encode()).hexdigest()
        prev = data["audit"]["hash"]
    result = audit.verify()
    assert result["intact"] is True and result["broken_at"] is None
    assert result["length"] == 3 and result["unchained"] == 0
    assert result["head"] == prev == audit.head()["head"]
    assert audit.head()["length"] == 3
    assert result["checked_at"].endswith("Z")


def test_empty_log_is_intact_with_null_head():
    assert audit.head() == {"length": 0, "head": None}
    result = audit.verify()
    assert result["intact"] is True and result["length"] == 0 and result["head"] is None


def test_caller_supplied_audit_is_discarded_and_recomputed():
    record(0, audit={"prev": "f" * 64, "hash": "f" * 64})
    (_, data), = rows()
    assert data["audit"]["prev"] == "0" * 64
    assert audit.verify()["intact"] is True


def test_modified_data_breaks_chain_at_row():
    ids = [record(i) for i in range(4)]
    with store.connection(write=True) as db:
        data = json.loads(db.execute("SELECT data FROM records WHERE id=?", (ids[1],)).fetchone()["data"])
        data["input"]["ip"] = "198.51.100.1"
        db.execute("UPDATE records SET data=? WHERE id=?", (json.dumps(data), ids[1]))
    result = audit.verify()
    assert result["intact"] is False and result["broken_at"] == ids[1]
    assert result["length"] == 1 and result["head"] == rows()[0][1]["audit"]["hash"]


def test_deleted_middle_row_breaks_chain():
    ids = [record(i) for i in range(4)]
    with store.connection(write=True) as db:
        db.execute("DELETE FROM records WHERE id=?", (ids[2],))
    result = audit.verify()
    assert result["intact"] is False and result["broken_at"] == ids[3]
    assert result["length"] == 2


def test_reordered_rows_break_chain():
    ids = [record(i) for i in range(3)]
    with store.connection(write=True) as db:
        db.execute("UPDATE records SET id=? WHERE id=?", (ids[2] + 100, ids[1]))
    result = audit.verify()
    assert result["intact"] is False and result["broken_at"] == ids[2]


def test_inserted_row_breaks_chain():
    record(0)
    record(1)
    insert_legacy({"ts": store.now(), "kind": "action", "tool": "unban_ip", "outcome": "ok"})
    unchained = audit.verify()
    assert unchained["intact"] is False and unchained["broken_at"] == rows()[-1][0]
    with store.connection(write=True) as db:
        db.execute("DELETE FROM records WHERE id=?", (rows()[-1][0],))
    prev = rows()[-1][1]["audit"]["hash"]
    forged = {"ts": store.now(), "kind": "action", "tool": "unban_ip", "outcome": "ok"}
    insert_legacy({**forged, "audit": {"prev": prev, "hash": store.action_hash("1" * 64, forged)}})
    forged_chain = audit.verify()
    assert forged_chain["intact"] is False and forged_chain["broken_at"] == rows()[-1][0]


def test_legacy_unchained_prefix_is_counted_not_failed():
    insert_legacy({"ts": store.now(), "kind": "action", "tool": "legacy_a", "outcome": "ok"})
    insert_legacy({"ts": store.now(), "kind": "triage", "case_id": "1", "escalated": False})
    ids = [record(i) for i in range(2)]
    result = audit.verify()
    assert result["intact"] is True and result["unchained"] == 2 and result["length"] == 2
    assert result["head"] == rows()[-1][1]["audit"]["hash"]
    assert rows()[2][1]["audit"]["prev"] == "0" * 64
    assert audit.head() == {"length": 2, "head": result["head"]}
    assert ids[0] == rows()[2][0]


def test_legacy_jsonl_import_is_chained(tmp_path):
    store.ACTIONS_FILE.write_text("\n".join(json.dumps({"ts": store.now(), "kind": "action", "tool": "t",
                                                        "outcome": "ok"}) for _ in range(3)) + "\n")
    with store.connection(write=True) as db:
        db.execute("DELETE FROM meta WHERE key='migration_v1'")
    store.initialize()
    result = audit.verify()
    assert result["intact"] is True and result["length"] == 3 and result["unchained"] == 0


def test_error_action_from_finish_event_is_chained():
    record(0)
    eid = store.enqueue_event({"ip": "192.0.2.1", "path": "/x"})
    store.claim_events()
    store.finish_event(eid, error="boom")
    last = rows()[-1][1]
    assert last["kind"] == "error" and last["case_id"] == str(eid)
    result = audit.verify()
    assert result["intact"] is True and result["length"] == 2


def test_actions_survive_retention():
    rid = record(0)
    with store.connection(write=True) as db:
        db.execute("UPDATE records SET ts=? WHERE id=?", (store.now_plus(-40 * 86400), rid))
    store.retain(days=30)
    result = audit.verify()
    assert result["intact"] is True and result["length"] == 1


def test_concurrent_inserts_do_not_fork_chain():
    errors = []
    start = threading.Barrier(8)

    def writer(n):
        try:
            start.wait()
            for i in range(25):
                record(n * 100 + i)
        except Exception as exc:  # noqa: BLE001 — surfaced via assert below
            errors.append(exc)

    threads = [threading.Thread(target=writer, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    result = audit.verify()
    assert result["intact"] is True and result["length"] == 200
    hashes = [data["audit"]["hash"] for _, data in rows()]
    assert len(set(hashes)) == 200


def test_verify_is_fast_for_ten_thousand_rows():
    with store.connection(write=True) as db:
        for i in range(10_000):
            store._insert_action(db, {"ts": store.now(), "kind": "action", "tool": "t", "input": {"i": i},
                                      "result": "ok" * 20, "outcome": "ok", "case_id": str(i)})
    started = time.perf_counter()
    result = audit.verify()
    elapsed = time.perf_counter() - started
    assert result["intact"] is True and result["length"] == 10_000
    assert elapsed < 1.0, elapsed


def test_endpoints_return_contract_shapes():
    app = FastAPI()
    app.include_router(audit.router)
    client = TestClient(app)
    assert client.get("/__api/v1/audit/head").json() == {"length": 0, "head": None}
    ids = [record(i) for i in range(2)]
    head = client.get("/__api/v1/audit/head").json()
    assert head["length"] == 2 and len(head["head"]) == 64
    verified = client.get("/__api/v1/audit/verify").json()
    assert set(verified) == {"intact", "length", "head", "unchained", "broken_at", "checked_at"}
    assert verified["intact"] is True and verified["length"] == 2 and verified["head"] == head["head"]
    assert verified["unchained"] == 0 and verified["broken_at"] is None
    with store.connection(write=True) as db:
        db.execute("UPDATE records SET data=json_set(data,'$.result','tampered') WHERE id=?", (ids[0],))
    broken = client.get("/__api/v1/audit/verify").json()
    assert broken["intact"] is False and broken["broken_at"] == ids[0] and broken["head"] is None
