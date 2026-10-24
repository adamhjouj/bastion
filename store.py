"""Transactional single-host SQLite WAL store, durable queue and audit/outbox.

The *_FILE constants remain as logical stream identifiers for tool compatibility.
JSONL/state files are imported once, backed up, and never written during operation.
"""
import contextlib
import json
import os
import shutil
import sqlite3
import threading
import time
from pathlib import Path

from privacy import redact

BASE = Path(__file__).resolve().parent
DATA = Path(os.getenv("BASTION_DATA_DIR", str(BASE / "data")))
STATE_FILE = DATA / "state.json"
EVENTS_FILE = DATA / "events.jsonl"
INCIDENTS_FILE = DATA / "incidents.jsonl"
ACTIONS_FILE = DATA / "actions.jsonl"
LOGS = DATA / "logs"
DVWA_LOG, PROXY_LOG, BLUE_LOG, RED_LOG = [LOGS / f"{n}.log" for n in ("dvwa", "proxy", "blue", "red")]
DEFAULT_STATE = {"denylist": [], "honeypot": [], "seen_ips": {}}
_local = threading.local()


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def now_plus(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + seconds))


def active_ban(entry, at=None):
    return not entry.get("expires") or entry["expires"] > (at or now())


def _open():
    DATA.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATA / "bastion.db", timeout=15)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=15000")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS records (
          id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT NOT NULL, ts TEXT NOT NULL,
          data TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'done', attempts INTEGER DEFAULT 0,
          lease REAL DEFAULT 0, available REAL DEFAULT 0, case_id TEXT);
        CREATE INDEX IF NOT EXISTS queue_idx ON records(kind,status,available,id);
        CREATE INDEX IF NOT EXISTS time_idx ON records(kind,ts,id);
        CREATE TABLE IF NOT EXISTS executions (
          key TEXT PRIMARY KEY, status TEXT NOT NULL, result TEXT, ts TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS outbox (
          id INTEGER PRIMARY KEY AUTOINCREMENT, key TEXT UNIQUE NOT NULL,
          data TEXT NOT NULL, attempts INTEGER DEFAULT 0, available REAL DEFAULT 0,
          status TEXT DEFAULT 'pending');
        CREATE TABLE IF NOT EXISTS mail_receipts (
          outbox_id INTEGER PRIMARY KEY, provider TEXT, provider_id TEXT, status TEXT,
          last_error TEXT, updated TEXT);
        CREATE TABLE IF NOT EXISTS budgets (name TEXT PRIMARY KEY, window INTEGER, used INTEGER);
        CREATE TABLE IF NOT EXISTS health (name TEXT PRIMARY KEY, ts TEXT, data TEXT);
    """)
    return db


@contextlib.contextmanager
def connection(write=False):
    current = getattr(_local, "db", None)
    if current is not None:
        yield current
        return
    db = _open()
    try:
        if write:
            db.execute("BEGIN IMMEDIATE")
        yield db
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


class StateLock:
    """Cross-process read-modify-write transaction, reused by existing named tools."""
    def __enter__(self):
        if getattr(_local, "db", None) is not None:
            raise RuntimeError("nested state transactions are not supported")
        self_context = connection(write=True)
        db = self_context.__enter__()
        _local.db, _local.context = db, self_context
        return self

    def __exit__(self, *exc):
        ctx = _local.context
        _local.db = None
        _local.context = None
        return ctx.__exit__(*exc)


state_lock = StateLock()


def initialize():
    """Idempotent legacy import under one writer transaction; originals retained."""
    with connection(write=True) as db:
        if db.execute("SELECT 1 FROM meta WHERE key='migration_v1'").fetchone():
            return
        legacy = [p for p in [STATE_FILE, EVENTS_FILE, INCIDENTS_FILE, ACTIONS_FILE] if p.exists()]
        if legacy:
            backup = DATA / "legacy_backup"
            backup.mkdir(exist_ok=True)
            for p in legacy:
                if not (backup / p.name).exists():
                    shutil.copy2(p, backup / p.name)
            os.chmod(backup, 0o700)
        state = json.loads(json.dumps(DEFAULT_STATE))
        if STATE_FILE.exists():
            state.update(json.loads(STATE_FILE.read_text()))
        state.pop("rules", None)
        db.execute("INSERT OR IGNORE INTO state VALUES(1, ?)", (json.dumps(state),))
        for path in [EVENTS_FILE, INCIDENTS_FILE, ACTIONS_FILE]:
            if path.exists():
                for line in path.read_text().splitlines():
                    try:
                        item = redact(json.loads(line))
                    except ValueError:
                        continue
                    # Legacy request payloads were not structured/redacted at capture.
                    if path == EVENTS_FILE:
                        item.update(query="[legacy payload omitted]", body="[legacy payload omitted]")
                    kind = path.stem
                    db.execute("INSERT INTO records(kind,ts,data,status) VALUES(?,?,?,?)",
                               (kind, item.get("ts", now()), json.dumps(item),
                                "pending" if kind == "events" else "done"))
        db.execute("INSERT INTO meta VALUES('migration_v1', ?)", (now(),))


def load_state():
    with connection() as db:
        row = db.execute("SELECT data FROM state WHERE id=1").fetchone()
        return json.loads(row[0]) if row else json.loads(json.dumps(DEFAULT_STATE))


def save_state(state):
    state = dict(state)
    state.pop("rules", None)
    with connection(write=True) as db:
        db.execute("INSERT INTO state VALUES(1,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data",
                   (json.dumps(state),))


def append_jsonl(path, obj):
    """Compatibility name; append a structured record transactionally, not a file."""
    item = redact(obj)
    kind = Path(path).stem
    with connection(write=True) as db:
        cursor = db.execute("INSERT INTO records(kind,ts,data,status,case_id) VALUES(?,?,?,?,?)",
                            (kind, item.get("ts", now()), json.dumps(item),
                             "pending" if kind == "events" else "done", item.get("case_id")))
        return cursor.lastrowid


def reserve_event(item, limit=10000):
    with connection(write=True) as db:
        count = db.execute("SELECT COUNT(*) FROM records WHERE kind='events' AND status IN ('pending','processing','receiving')").fetchone()[0]
        if count >= limit:
            raise OverflowError("investigation queue is full")
        return db.execute("INSERT INTO records(kind,ts,data,status,lease) VALUES('events',?,?,'receiving',?)",
                          (item.get("ts", now()), json.dumps(redact(item)), time.time() + 120)).lastrowid


def finalize_event(event_id, item, observe=False):
    with connection(write=True) as db:
        db.execute("UPDATE records SET data=?,status=?,lease=0 WHERE id=?",
                   (json.dumps(redact(item)), "done" if observe else "pending", event_id))


def enqueue_event(item, limit=10000):
    event_id = reserve_event(item, limit)
    finalize_event(event_id, item)
    return event_id


def read_jsonl(path, limit=None):
    with connection() as db:
        sql = "SELECT id,data FROM records WHERE kind=? ORDER BY id DESC LIMIT ?"
        rows = db.execute(sql, (Path(path).stem, limit or 1000)).fetchall()
        return [dict(json.loads(r["data"]), id=r["id"]) for r in reversed(rows)]


def count_lines(path):
    with connection() as db:
        return db.execute("SELECT COUNT(*) FROM records WHERE kind=?", (Path(path).stem,)).fetchone()[0]


def tail_lines(path, n=120):
    return []  # stdout lives in the container log driver, not pretend empty log files


def claim_events(limit=32, lease_seconds=180):
    with connection(write=True) as db:
        db.execute("UPDATE records SET status='pending' WHERE kind='events' AND status='processing' AND lease<?", (time.time(),))
        db.execute("UPDATE records SET status='dead' WHERE kind='events' AND status='receiving' AND lease<?", (time.time(),))
        rows = db.execute("SELECT id,data,attempts FROM records WHERE kind='events' AND status='pending' AND available<=? ORDER BY id LIMIT ?",
                          (time.time(), limit)).fetchall()
        for row in rows:
            db.execute("UPDATE records SET status='processing', attempts=attempts+1, lease=? WHERE id=?",
                       (time.time() + lease_seconds, row["id"]))
        return [dict(json.loads(r["data"]), id=r["id"], attempts=r["attempts"] + 1) for r in rows]


def finish_event(event_id, error=None, max_attempts=3):
    with connection(write=True) as db:
        row = db.execute("SELECT attempts FROM records WHERE id=?", (event_id,)).fetchone()
        if not error:
            db.execute("UPDATE records SET status='done',lease=0,available=0 WHERE id=?", (event_id,))
            return
        attempts = row[0] if row else 1
        status = "dead" if attempts >= max_attempts else "pending"
        delay = min(2 ** attempts, 300)
        db.execute("UPDATE records SET status=?, available=?, lease=0 WHERE id=?",
                   (status, time.time() + delay, event_id))
        if error:
            db.execute("INSERT INTO records(kind,ts,data) VALUES('actions',?,?)",
                       (now(), json.dumps({"kind": "error", "case_id": str(event_id), "error": str(error)[:300], "status": status})))


def execute_once(key, fn):
    """At-most-once attempt. Crashed attempts are UNKNOWN, never blindly replayed."""
    with connection(write=True) as db:
        row = db.execute("SELECT status,result FROM executions WHERE key=?", (key,)).fetchone()
        if row:
            return row["result"] or "UNKNOWN: earlier action may have run; inspect before retrying"
        db.execute("INSERT INTO executions VALUES(?,'started',NULL,?)", (key, now()))
    try:
        result = str(fn())
    except Exception as exc:
        result = f"ERROR: {type(exc).__name__}: action failed"
    with connection(write=True) as db:
        db.execute("UPDATE executions SET status='finished',result=? WHERE key=?", (result, key))
    return result


def spend(name, limit, period=60):
    window = int(time.time() // period)
    with connection(write=True) as db:
        row = db.execute("SELECT window,used FROM budgets WHERE name=?", (name,)).fetchone()
        used = row["used"] if row and row["window"] == window else 0
        if used >= limit:
            return False
        db.execute("INSERT INTO budgets VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET window=excluded.window,used=excluded.used",
                   (name, window, used + 1))
    return True


def set_health(name, data):
    with connection(write=True) as db:
        db.execute("INSERT INTO health VALUES(?,?,?) ON CONFLICT(name) DO UPDATE SET ts=excluded.ts,data=excluded.data",
                   (name, now(), json.dumps(redact(data))))


def queue_mail(key, incident):
    from notifications import prepare_message
    item = dict(redact(incident))
    item["_mail"] = prepare_message(item)
    with connection(write=True) as db:
        db.execute("INSERT OR IGNORE INTO outbox(key,data) VALUES(?,?)", (key, json.dumps(item)))


def deliver_mail(send, key=None):
    """Lease one message. Resend retries reuse the persisted idempotency key.

    Optional key restricts a test run to its own message (never drains real alerts).
    Accepted means the relay/API accepted the message, NOT inbox delivery.
    """
    from notifications import MailError
    with connection(write=True) as db:
        row = db.execute("SELECT * FROM outbox WHERE status='pending' AND available<=? "
                         "AND (? IS NULL OR key=?) ORDER BY id LIMIT 1", (time.time(), key, key)).fetchone()
        if not row:
            return None
        db.execute("UPDATE outbox SET available=?,attempts=attempts+1 WHERE id=?", (time.time() + 60, row["id"]))
    try:
        item = json.loads(row["data"])
        item["_mail_key"] = row["key"]
        result = send(item) or {"status": "accepted", "provider": "resend"}
        result = {"status": "accepted", "provider": result.get("provider", "unknown"),
                  "provider_id": result.get("provider_id")}
    except Exception as exc:
        retryable = not isinstance(exc, MailError) or exc.retryable
        error = str(exc) if isinstance(exc, MailError) else "Unexpected mail transport failure"
        delay = getattr(exc, "retry_after", None) or min(60 * 2 ** row["attempts"], 3600)
        status = "dead" if not retryable or row["attempts"] >= 4 else "pending"
        result = {"status": status, "error": error, "provider": "unknown"}
        with connection(write=True) as db:
            db.execute("UPDATE outbox SET status=?,available=? WHERE id=?", (status, time.time() + delay, row["id"]))
            db.execute("INSERT OR REPLACE INTO mail_receipts VALUES(?,?,?,?,?,?)",
                       (row["id"], None, None, status, error, now()))
    else:
        with connection(write=True) as db:
            db.execute("UPDATE outbox SET status='accepted' WHERE id=?", (row["id"],))
            db.execute("INSERT OR REPLACE INTO mail_receipts VALUES(?,?,?,?,?,?)",
                       (row["id"], result["provider"], result["provider_id"], "accepted", None, now()))
    set_health("mail", {"available": result["status"] == "accepted", **result})
    return result


def snapshot():
    st = load_state()
    with connection() as db:
        counts = {r["kind"]: r["n"] for r in db.execute("SELECT kind,COUNT(*) n FROM records GROUP BY kind")}
        queue = {r["status"]: r["n"] for r in db.execute("SELECT status,COUNT(*) n FROM records WHERE kind='events' GROUP BY status")}
        mail = {r["status"]: r["n"] for r in db.execute("SELECT status,COUNT(*) n FROM outbox GROUP BY status")}
        health = {r["name"]: {"ts": r["ts"], **json.loads(r["data"])} for r in db.execute("SELECT * FROM health")}
        triage = {"evaluated": 0, "flagged": 0, "escalated": 0, "actions": 0, "succeeded": 0}
        for r in db.execute("SELECT data FROM records WHERE kind='actions'"):
            a = json.loads(r[0])
            if a.get("kind") == "triage":
                triage["evaluated"] += 1
                triage["flagged"] += bool((a.get("jev") or {}).get("malicious"))
                triage["escalated"] += bool(a.get("escalated"))
            elif a.get("kind") == "action":
                triage["actions"] += 1
                triage["succeeded"] += a.get("outcome") == "ok"
        blocked = db.execute("SELECT COUNT(*) FROM records WHERE kind='events' AND json_extract(data,'$.blocked')=1").fetchone()[0]
    return {"events": read_jsonl(EVENTS_FILE, 200)[::-1], "actions": read_jsonl(ACTIONS_FILE, 400)[::-1],
            "incidents": read_jsonl(INCIDENTS_FILE, 100)[::-1], "events_total": counts.get("events", 0),
            "incidents_total": counts.get("incidents", 0), "blocked_total": blocked,
            "denylist": [d for d in st.get("denylist", []) if active_ban(d)],
            "honeypot": st.get("honeypot", []), "enforced_security": st.get("enforced_security"),
            "queue": queue, "mail": mail, "health": health, "funnel": triage, "logs": {}}


def retain(days=30):
    """Delete terminal records only. Never discard unfinished work silently."""
    cutoff = now_plus(-days * 86400)
    with connection(write=True) as db:
        return db.execute("DELETE FROM records WHERE ts<? AND status IN ('done','dead')", (cutoff,)).rowcount
