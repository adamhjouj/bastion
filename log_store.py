"""Bounded, cursor-addressable container log history. No Docker access here."""
import os
import re
from datetime import datetime, timezone

import store

SOURCES = ("blue", "proxy", "dvwa", "honeypot", "actuator", "mail-worker", "red")
# Redaction patterns are for display safety, not request/attack classification.
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_CREDENTIAL = re.compile(r"(?i)(\b(?:password|passwd|api[_-]?key|access[_-]?token|actuator[_-]?token|management[_-]?token|resend[_-]?api[_-]?key)\b[\"']?\s*[:=]\s*[\"']?)([^\s\"'&,;<>]+)")
_BEARER = re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/-]+")
_KEY = re.compile(r"\b(?:re_[A-Za-z0-9_-]{16,}|sk-[A-Za-z0-9_-]{16,})\b")


def safe_line(text):
    text = _ANSI.sub("", text)
    text = "".join(c for c in text if c == "\t" or ord(c) >= 32 and ord(c) != 127)
    for name, value in os.environ.items():
        if any(word in name.upper() for word in ("TOKEN", "PASSWORD", "SECRET", "API_KEY")) and len(value) >= 6:
            text = text.replace(value, "[REDACTED]")
    text = _CREDENTIAL.sub(r"\1[REDACTED]", text)
    text = _BEARER.sub(r"\1[REDACTED]", text)
    return _KEY.sub("[REDACTED]", text)


def set_source(source, status, message, container_id=None):
    if source not in SOURCES:
        raise ValueError("unknown log source")
    with store.connection(write=True) as db:
        db.execute("INSERT INTO log_sources VALUES(?,?,?,?,?) ON CONFLICT(source) DO UPDATE SET "
                   "container_id=excluded.container_id,status=excluded.status,message=excluded.message,updated=excluded.updated",
                   (source, container_id, status, message, store.now()))


def sources():
    with store.connection() as db:
        rows = {r["source"]: dict(r) for r in db.execute("SELECT * FROM log_sources")}
    result = []
    for source in SOURCES:
        item = rows.get(source, {"source": source, "status": "unavailable", "message": "Collector has not reported this source", "updated": None, "container_id": None})
        if item["updated"]:
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(item["updated"].replace("Z", "+00:00"))).total_seconds()
            if age > 60:  # 10s heartbeat; allow 6x headroom for slow stores and GC pauses
                item.update(status="stale", message="Log collector heartbeat is stale")
        # No arbitrary container selector is exposed to the browser.
        result.append(item)
    return result


def append(source, entries, retention=1000):
    if source not in SOURCES or not 1 <= retention <= 10000 or len(entries) > 200:
        raise ValueError("invalid log append")
    with store.connection(write=True) as db:
        for entry in entries:
            text = safe_line(entry["text"])
            db.execute("INSERT OR IGNORE INTO service_logs(source,container_id,ts,stream,text,digest,occurrence,truncated) "
                       "VALUES(?,?,?,?,?,?,?,?)", (source, entry["container_id"], entry["ts"], entry["stream"],
                                                 text[:4096], entry["digest"], entry["occurrence"],
                                                 bool(entry.get("truncated") or len(text) > 4096)))
        db.execute("DELETE FROM service_logs WHERE source=? AND id NOT IN "
                   "(SELECT id FROM service_logs WHERE source=? ORDER BY id DESC LIMIT ?)", (source, source, retention))


def watermark(source, container_id):
    with store.connection() as db:
        row = db.execute("SELECT MAX(ts) FROM service_logs WHERE source=? AND container_id=?", (source, container_id)).fetchone()
        return row[0]


def page(source, after=0, limit=200):
    if source not in SOURCES or after < 0 or not 1 <= limit <= 500:
        raise ValueError("invalid log cursor")
    with store.connection() as db:
        bounds = db.execute("SELECT MIN(id),MAX(id) FROM service_logs WHERE source=?", (source,)).fetchone()
        oldest, latest = bounds[0] or 0, bounds[1] or 0
        reset = after > latest or bool(after and oldest and after < oldest)
        if not after or reset:
            rows = list(reversed(db.execute("SELECT id,ts,stream,text,truncated FROM service_logs WHERE source=? "
                                            "ORDER BY id DESC LIMIT ?", (source, limit)).fetchall()))
        else:
            rows = db.execute("SELECT id,ts,stream,text,truncated FROM service_logs WHERE source=? AND id>? "
                              "ORDER BY id LIMIT ?", (source, after, limit)).fetchall()
    return {"source": source, "entries": [dict(r) for r in rows],
            "next_cursor": rows[-1]["id"] if rows else (latest if reset else after),
            "reset": reset, "oldest_id": oldest,
            "status": next(item for item in sources() if item["source"] == source)}
