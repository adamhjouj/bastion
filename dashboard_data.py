"""Dashboard queries. Aggregates describe retained data, not the visible page."""
import json
from datetime import datetime, timezone

import log_store
import store

KINDS = {"events", "actions", "incidents"}
CONTAINMENT = {"blacklist_ip", "bulk_blacklist_ip", "divert_to_honeypot", "kill_process", "kill_session",
               "isolate_egress", "quarantine_container", "patch_vuln", "rotate_secret", "virtual_patch"}


def record_page(kind, before=None, limit=100, case_id=None):
    if kind not in KINDS or not 1 <= limit <= 200:
        raise ValueError("invalid record query")
    with store.connection() as db:
        rows = db.execute("SELECT id,data,status FROM records WHERE kind=? AND (? IS NULL OR id<?) "
                          "AND (? IS NULL OR COALESCE(case_id,json_extract(data,'$.case_id'))=?) "
                          "ORDER BY id DESC LIMIT ?", (kind, before, before, case_id, case_id, limit + 1)).fetchall()
    more = len(rows) > limit
    items = [{**json.loads(r["data"]), "id": r["id"], "processing_status": r["status"]} for r in rows[:limit]]
    return {"items": items, "next_cursor": items[-1]["id"] if more and items else None}


def notifications(case_id=None, before=None, limit=100):
    with store.connection() as db:
        rows = db.execute("SELECT o.id,o.data,o.status,o.attempts,r.provider,r.provider_id,r.last_error,r.updated "
                          "FROM outbox o LEFT JOIN mail_receipts r ON r.outbox_id=o.id "
                          "WHERE (? IS NULL OR json_extract(o.data,'$.case_id')=?) AND (? IS NULL OR o.id<?) "
                          "ORDER BY o.id DESC LIMIT ?", (case_id, case_id, before, before, limit + 1)).fetchall()
    items = []
    for r in rows[:limit]:
        data = json.loads(r["data"])
        items.append({"id": r["id"], "case_id": data.get("case_id"), "queued_at": data.get("ts"),
                      "status": "accepted" if r["status"] == "delivered" else r["status"], "attempts": r["attempts"],
                      "provider": r["provider"], "provider_id": r["provider_id"],
                      "error": r["last_error"], "updated_at": r["updated"]})
    return {"items": items, "next_cursor": items[-1]["id"] if len(rows) > limit and items else None}


def incident_detail(incident_id):
    with store.connection() as db:
        row = db.execute("SELECT id,data FROM records WHERE kind='incidents' AND id=?", (incident_id,)).fetchone()
        if row is None:
            return None
        incident = {**json.loads(row["data"]), "id": row["id"]}
        case_id = incident.get("case_id")
        # Existing cases identify the contributing event IDs as a comma-separated list.
        ids = [int(p) for p in str(case_id).split(",") if p.isdigit()][:200]
        requests = []
        if ids:
            sql = "SELECT id,data,status FROM records WHERE kind='events' AND id IN (" + ",".join("?" for _ in ids) + ") ORDER BY id"
            requests = [{**json.loads(r["data"]), "id": r["id"], "processing_status": r["status"]} for r in db.execute(sql, ids)]
    return {"incident": incident, "requests": requests,
            "actions": record_page("actions", case_id=case_id)["items"] if case_id else [],
            "notifications": notifications(case_id=case_id)["items"] if case_id else []}


def _health(db):
    result = {}
    for row in db.execute("SELECT * FROM health"):
        age = max(0, (datetime.now(timezone.utc) - datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))).total_seconds())
        data = json.loads(row["data"])
        # Classifier/agent reports are event-driven, not heartbeats. Silence is unknown,
        # not a fabricated outage; only process heartbeats have a freshness threshold.
        stale = row["name"] in {"blue", "proxy", "mail-worker", "actuator"} and age > 90
        result[row["name"]] = {**data, "ts": row["ts"], "age_seconds": int(age), "stale": stale}
    return result


def _recent_outcomes(events):
    pairs, first = [], {}
    for event in sorted(events, key=lambda e: e["id"]):
        signature = json.dumps([event.get(k) for k in ("ip", "method", "path", "query", "body", "content_type")])
        if not event.get("blocked") and event.get("status") is not None and event.get("matched") != "diverted":
            first.setdefault(signature, event)
        elif event.get("blocked") and signature in first:
            before = first.pop(signature)
            pairs.append({"id": event["id"], "method": event.get("method"), "path": event.get("path"),
                          "before_id": before["id"], "after_id": event["id"], "before_status": before.get("status"),
                          "after_status": event.get("status"), "reason": event.get("matched")})
    return list(reversed(pairs[-3:]))


def _latest_containment(db, incidents):
    for incident in incidents[:20]:
        case_id = incident.get("case_id")
        ids = [int(p) for p in str(case_id).split(",") if p.isdigit()][:200]
        if not ids:
            continue
        placeholders = ",".join("?" for _ in ids)
        first = db.execute("SELECT MIN(ts) FROM records WHERE kind='events' AND id IN (" + placeholders + ")", ids).fetchone()[0]
        for row in db.execute("SELECT ts,data FROM records WHERE kind='actions' AND case_id=? ORDER BY id", (case_id,)):
            action = json.loads(row["data"])
            if first and action.get("tool") in CONTAINMENT and action.get("outcome") == "ok":
                try:
                    seconds = (datetime.fromisoformat(row["ts"].replace("Z", "+00:00")) - datetime.fromisoformat(first.replace("Z", "+00:00"))).total_seconds()
                    return {"seconds": max(0, seconds), "case_id": case_id}
                except ValueError:
                    pass
    return None


def snapshot(mode=None):
    with store.connection() as db:
        # WAL mode readers see a consistent snapshot without an explicit transaction.
        counts = {r["kind"]: r["n"] for r in db.execute("SELECT kind,COUNT(*) n FROM records GROUP BY kind")}
        queue = {r["status"]: r["n"] for r in db.execute("SELECT status,COUNT(*) n FROM records WHERE kind='events' GROUP BY status")}
        mail = {r["status"]: r["n"] for r in db.execute("SELECT status,COUNT(*) n FROM outbox GROUP BY status")}
        triage = db.execute("SELECT COUNT(DISTINCT json_extract(data,'$.case_id')) evaluated, "
                            "COUNT(DISTINCT CASE WHEN json_extract(data,'$.jev.malicious')=1 THEN json_extract(data,'$.case_id') END) flagged, "
                            "COUNT(DISTINCT CASE WHEN json_extract(data,'$.escalated')=1 THEN json_extract(data,'$.case_id') END) escalated "
                            "FROM records WHERE kind='actions' AND json_extract(data,'$.kind')='triage'").fetchone()
        actions = db.execute("SELECT COUNT(*) calls, COALESCE(SUM(json_extract(data,'$.outcome')='ok'),0) succeeded "
                             "FROM records WHERE kind='actions' AND json_extract(data,'$.kind')='action'").fetchone()
        blocked = db.execute("SELECT COUNT(*) FROM records WHERE kind='events' AND json_extract(data,'$.blocked')=1").fetchone()[0]
        # Read directly through this connection, rather than opening inconsistent snapshots.
        def latest(kind, limit):
            return [{**json.loads(r["data"]), "id": r["id"], "processing_status": r["status"]} for r in
                    db.execute("SELECT id,data,status FROM records WHERE kind=? ORDER BY id DESC LIMIT ?", (kind, limit))]
        state_row = db.execute("SELECT data FROM state WHERE id=1").fetchone()
        state = json.loads(state_row[0]) if state_row else store.DEFAULT_STATE
        events, recent_actions, incidents = latest("events", 200), latest("actions", 200), latest("incidents", 50)
        health = _health(db)
        containment = _latest_containment(db, incidents)
    allow_destructive = bool(state.get("allow_destructive")) or False
    return {"schema_version": 1, "mode": mode, "metrics_scope": "retained history",
            "allow_destructive": allow_destructive,
            "events": events, "actions": recent_actions, "incidents": incidents,
            "events_total": counts.get("events", 0), "incidents_total": counts.get("incidents", 0),
            "blocked_total": blocked, "denylist": [d for d in state.get("denylist", []) if store.active_ban(d)],
            "honeypot": state.get("honeypot", []), "vpatch": state.get("vpatch", []),
            "enforced_security": state.get("enforced_security"),
            "queue": queue, "mail": mail, "health": health, "latest_containment": containment,
            "funnel": {**dict(triage), "actions": actions["calls"], "succeeded": actions["succeeded"]},
            "notifications": notifications(limit=50)["items"], "log_sources": log_store.sources(),
            "recent_outcomes": _recent_outcomes(events)}
