"""Versioned dashboard API — read-only queries plus authenticated operator controls."""
import asyncio
import hashlib
import ipaddress
import json
import secrets
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, field_validator

from bastion import dashboard_data
from bastion import log_store
from bastion import operator_controls
from bastion import rollback
from bastion import store
from bastion.notifications import MailError, send_email, prepare_message

router = APIRouter(prefix="/__api/v1")

# ---- read models ----

class RecordPage(BaseModel):
    items: list[dict[str, Any]]
    next_cursor: int | None


class Overview(BaseModel):
    model_config = {"extra": "allow"}  # pass-through new fields without a model change
    schema_version: Literal[1]
    mode: str | None
    metrics_scope: str
    events_total: int
    incidents_total: int
    blocked_total: int
    diverted_total: int = 0   # requests sent to the decoy (matched == 'diverted')
    events: list[dict[str, Any]]
    actions: list[dict[str, Any]]
    incidents: list[dict[str, Any]]
    denylist: list[dict[str, Any]]
    honeypot: list[dict[str, Any]]
    vpatch: list[dict[str, Any]] = []   # proxy virtual patches (route-scoped exploit rules)
    enforced_security: str | None
    queue: dict[str, Any]
    mail: dict[str, Any]
    health: dict[str, Any]
    funnel: dict[str, Any]
    notifications: list[dict[str, Any]]
    log_sources: list[dict[str, Any]]
    recent_outcomes: list[dict[str, Any]]
    latest_containment: dict[str, Any] | None
    allow_destructive: bool = False


# ---- write models ----

class IPBody(BaseModel):
    ip: str
    reason: str = ""

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v):
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            raise ValueError("invalid IP address")


class PolicyBody(BaseModel):
    allow_destructive: bool


class RetryNotificationBody(BaseModel):
    id: int


class RollbackBody(BaseModel):
    reason: str = ""


class RunBody(BaseModel):
    job: str

    @field_validator("job")
    @classmethod
    def validate_job(cls, v):
        if v not in operator_controls.JOBS:
            raise ValueError("unknown job")
        return v


# ---- read endpoints ----

@router.get("/overview", response_model=Overview)
def overview(request: Request):
    return dashboard_data.snapshot(request.app.state.settings.mode)


@router.get("/requests", response_model=RecordPage)
def requests(before: int | None = Query(None, ge=1, le=9223372036854775807), limit: int = Query(100, ge=1, le=200)):
    return dashboard_data.record_page("events", before, limit)


@router.get("/actions", response_model=RecordPage)
def actions(before: int | None = Query(None, ge=1, le=9223372036854775807), limit: int = Query(100, ge=1, le=200),
            case_id: str | None = Query(None, max_length=1024)):
    return dashboard_data.record_page("actions", before, limit, case_id)


@router.get("/actions/{action_id}")
def action(action_id: int):
    item = rollback.load_action(action_id)
    if item is None:
        raise HTTPException(404, "action not found")
    return {"item": item}


@router.get("/rollback/capabilities")
def rollback_capabilities():
    return {"inverse": dict(rollback.INVERSE), "irreversible": sorted(rollback.IRREVERSIBLE)}


@router.get("/incidents", response_model=RecordPage)
def incidents(before: int | None = Query(None, ge=1, le=9223372036854775807), limit: int = Query(100, ge=1, le=200)):
    return dashboard_data.record_page("incidents", before, limit)


@router.get("/incidents/{incident_id}")
def incident(incident_id: int):
    result = dashboard_data.incident_detail(incident_id)
    if result is None:
        raise HTTPException(404, "incident not found")
    return result


@router.get("/notifications", response_model=RecordPage)
def notifications(before: int | None = Query(None, ge=1, le=9223372036854775807), limit: int = Query(100, ge=1, le=200),
                  case_id: str | None = Query(None, max_length=1024)):
    return dashboard_data.notifications(case_id, before, limit)


@router.get("/logs")
def log_sources():
    return {"items": log_store.sources()}


@router.get("/logs/{source}")
def logs(source: str, after: int = Query(0, ge=0, le=9223372036854775807), limit: int = Query(200, ge=1, le=500)):
    if source not in log_store.SOURCES:
        raise HTTPException(404, "unknown log source")
    return log_store.page(source, after, limit)


# ---- operator control endpoints ----

@router.post("/actions/{action_id}/rollback")
async def rollback_action(action_id: int, body: RollbackBody | None = None):
    """Revert one agent action through its inverse and append the compensating `rollback`
    action to the audit chain (the original row is never modified). Contract: CONTRACTS §3.1."""
    reason = body.reason[:500] if body else ""
    try:
        compensating = await asyncio.to_thread(rollback.rollback, action_id, reason)
    except LookupError:
        raise HTTPException(404, "action not found")
    except rollback.RollbackRefused as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=409)
    if compensating["outcome"] != "ok":
        return JSONResponse({"ok": False, "error": compensating["result"], "action": compensating}, status_code=502)
    return {"ok": True, "reverted": action_id, "action": compensating}


@router.post("/defenses/unban")
async def unban(body: IPBody):
    """Remove an active IP ban. Records the reversal in audit log."""
    removed = rollback.release_ban(body.ip)
    store.append_jsonl(store.ACTIONS_FILE, {"ts": store.now(), "kind": "action", "tool": "operator_unban",
                                             "input": {"ip": body.ip, "reason": body.reason[:500]},
                                             "outcome": "ok", "result": f"Removed {removed} ban(s) for {body.ip}"})
    return {"removed": removed, "ip": body.ip}


@router.post("/defenses/undivert")
async def undivert(body: IPBody):
    """Release a honeypot diversion, routing the source back to the real app."""
    removed = rollback.release_diversion(body.ip)
    store.append_jsonl(store.ACTIONS_FILE, {"ts": store.now(), "kind": "action", "tool": "operator_undivert",
                                             "input": {"ip": body.ip, "reason": body.reason[:500]},
                                             "outcome": "ok", "result": f"Released {removed} diversion(s) for {body.ip}"})
    return {"released": removed, "ip": body.ip}


@router.post("/defenses/policy")
async def set_policy(body: PolicyBody):
    """Toggle destructive-remediation approval at runtime without a service restart.
    Takes effect on the investigator's next tool call. Recorded in audit log."""
    store.set_policy("allow_destructive", body.allow_destructive)
    store.append_jsonl(store.ACTIONS_FILE, {"ts": store.now(), "kind": "action", "tool": "operator_policy",
                                             "input": {"allow_destructive": body.allow_destructive},
                                             "outcome": "ok",
                                             "result": f"allow_destructive set to {body.allow_destructive}"})
    return {"allow_destructive": body.allow_destructive}


@router.post("/notifications/retry")
async def retry_notification(body: RetryNotificationBody):
    """Mark a dead notification as pending so the mail worker retries it."""
    with store.connection(write=True) as db:
        row = db.execute("SELECT status FROM outbox WHERE id=?", (body.id,)).fetchone()
        if not row:
            raise HTTPException(404, "notification not found")
        if row["status"] not in {"dead", "pending"}:
            raise HTTPException(409, f"notification is {row['status']}, not retryable")
        db.execute("UPDATE outbox SET status='pending', available=0, attempts=0 WHERE id=?", (body.id,))
    return {"id": body.id, "status": "pending"}


@router.post("/notifications/test")
async def test_notification():
    """Queue and immediately attempt one labeled synthetic email to the configured ALERT_TO."""
    import uuid
    incident = {"ts": store.now(), "case_id": "operator-test-" + uuid.uuid4().hex[:8],
                "severity": "info", "attack_type": "notification_test",
                "source_ip": "not applicable",
                "evidence": "Operator-initiated test from the dashboard.",
                "summary": "Bastion alert delivery check. No attack occurred."}
    key = "operator-test-" + hashlib.sha256(json.dumps(incident, sort_keys=True).encode()).hexdigest()
    store.queue_mail(key, incident)
    result = await asyncio.to_thread(store.deliver_mail, send_email, key)
    if result is None:
        raise HTTPException(500, "mail worker did not process the test (no pending message found)")
    return result


# ---- demo control plane (local lab; fixed allow-listed jobs only) ----

@router.get("/control/status")
def control_status():
    """What is running and what can be run, for the dashboard's control buttons."""
    return operator_controls.snapshot()


@router.post("/control/run")
async def control_run(body: RunBody):
    """Launch a fixed, allow-listed job (e.g. a red-team attack). One at a time."""
    try:
        return await asyncio.to_thread(operator_controls.start, body.job)
    except operator_controls.Busy as exc:
        raise HTTPException(409, str(exc))
    except operator_controls.Unavailable as exc:
        raise HTTPException(503, str(exc))
    except operator_controls.Unknown:
        raise HTTPException(404, "unknown job")


@router.post("/control/stop")
async def control_stop():
    """Stop the currently running job, if any."""
    return await asyncio.to_thread(operator_controls.stop)


@router.post("/control/reset")
async def control_reset():
    """Clear the demo board: requests, actions, incidents, logs, queued mail, and defenses."""
    return await asyncio.to_thread(operator_controls.reset)


# ---- Resend delivery webhooks ----

@router.post("/__webhooks/resend")
async def resend_webhook(request: Request):
    """Update outbox status from Resend's event webhook (email.delivered, email.bounced, etc.)
    Verify svix-id / svix-signature before updating — reject without a configured secret."""
    webhook_secret = store.get_policy("resend_webhook_secret")
    if not webhook_secret:
        raise HTTPException(501, "RESEND_WEBHOOK_SECRET not configured; set it via POST /defenses/policy")
    # Svix signature verification: HMAC-SHA256 over f"{svix_id}.{svix_timestamp}.{body}"
    svix_id = request.headers.get("svix-id", "")
    svix_ts = request.headers.get("svix-timestamp", "")
    svix_sig = request.headers.get("svix-signature", "")
    body = await request.body()
    if not (svix_id and svix_ts and svix_sig):
        raise HTTPException(400, "missing Resend webhook signature headers")
    try:
        secret_bytes = webhook_secret.encode() if isinstance(webhook_secret, str) else webhook_secret
        signed = f"{svix_id}.{svix_ts}.{body.decode()}".encode()
        expected = "v1," + __import__("base64").b64encode(
            __import__("hmac").new(secret_bytes, signed, __import__("hashlib").sha256).digest()
        ).decode()
        if not any(secrets.compare_digest(expected, s.strip()) for s in svix_sig.split()):
            raise HTTPException(401, "webhook signature invalid")
    except Exception:
        raise HTTPException(401, "webhook signature verification failed")
    try:
        event = json.loads(body)
        event_type = event.get("type", "")
        email_id = event.get("data", {}).get("email_id", "")
        if not email_id:
            return {"ok": True, "skipped": "no email_id in payload"}
        delivery_status = {"email.delivered": "delivered", "email.bounced": "bounced",
                           "email.complained": "complained", "email.opened": "opened",
                           "email.clicked": "clicked"}.get(event_type)
        if delivery_status:
            with store.connection(write=True) as db:
                db.execute("UPDATE mail_receipts SET status=?,updated=? WHERE provider_id=?",
                           (delivery_status, store.now(), email_id))
                db.execute("UPDATE outbox SET status=? WHERE id=("
                           "SELECT outbox_id FROM mail_receipts WHERE provider_id=?)",
                           ("delivered" if delivery_status == "delivered" else "accepted", email_id))
        return {"ok": True, "event_type": event_type, "email_id": email_id}
    except json.JSONDecodeError:
        raise HTTPException(400, "invalid webhook payload")


# ---- SSE streams ----

async def overview_events(request):
    previous = None
    while not await request.is_disconnected():
        value = await asyncio.to_thread(dashboard_data.snapshot, request.app.state.settings.mode)
        payload = json.dumps(value, sort_keys=True)
        if payload != previous:
            previous = payload
            yield "event: snapshot\ndata: " + payload + "\n\n"
        else:
            yield ": keep-alive\n\n"
        await asyncio.sleep(1)


async def log_events(request, source, after):
    previous = None
    while not await request.is_disconnected():
        value = await asyncio.to_thread(log_store.page, source, after)
        payload = json.dumps(value, sort_keys=True)
        if payload != previous:
            previous = payload
            after = value["next_cursor"]
            identity = f"id: {after}\n" if value["entries"] else ""
            yield identity + "event: logs\ndata: " + payload + "\n\n"
        else:
            yield ": keep-alive\n\n"
        await asyncio.sleep(1)


def event_response(generator):
    return StreamingResponse(generator, media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@router.get("/stream")
async def stream(request: Request):
    return event_response(overview_events(request))


@router.get("/logs/{source}/stream")
async def log_stream(request: Request, source: str, after: int = Query(0, ge=0, le=9223372036854775807)):
    if source not in log_store.SOURCES:
        raise HTTPException(404, "unknown log source")
    cursor = request.headers.get("last-event-id")
    if cursor is not None:
        try:
            after = int(cursor)
            if not 0 <= after <= 9223372036854775807:
                raise ValueError()
        except ValueError:
            raise HTTPException(400, "invalid log cursor")
    return event_response(log_events(request, source, after))
