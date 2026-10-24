"""Read-only versioned dashboard API, protected by the proxy management boundary."""
import asyncio
import json
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

import dashboard_data
import log_store

router = APIRouter(prefix="/__api/v1")


class RecordPage(BaseModel):
    items: list[dict[str, Any]]
    next_cursor: int | None


class Overview(BaseModel):
    schema_version: Literal[1]
    mode: str | None
    metrics_scope: str
    events_total: int
    incidents_total: int
    blocked_total: int
    events: list[dict[str, Any]]
    actions: list[dict[str, Any]]
    incidents: list[dict[str, Any]]
    denylist: list[dict[str, Any]]
    honeypot: list[dict[str, Any]]
    enforced_security: str | None
    queue: dict[str, int]
    mail: dict[str, int]
    health: dict[str, dict[str, Any]]
    funnel: dict[str, int]
    notifications: list[dict[str, Any]]
    log_sources: list[dict[str, Any]]
    recent_outcomes: list[dict[str, Any]]
    latest_containment: dict[str, Any] | None


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


async def overview_events(request):
    previous = None
    while not await request.is_disconnected():
        value = await asyncio.to_thread(dashboard_data.snapshot, request.app.state.settings.mode)
        payload = json.dumps(value, sort_keys=True)
        if payload != previous:
            previous = payload
            # Full snapshots make reconnect a complete resync, not a partial delta.
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
