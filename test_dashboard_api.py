"""Read-only dashboard API, accurate aggregates and linked incident details."""
import asyncio
import hashlib
import json
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

import dashboard_api
import log_store
import store
from proxy import create_app
from settings import Settings


@pytest.fixture
def client():
    async def upstream(request):
        return httpx.Response(200, text="OK")
    app = create_app(Settings(management_token="x" * 32), upstream_transport=httpx.MockTransport(upstream))
    with TestClient(app, headers={"Authorization": "Bearer " + "x" * 32}) as c:
        yield c


def record(stream, **data):
    return store.append_jsonl(getattr(store, stream.upper() + "_FILE"), {"ts": store.now(), **data})


def test_all_dashboard_surfaces_require_authentication(client):
    for path in ["/__api/v1/overview", "/__api/v1/logs", "/__api/v1/logs/blue", "/__api/v1/stream",
                 "/__api/v1/logs/blue/stream", "/__api/v1/notifications", "/__assets/app.js", "/__dashboard"]:
        assert client.get(path, headers={"Authorization": ""}).status_code == 401


def test_aggregates_use_retained_history_not_visible_page(client):
    for _ in range(205):
        record("events", status=403, blocked=True)
    data = client.get("/__api/v1/overview").json()
    assert data["schema_version"] == 1
    assert data["mode"] == "observe"
    assert data["events_total"] == 205 and data["blocked_total"] == 205
    assert len(data["events"]) == 200


def test_triage_retries_are_not_counted_twice(client):
    for _ in range(2):
        record("actions", kind="triage", case_id="123", jev={"malicious": True}, escalated=True)
    record("actions", kind="action", case_id="123", tool="blacklist_ip", outcome="error")
    record("actions", kind="action", case_id="123", tool="inspect_target", outcome="ok")
    funnel = client.get("/__api/v1/overview").json()["funnel"]
    assert funnel == {"evaluated": 1, "flagged": 1, "escalated": 1, "actions": 2, "succeeded": 1}


def test_record_pagination_uses_database_identity(client):
    for _ in range(3):
        record("events", method="GET", path="/same", blocked=False)
    page = client.get("/__api/v1/requests?limit=2").json()
    assert len(page["items"]) == 2
    older = client.get(f"/__api/v1/requests?limit=2&before={page['next_cursor']}").json()
    assert len(older["items"]) == 1
    assert len({e["id"] for e in page["items"] + older["items"]}) == 3


def test_incident_details_link_requests_actions_and_email(client):
    first = record("events", method="GET", path="/one")
    second = record("events", method="POST", path="/two")
    case = f"{first},{second}"
    record("actions", kind="action", case_id=case, tool="blacklist_ip", outcome="ok", result="blocked")
    iid = record("incidents", case_id=case, severity="high", summary="test")
    store.queue_mail("test-email", {"case_id": case, "severity": "high", "ts": store.now()})
    store.deliver_mail(lambda _: {"provider": "resend", "provider_id": "provider-123"})
    data = client.get(f"/__api/v1/incidents/{iid}").json()
    assert {r["id"] for r in data["requests"]} == {first, second}
    assert data["actions"][0]["tool"] == "blacklist_ip"
    assert data["notifications"][0]["provider_id"] == "provider-123"
    assert "_mail" not in json.dumps(data)
    assert "RESEND_API_KEY" not in json.dumps(data)
    assert client.get("/__api/v1/incidents/999999").status_code == 404


def test_expired_defenses_do_not_show_as_active(client):
    store.save_state({"denylist": [{"ip": "192.0.2.1", "expires": store.now_plus(-60)}], "honeypot": []})
    assert client.get("/__api/v1/overview").json()["denylist"] == []


def test_log_api_is_bounded_and_cursor_addressable(client):
    entry = {"container_id": "a" * 12, "ts": store.now(), "text": "real output", "stream": "stderr",
             "digest": hashlib.sha256(b"real output").hexdigest(), "occurrence": 0}
    log_store.append("blue", [entry])
    page = client.get("/__api/v1/logs/blue").json()
    assert page["entries"][0]["stream"] == "stderr"
    assert client.get(f"/__api/v1/logs/blue?after={page['next_cursor']}").json()["entries"] == []
    assert client.get("/__api/v1/logs/unrelated").status_code == 404
    assert client.get("/__api/v1/logs/blue?limit=10000").status_code == 422
    assert client.get("/__api/v1/logs/blue?after=-1").status_code == 422
    assert client.get("/__api/v1/logs/blue?after=999999999999999999999999999").status_code == 422
    assert client.get("/__api/v1/logs/blue/stream", headers={"Last-Event-ID": "bad"}).status_code == 400


def test_no_authenticated_management_request_falls_through_to_target(client):
    assert client.post("/__api/v1/unban", json={}).status_code == 404
    assert client.get("/__not-a-route").status_code == 404


def test_assets_and_policy_do_not_require_inline_code(client):
    response = client.get("/__dashboard")
    assert response.status_code == 200
    assert "unsafe-inline" not in response.headers["Content-Security-Policy"]
    assert "<script type=\"module\" src=\"/__assets/app.js\"" in response.text
    assert client.get("/__assets/app.js").status_code == 200
    assert client.get("/__assets/dashboard.css").status_code == 200


def test_full_snapshot_and_log_stream_payloads():
    class Request:
        app = SimpleNamespace(state=SimpleNamespace(settings=Settings()))
        async def is_disconnected(self):
            return False
    async def scenario():
        overview = dashboard_api.overview_events(Request())
        first = await anext(overview)
        assert "event: snapshot" in first and '"schema_version": 1' in first
        await overview.aclose()
        log_store.append("proxy", [{"container_id": "a" * 12, "ts": store.now(), "text": "line", "stream": "stdout", "digest": "digest", "occurrence": 0}])
        events = dashboard_api.log_events(Request(), "proxy", 0)
        first = await anext(events)
        assert "event: logs" in first and "id: " in first
        assert '"text": "line"' in first
        await events.aclose()
        cursor = log_store.page("proxy")["next_cursor"]
        log_store.append("proxy", [{"container_id": "a" * 12, "ts": store.now(), "text": "new line", "stream": "stderr", "digest": "newdigest", "occurrence": 0}])
        request = Request()
        request.headers = {"last-event-id": str(cursor)}
        response = await dashboard_api.log_stream(request, "proxy", after=0)
        frame = await anext(response.body_iterator)
        assert '"text": "new line"' in frame
        assert '"text": "line"' not in frame
        await response.body_iterator.aclose()
    asyncio.run(scenario())
