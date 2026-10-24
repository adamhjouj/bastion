"""Isolated browser-test server. Never loaded by a production service."""
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main():
    with tempfile.TemporaryDirectory(prefix="bastion-browser-") as directory:
        os.environ["BASTION_DATA_DIR"] = directory
        os.environ["ALERT_FROM"] = "Tests <alerts@example.com>"
        os.environ["ALERT_TO"] = "recipient@example.com"
        import hashlib
        import httpx
        import uvicorn
        import log_store
        import store
        from proxy import create_app
        from settings import Settings
        store.initialize()
        for _ in range(205):
            event_id = store.append_jsonl(store.EVENTS_FILE, {"ts": store.now(), "ip": "192.0.2.1", "method": "GET",
                "path": "/fixture", "query": '<img src=x onerror="window.injected=1">', "body": "", "status": 403, "blocked": True})
        store.append_jsonl(store.ACTIONS_FILE, {"ts": store.now(), "kind": "action", "tool": "blacklist_ip", "case_id": "1",
                                                "outcome": "error", "result": "Fixture: action failed"})
        store.append_jsonl(store.INCIDENTS_FILE, {"ts": store.now(), "case_id": "1", "source_ip": "192.0.2.1", "severity": "high",
                                                  "attack_type": "browser_fixture", "summary": "Browser fixture, not live attack traffic"})
        store.queue_mail("browser-mail", {"ts": store.now(), "case_id": "1", "severity": "high"})
        for source in ["blue", "proxy"]:
            text = source + ' <script>window.injected=1</script>'
            log_store.append(source, [{"ts": store.now(), "container_id": "a" * 12, "stream": "stdout", "text": text,
                                       "digest": hashlib.sha256(text.encode()).hexdigest(), "occurrence": 0}])
            log_store.set_source(source, "streaming", "Browser-test fixture producer")
        async def upstream(request):
            return httpx.Response(200, text="fixture")
        app = create_app(Settings(management_token="x" * 32), upstream_transport=httpx.MockTransport(upstream))

        @app.post("/__test/advance")
        async def advance():
            text = "blue new output"
            log_store.append("blue", [{"ts": store.now(), "container_id": "a" * 12, "stream": "stderr", "text": text,
                                       "digest": hashlib.sha256(text.encode()).hexdigest(), "occurrence": 0}])
            store.deliver_mail(lambda _: {"provider": "resend", "provider_id": "browser-email-id"})
            return {"ok": True}

        @app.post("/__test/update-request")
        async def update():
            store.finalize_event(event_id, {"ts": store.now(), "ip": "192.0.2.1", "method": "GET", "path": "/updated",
                                            "status": 202, "blocked": False}, observe=True)
            return {"ok": True}

        # Test-only mutation routes precede the production catch-all; management
        # authentication still applies. No such endpoints exist in the production app.
        app.router.routes.sort(key=lambda route: 0 if getattr(route, 'path', '').startswith('/__test/') else 1)
        uvicorn.run(app, host="127.0.0.1", port=8898, log_level="warning", proxy_headers=False)


if __name__ == "__main__":
    main()
