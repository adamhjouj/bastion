"""Self-test for honeypot_app. Points the hit-log at a tempdir so the real
data/ dir stays clean. Run: .venv/bin/python test_honeypot_app.py
"""
import json
import tempfile
from pathlib import Path

import store

# Redirect hit logging to a throwaway dir BEFORE importing the app. The handler
# reads store.DATA at call time, so this monkeypatch takes effect.
tmp = Path(tempfile.mkdtemp())
store.DATA = tmp

import honeypot_app
from fastapi.testclient import TestClient

client = TestClient(honeypot_app.app)

# GET / -> real-looking 200 page with the marker and no honeypot tells.
r = client.get("/?q=union+select", headers={"User-Agent": "curl/8.0"})
assert r.status_code == 200, r.status_code
body = r.text
assert "Acme Internal Portal" in body, "fake-page marker missing"
low = body.lower()
assert "honeypot" not in low and "decoy" not in low, "honeypot tell leaked into response"

# POST to an arbitrary path with a body -> still 200. Spoofed XFF + UA exercise
# the IP first-hop parsing and user-agent capture.
r2 = client.post("/admin/login", data={"username": "root", "password": "x"},
                 headers={"X-Forwarded-For": "203.0.113.9, 10.0.0.1",
                          "User-Agent": "sqlmap/1.7"})
assert r2.status_code == 200, r2.status_code

# Both hits logged with the expected fields.
lines = (tmp / "honeypot_hits.jsonl").read_text().splitlines()
assert len(lines) == 2, f"expected 2 logged hits, got {len(lines)}"
rows = [json.loads(ln) for ln in lines]
for o in rows:
    assert o["ip"] and o["method"] and o["path"] is not None, o
    assert "ts" in o and "query" in o and "body" in o and "user_agent" in o, o

g, p = rows
assert g["method"] == "GET" and g["path"] == "/", g
assert "union" in g["query"], g
assert p["method"] == "POST" and p["path"] == "/admin/login", p
assert p["ip"] == "203.0.113.9", f"XFF first hop not used: {p['ip']}"
assert p["user_agent"] == "sqlmap/1.7", p
assert "root" in p["body"], p

print("honeypot_app test: ALL PASSED")
