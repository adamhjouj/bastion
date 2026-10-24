#!/usr/bin/env bash
# Proxy container entrypoint: wait for DVWA, bootstrap it, reset demo state, serve.
set -e
echo "[proxy-entry] waiting for DVWA at ${DVWA_URL} ..."
python - <<'PY'
import os, time, httpx
url = os.environ.get("DVWA_URL", "http://dvwa:80")
for _ in range(90):
    try:
        httpx.get(url + "/login.php", timeout=3)
        break
    except Exception:
        time.sleep(2)
PY
echo "[proxy-entry] bootstrapping DVWA ..."
python bootstrap_dvwa.py "${DVWA_URL}" || echo "[proxy-entry] bootstrap warning (continuing)"
echo "[proxy-entry] resetting demo state ..."
mkdir -p /app/data
: > /app/data/events.jsonl; : > /app/data/incidents.jsonl
echo '{"denylist":[],"rules":[],"seen_ips":{}}' > /app/data/state.json
echo "[proxy-entry] starting reverse proxy on :8080 ..."
exec uvicorn proxy:app --host 0.0.0.0 --port 8080 --log-level warning
