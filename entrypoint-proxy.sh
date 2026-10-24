#!/usr/bin/env bash
# Wait for DVWA, initialize the store (idempotent), then serve.
# Does NOT reset defenses, events or logs between restarts.
set -euo pipefail

DVWA_URL="${DVWA_URL:-http://dvwa:80}"

echo "[proxy] waiting for DVWA at ${DVWA_URL} ..."
for i in $(seq 1 60); do
    curl -sf "${DVWA_URL}/login.php" -o /dev/null && break
    [ "$i" = 60 ] && { echo "[proxy] DVWA not ready after 60s"; exit 1; }
    sleep 2
done

echo "[proxy] verifying DVWA login ..."
python bootstrap_dvwa.py "${DVWA_URL}" || {
    echo "[proxy] WARNING: DVWA login failed; DB may need explicit initialization"
    echo "[proxy] Run: docker compose exec dvwa python bootstrap_dvwa.py \$DVWA_URL --reset-confirm RESET-DVWA"
}

mkdir -p /app/data/logs
echo "[proxy] starting reverse proxy on :8080 (mode: ${BASTION_MODE:-observe})"
exec uvicorn proxy:app --host 0.0.0.0 --port 8080 --log-level info
