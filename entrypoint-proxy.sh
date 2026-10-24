#!/usr/bin/env bash
set -euo pipefail
export DVWA_URL="${DVWA_URL:-http://dvwa:80}"

echo "[proxy] waiting for DVWA ..."
python - <<'PY'
import os
import time
import urllib.request

for attempt in range(60):
    try:
        urllib.request.urlopen(os.environ['DVWA_URL'] + '/login.php', timeout=3).close()
        break
    except Exception:
        if attempt == 59:
            raise SystemExit('[proxy] DVWA readiness timed out')
        time.sleep(2)
PY

python bootstrap_dvwa.py "${DVWA_URL}" || {
    echo "[proxy] DVWA login unavailable; initialize the lab DB explicitly if needed"
    echo "[proxy] docker compose exec proxy python bootstrap_dvwa.py http://dvwa:80 --reset-confirm RESET-DVWA"
}

exec uvicorn proxy:app --host 0.0.0.0 --port 8080 --no-proxy-headers --log-level info
