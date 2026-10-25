#!/usr/bin/env bash
set -euo pipefail
export DVWA_URL="${DVWA_URL:-http://dvwa:80}"

echo "[proxy] waiting for target ..."
python - <<'PY'
import os
import time
import urllib.request

for attempt in range(60):
    try:
        urllib.request.urlopen(os.environ['DVWA_URL'] + '/', timeout=3).close()
        break
    except Exception:
        if attempt == 59:
            raise SystemExit('[proxy] target readiness timed out')
        time.sleep(2)
PY

# The target self-initializes its database and per-deploy mutation at boot (see target_app/),
# so no external bootstrap step is required here.

# UVICORN_EXTRA_ARGS lets the dev override enable --reload without changing prod.
# Disable pathname expansion so glob-style --reload-exclude patterns (e.g.
# node_modules/*) are passed to uvicorn literally instead of being expanded by
# the shell against the mounted /app tree.
set -f
exec uvicorn proxy:app --host 0.0.0.0 --port 8080 --no-proxy-headers --log-level info ${UVICORN_EXTRA_ARGS:-}
