#!/usr/bin/env bash
# Bring up the whole stack: DVWA + MailHog, bootstrap DVWA, start the proxy and
# the blue-team agent. Then attack it from another terminal with red_agent.py.
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env ] && { set -a; . ./.env; set +a; }
: "${ANTHROPIC_API_KEY:?set ANTHROPIC_API_KEY (copy .env.example to .env)}"

PY=${PY:-python3}
[ -d .venv ] && PY=.venv/bin/python

echo "[*] starting DVWA + MailHog ..."
docker compose up -d

echo "[*] waiting for DVWA ..."
for _ in $(seq 1 60); do curl -sf http://localhost:80/login.php >/dev/null 2>&1 && break; sleep 2; done

echo "[*] bootstrapping DVWA (create DB, login, Security=Low) ..."
$PY bootstrap_dvwa.py http://localhost:80 || echo "   (check http://localhost/setup.php manually if this failed)"

echo "[*] clearing previous demo state ..."
mkdir -p data
: > data/events.jsonl; : > data/incidents.jsonl
echo '{"denylist":[],"rules":[],"seen_ips":{}}' > data/state.json

echo "[*] starting reverse proxy on :8080 ..."
$PY -m uvicorn proxy:app --host 0.0.0.0 --port 8080 --log-level warning &
PROXY_PID=$!
sleep 2

echo "[*] starting blue-team agent ..."
$PY blue_agent.py &
BLUE_PID=$!

trap 'kill $PROXY_PID $BLUE_PID 2>/dev/null || true; docker compose stop' INT TERM
cat <<EOF

=== READY ===
  Dashboard : http://localhost:8080/__dashboard
  MailHog   : http://localhost:8025
  App (via proxy, browse it): http://localhost:8080/
  Attack    : $PY red_agent.py sqli     (then: $PY red_agent.py cmdi)

Ctrl-C to stop everything.
EOF
wait
