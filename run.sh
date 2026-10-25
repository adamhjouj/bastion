#!/usr/bin/env bash
# Build and start the full stack. State persists across restarts.
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -f .env ]; then
    echo "ERROR: .env not found. Copy .env.example and fill in required values."
    exit 1
fi

# Fail early if required secrets are missing.
check_token() {
    local var="$1"
    local val
    val="$(grep -E "^${var}=" .env | cut -d= -f2- | tr -d ' \r')" || true
    if [ -z "$val" ] || [ "$val" = "..." ] || [ "$val" = "changeme" ]; then
        echo "ERROR: ${var} must be set in .env (current value looks like a placeholder)"
        exit 1
    fi
}
check_token MANAGEMENT_TOKEN
check_token ACTUATOR_TOKEN

echo "[*] building and starting bastion stack ..."
docker compose up --build -d

cat <<EOF

=== Bastion up ===
  API:       http://localhost:8080/__api/v1/overview
    Token:   send MANAGEMENT_TOKEN as Basic Auth or a Bearer Authorization header
  App:       http://localhost:8080/
  Email:     Resend (configure RESEND_API_KEY, ALERT_FROM, ALERT_TO)
  Test mail: docker compose run --rm --no-deps mail-worker python mail_worker.py --test

  Mode: $(grep -E '^BASTION_MODE=' .env | cut -d= -f2 || echo observe)
  Logs: docker compose logs -f proxy blue
  Stop: docker compose down

  To initialize the DVWA database (first run or explicit reset):
    docker compose exec proxy python bootstrap_dvwa.py \$DVWA_URL --reset-confirm RESET-DVWA
EOF
