#!/usr/bin/env bash
# Build + run the entire stack in Docker: DVWA + MailHog + reverse-proxy/WAF +
# blue-team agent. The proxy container waits for DVWA, bootstraps it, then serves.
set -euo pipefail
cd "$(dirname "$0")"
[ -f .env ] || { echo "Missing .env — run: cp .env.example .env  and add TYPESAFE_API_KEY"; exit 1; }

echo "[*] building + starting stack (DVWA + MailHog + proxy + blue agent) ..."
docker compose up --build -d

cat <<EOF

=== Bastion up (dockerized) ===
  Dashboard : http://localhost:8080/__dashboard
  MailHog   : http://localhost:8025
  App (proxied): http://localhost:8080/

  Attack it (pure-Jev, no Anthropic key needed):
    curl -H 'X-Forwarded-For: 10.13.37.7' \\
      "http://localhost:8080/vulnerabilities/sqli/?id=1'+OR+'1'='1&Submit=Submit"
    # then re-run the same curl -> 403 (Jev banned the IP + added a WAF rule)

  With ANTHROPIC_API_KEY in .env, the autonomous red agent works too:
    .venv/bin/python red_agent.py sqli

  Logs : docker compose logs -f proxy blue
  Stop : docker compose down
EOF
