# Breach Agent — autonomous blue-team damage control over DVWA

A 24/7 blue-team agent that watches a live web app's request logs, detects
attacks in real time, and runs damage control automatically: **blacklist the
attacker's IP, virtually patch the vulnerability (WAF rule), and email an
incident report** — with a live dashboard and a scoped autonomous red-team
agent that finds the exploit on stage.

See `architecture.md` for the full design.

## How it works
A reverse proxy sits in front of DVWA and is **both** the log source **and** the
enforcement point. The blue agent tails its log, a cheap regex pre-filter gates
what reaches Claude, then Claude classifies and calls tools to block + patch +
alert. Re-running the same attack then returns `403` live.

```
red_agent → proxy :8080 → DVWA :80
                │ logs + enforces (denylist + WAF)
                ▼
          blue_agent → Claude → blacklist / WAF rule / email
                │
          dashboard (/__dashboard)
```

## Quick start
```bash
cp .env.example .env            # add your ANTHROPIC_API_KEY
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
./run.sh                        # DVWA+MailHog, bootstrap, proxy, blue agent
```
Open the dashboard: http://localhost:8080/__dashboard · MailHog: http://localhost:8025

Then, in another terminal, attack it:
```bash
.venv/bin/python red_agent.py sqli     # SQL injection → data exfiltration
.venv/bin/python red_agent.py cmdi     # command injection → RCE
```

## Demo script
1. Dashboard up, quiet.
2. Run `red_agent.py sqli` → feed lights up red as it probes and finds the injection.
3. Blue agent fires: incident appears, attacker IP banned, WAF rule added, **email in MailHog**.
4. Re-run the same attack → **403, blocked**. "Same exploit, now dead."
5. Run `red_agent.py cmdi` → proves it defends more than one attack class.

## Manual test (no agents)
```bash
# benign (200), then an obvious SQLi (blue should ban within ~2s), then blocked (403)
curl -s -o /dev/null -w "%{http_code}\n" -H 'X-Forwarded-For: 9.9.9.9' \
  "http://localhost:8080/vulnerabilities/sqli/?id=1%27+OR+%271%27=%271&Submit=Submit"
```

Notes: DVWA runs at Security=Low (the red agent's target). Everything is local —
never expose DVWA publicly. `# ponytail` comments in the code flag the demo-grade
corners and their upgrade paths.
