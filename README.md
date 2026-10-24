# Bastion

**Autonomous incident response for web applications.**

Bastion monitors HTTP traffic, investigates suspected attacks, and takes action against confirmed threats. It combines a fast request classifier with an LLM investigator that can inspect current defenses, contain an attacker, harden the application, and send an incident report.

The project includes a reverse proxy, a live security dashboard, a honeypot, and a vulnerable application for testing the complete response loop locally.

## Capabilities

- **Request classification:** TypeSafe Jev scores requests before they reach the application or asynchronously after capture, depending on the selected mode.
- **Agent-led investigation:** Claude or DeepSeek reviews request context and uses read-only tools before deciding how to respond.
- **Active response:** Ban or release sources, divert traffic to a decoy, invalidate sessions, investigate processes, and request application or container remediation.
- **Persistent processing:** SQLite-backed event queues, action records, retry handling, and an independent notification outbox preserve work across restarts.
- **Incident reporting:** Resend delivers structured email alerts with evidence, source information, severity, and response details.
- **Live visibility:** An authenticated dashboard streams traffic, incidents, defenses, and agent activity over Server-Sent Events.

**Status:** experimental. The bundled target is DVWA, an intentionally vulnerable application. Run the lab on a trusted local machine; do not expose the stack to the internet.

## Quick start

### Requirements

- Docker with Docker Compose
- An Anthropic or DeepSeek API key for agent mode
- A TypeSafe API key for inline or classifier-containment mode
- A Resend API key and a verified sending domain for email alerts

Python 3.12+ is required for running the services or tests outside Docker.

### Configure

```sh
git clone https://github.com/adamhjouj/bastion.git
cd bastion
cp .env.example .env
```

Generate separate management and actuator tokens:

```sh
python3 -c 'import secrets; print(secrets.token_hex(32)); print(secrets.token_hex(32))'
```

Set the following in `.env`, using one generated token for each credential:

```env
MANAGEMENT_TOKEN=your-management-token
ACTUATOR_TOKEN=your-actuator-token
BASTION_MODE=agent
ANTHROPIC_API_KEY=your-anthropic-key
RESEND_API_KEY=your-resend-key
ALERT_FROM="Bastion Alerts <alerts@your-domain.com>"
ALERT_TO=you@example.com
```

For DeepSeek, set `DEEPSEEK_API_KEY` instead. DeepSeek takes precedence when both LLM keys are present. Add `TYPESAFE_API_KEY` to classify requests with Jev before escalating them to the agent; otherwise, agent mode sends eligible requests directly to the LLM.

Keep `.env` private. See [`.env.example`](.env.example) for request limits, classifier budgets, source attribution, and response permissions.

### Start

```sh
bash run.sh
```

- **Application:** http://localhost:8080/
- **Dashboard:** http://localhost:8080/__dashboard

The dashboard uses HTTP Basic authentication: username `admin`, password `MANAGEMENT_TOKEN`. Management APIs also accept that token as a Bearer credential.

Initialize the lab database on first use:

```sh
docker compose exec proxy python bootstrap_dvwa.py http://dvwa:80 --reset-confirm RESET-DVWA
```

This command **resets DVWA's database**. Normal authentication and proxy restarts do not perform a reset.

```sh
docker compose logs -f proxy blue mail-worker
docker compose down
```

`docker compose down` preserves the named data volume. Adding `--volumes` deletes it.

## Operating modes

Set `BASTION_MODE` to choose when classification happens and who makes enforcement decisions.

| Mode | Behavior | Required model credentials |
| --- | --- | --- |
| `observe` | Capture traffic without model classification or automatic investigation. Existing bans, diversions, and rate limits still apply. | None |
| `agent` | Investigate captured requests asynchronously. Jev can triage first; the LLM decides response actions. | Anthropic or DeepSeek; Jev optional |
| `classifier-contain` | Classify captured requests with Jev. Malicious verdicts trigger provisional 15-minute bans and incident reports. | TypeSafe |
| `inline` | Classify with Jev before forwarding. Reject malicious requests; optionally escalate flagged cases to an LLM. | TypeSafe; LLM optional |

Asynchronous modes cannot stop the initial request from reaching the application. Inline classification adds provider latency; `INLINE_FAILURE=reject` returns a service-unavailable response when classification fails, while `allow` forwards the request. The default is `reject`.

## Response controls

The investigator calls named, schema-validated tools. It can inspect recent requests and defenses, ban or unban sources, divert attackers, and raise incidents. Infrastructure operations go through an authenticated actuator service; the Docker socket is mounted only into that service.

`ALLOW_DESTRUCTIVE=0` is the default. Enabling it permits higher-impact tools such as process/session termination, credential rotation, container quarantine, and DVWA security-level changes. These actions are deployment-specific: process termination requires target-side Python with Linux pidfd support, and egress isolation requires a separate outbound network.

Diversion takes precedence over a ban. Remove an IP's diversion if you intend its ban to cut off access.

## Email alerts

Alerts use Resend's HTTPS API. A separate `mail-worker` drains the persistent outbox, retries transient failures, and records provider acceptance IDs. Sender and recipient settings come from `.env`; multiple recipients can be comma-separated.

Send one labeled test email without generating attack traffic:

```sh
docker compose run --rm --no-deps mail-worker python mail_worker.py --test
```

For local Python development:

```sh
python mail_worker.py --env-file .env --check
python mail_worker.py --env-file .env --test
python mail_worker.py --env-file .env
```

`--check` validates configuration without sending. `--test` sends only its synthetic message, not unrelated queued alerts. An `accepted` result means Resend accepted the request; use Resend's email log to check delivery or bounce status. Delivery webhooks are not implemented.

## Development

```sh
uv venv --python 3.12
uv pip install -r requirements.txt pytest
.venv/bin/python -m pytest -q
```

Tests cover proxy enforcement, classification failures, tool dispatch, persistent state, redaction, authentication, and notification retries. Network interactions use mock transports; these tests do not establish live-model detection quality or production readiness.

The optional red agent supports SQL-injection and command-injection objectives against the local DVWA lab. Run it with the appropriate provider credentials exported:

```sh
.venv/bin/python red_agent.py sqli
.venv/bin/python red_agent.py cmdi
```

`eval_waf.py` evaluates Jev against the included labeled dataset and reports precision, recall, confidence intervals, and repeated-run variance. Live evaluations incur API usage:

```sh
TYPESAFE_API_KEY=your-key .venv/bin/python eval_waf.py --repeat 3
```

## Technical notes

Bastion is built with Python, FastAPI, HTTPX, SQLite WAL, the Anthropic SDK, TypeSafe Jev, and Resend. The dashboard uses plain HTML, CSS, and JavaScript.

The proxy is a single-worker, buffered implementation. Rate limits are process-local, the honeypot shares the demo network and data volume, and infrastructure remediation is specific to the bundled target. Sensitive-field redaction reduces exposure but does not guarantee removal of secrets from arbitrary text. External model calls, privileged tools, and false-positive containment all require a deployment-specific security review.

See [architecture.md](architecture.md) for component responsibilities, state transitions, and implementation boundaries.
