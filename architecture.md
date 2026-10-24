# Architecture

This document describes implementation details. See [README.md](README.md) for setup, operating modes, and usage.

## Components

| Component | Entry point | Responsibility |
| --- | --- | --- |
| Proxy | `proxy.py` | Forward requests, enforce defenses, classify inline, capture events, serve management endpoints |
| Investigator | `blue_agent.py` | Consume queued events, classify asynchronously, run bounded LLM tool loops |
| Classifier | `classifier.py` | Call Jev, validate responses, enforce model-call budgets and inline deadlines |
| Actuator | `actuator_app.py` | Authenticate and validate infrastructure tool calls, apply deployment policy, execute Docker operations |
| Actuator client | `actuator_client.py` | Expose remote infrastructure tools to the investigator |
| Mail worker | `mail_worker.py` | Deliver pending notifications independently of investigations |
| Notification transport | `notifications.py` | Render incident emails and submit them to Resend |
| Honeypot | `honeypot_app.py` | Serve a static decoy and record diverted traffic |
| Store | `store.py` | Maintain shared defenses, durable queues, action records, budgets, and health |
| Dashboard | `dashboard.html` | Render traffic, incidents, defenses, and agent activity |

Compose names the project `bastion`. The proxy, investigator, actuator, honeypot, and mail worker share the `bastion-data` volume. DVWA is the bundled target. Only the actuator service mounts the Docker socket.

## Request lifecycle

The proxy buffers requests up to `MAX_REQUEST_BYTES`, derives source identity, and builds a structured, redacted observation. It reserves an event record before forwarding; queue exhaustion returns 503.

Enforcement runs in this order:

1. Divert configured sources to `HONEYPOT_URL`.
2. Reject active denylisted sources with 403.
3. Apply the per-source sliding-window rate limit, returning 429 when exceeded.
4. In `inline` mode, classify through Jev before forwarding. Malicious verdicts return 403; unavailable classification follows `INLINE_FAILURE`.
5. Forward to `DVWA_URL`, overriding the inbound security cookie if an enforced level is present.

The forwarding client preserves duplicate query parameters and multiple response cookies. It removes hop-by-hop headers, rebuilds source attribution, and currently strips `Authorization` before forwarding. Response buffering is bounded by `MAX_RESPONSE_BYTES`; upstream errors and oversized responses return 502.

After enforcement or forwarding, the proxy finalizes the event with the observed response status and outcome. Observe-mode events are terminal immediately; other modes queue them for the investigator. Unexpected interruption can leave a reserved event in `receiving` until its lease expires.

## Management and source identity

`/__dashboard`, `/__state`, `/__stream`, and `/__health` require `MANAGEMENT_TOKEN`. Clients may use Bearer authentication or HTTP Basic with username `admin`. Framework-generated API documentation routes are disabled.

The SSE endpoint checks snapshots once per second and emits a new snapshot on change. The browser falls back to polling if SSE fails. Snapshots include recent records, aggregate counts, active defenses, queue state, and component health. Console panes currently have no backing log stream; use Compose logs for service output.

Application-level source attribution uses the peer address unless the peer belongs to `TRUSTED_PROXY_CIDRS`. Trusted chains are processed from the nearest proxy outward. `DEMO_IDENTITY=1` explicitly enables first-hop X-Forwarded-For identity for lab traffic. Deployment must also account for the ASGI server's own proxy-header handling.

## Classification and investigation

The investigator claims up to 32 events at a time with a 180-second lease. Failed events retry with backoff and move to `dead` after three claimed attempts. Restarts resume queued work rather than skipping to the current log end.

In asynchronous classification, Jev flags are passed to the LLM when configured; provider errors also escalate when an investigator is available. Without Jev, agent mode sends eligible requests directly to the LLM. Classifier-containment mode applies a 15-minute source ban and queues an incident report for a malicious verdict. Inline verdicts are attached to events and reused by the investigator.

Source count controls investigation coordination. Below `SUPERVISOR_MIN`, requests are grouped by source and investigated in a pool bounded by `SWARM_MAX`. At or above the threshold, one campaign investigator receives a compact source/payload summary. This routing decision is not proof that a campaign exists.

The agent loop enforces eight turns, sixteen tool calls, a 60-second case budget checked between operations, and a 24,000-token usage threshold. SDK calls have timeouts; a running tool can extend beyond the remaining case budget. These are operational limits, not hard process-level cancellation guarantees. Model-call budgets are enforced transactionally in the shared store.

The system prompt includes environment context, the registered tool catalog, and operating instructions. Request content and tool results are treated as untrusted evidence. This is a prompt-level precaution, not a complete defense against prompt injection.

## Tools and infrastructure authority

Tools are registered as `{name, schema, fn}` entries. Core response tools live in `blue_agent.py`; read-only context tools in `tools.py`; diversion tools in `honeypot_tools.py`; infrastructure and DVWA-remediation tools are exposed through `actuator_client.py`.

Before dispatch, the investigator validates tool arguments against JSON Schema and applies the destructive-action setting. Read-only tools execute directly. Mutating actions use an execution key derived from case ID, tool name, and parameters. The store records the attempt before calling the handler. An interrupted attempt returns `UNKNOWN` on retry rather than silently repeating the operation.

The actuator independently authenticates requests, validates parameters, applies `ALLOW_DESTRUCTIVE`, checks budgets, and limits concurrent execution. Docker operations resolve an allowlisted service through Compose project/service labels. Process termination checks container ID, PID, start time, baseline membership, and protected service names; target-side pidfd support is required. A newly observed process is a candidate, not evidence of compromise.

`patch_vuln` changes DVWA's security level, verifies the same session, and persists the level the proxy must pin. Failure to persist enforcement is reported as a partial failure. Credential rotation updates the database and app configuration, verifies new/old credentials, and attempts verified rollback on failure.

The actuator remains highly privileged. Its API reduces the model container's direct authority but does not make Docker socket access safe for an untrusted host.

## Persistence

The active database is `bastion.db` under `BASTION_DATA_DIR`, using SQLite WAL with writer transactions and a busy timeout.

| Table | Contents |
| --- | --- |
| `state` | Source bans, diversions, enforced application security |
| `records` | Request observations, triage, tool activity, incidents, decoy hits |
| `executions` | Mutating-action attempts and cached results |
| `outbox` | Frozen notification payloads, retry counts, scheduling state |
| `mail_receipts` | Resend acceptance IDs and safe delivery errors |
| `budgets` | Per-window model and actuator call counters |
| `health` | Latest component health reports |
| `meta` | Migration markers |

Queue transitions are `receiving`, `pending`, `processing`, and finally `done` or `dead`. The `available` timestamp schedules retries; leases permit recovery from interrupted processing. The current schema does not assign an ownership token to a claim, so deployments should keep a single investigator and review lease duration before increasing concurrency.

The legacy JSON/state files are backed up and imported once. Their path constants remain as stream identifiers for older tool interfaces; normal writes go to SQLite. Retention removes terminal records older than `RETENTION_DAYS`; it does not currently prune every auxiliary table or legacy backup.

## Notifications

Incident creation and outbox enqueueing share one transaction. The message captures sender, recipients, and rendered content when queued, so a retry does not change its provider-idempotent payload after configuration changes.

The independent mail worker leases pending messages and submits them to Resend. Network failures, rate limiting, and server failures are retryable; permanent refusals move the message to `dead`. Attempts stop after five failures. A provider acceptance ID is recorded in `mail_receipts`, and the outbox status becomes `accepted`.

The lease is 60 seconds and the HTTP client timeout is 10 seconds. Resend retries reuse a stable idempotency key; provider idempotency retention is finite, so this is not an unlimited exactly-once guarantee. Delivery and bounce webhooks are not implemented. Resend's email log remains the source of recipient-server delivery status.

## Data handling

`privacy.py` redacts recognized sensitive keys in form and JSON data, preserves duplicate form/query parameters, and omits unstructured bodies from the main proxy's model view. Field redaction cannot identify every secret in arbitrary text, URL paths, process output, or human-written incident evidence. External-provider use requires a suitable data-handling policy.

The decoy returns the same portal for every route and optionally delays responses. It shares the demo network and writable data volume; it is not an isolated production deception environment.

## Verification and remaining boundaries

Pytest uses a temporary database per test and mocked HTTP transports. Coverage includes the real proxy app, authentication, classifier failures, state changes, tool dispatch, queues, and Resend submission/retry behavior. A live synthetic notification was also received successfully. These checks do not measure model judgment, prove exploit prevention, or validate real Docker remediation across supported environments.

`eval_waf.py` measures Jev against a small labeled dataset with precision/recall confidence intervals and optional repeated sampling. It is an evaluation utility, not a production detection-quality claim.

Priority hardening areas are a verified Compose startup/shutdown workflow, explicit image build targets, resource/client lifecycle cleanup, queue lease ownership, broader network isolation, reliable historical dashboard metrics, and live provider/actuator integration tests. Keep the supplied stack local while those boundaries remain.
