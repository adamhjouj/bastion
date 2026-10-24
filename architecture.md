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
| Dashboard API | `dashboard_api.py`, `dashboard_data.py` | Versioned read-only queries, linked incident details, server metrics, SSE |
| Log collector | `log_collector.py`, `log_store.py` | Follow allowlisted Compose stdout/stderr, redact and retain bounded cursor-addressable history |
| Dashboard | `dashboard.html`, `static/` | Render traffic, health, incidents, defenses, email state, and live logs |

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

`/__dashboard`, `/__api/v1/*`, and `/__assets/*` require `MANAGEMENT_TOKEN`. Legacy `/__state`, `/__stream`, and `/__health` routes remain authenticated. Clients may use Bearer authentication or HTTP Basic with username `admin`. Framework-generated API documentation routes are disabled, and unknown management paths cannot fall through to the upstream application.

The dashboard consumes full overview snapshots once per second over SSE. Reconnecting resynchronizes the entire view; failed streams use polling while retrying SSE. Component heartbeat freshness is separate from transport connection status. Client rendering uses database identities, bounds displayed history, updates changed records, and uses DOM text APIs rather than HTML interpolation. Assets are separate ES modules and a stylesheet under a CSP without inline scripts/styles.

The versioned read-only API exposes overview, paginated requests/actions/incidents/notifications, linked incident details, source metadata, log pages, and log SSE streams. Pagination uses `before` record IDs. Each log source uses an independent `after` cursor; SSE accepts `Last-Event-ID`. Pruned/reset history causes an explicit reset response. Invalid cursors and non-allowlisted sources are rejected before any query.

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
| `service_logs` | Bounded stdout/stderr entries with source, container identity, timestamps, and replay deduplication keys |
| `log_sources` | Log reader connection state and heartbeat per service |
| `meta` | Migration markers |

Queue transitions are `receiving`, `pending`, `processing`, and finally `done` or `dead`. The `available` timestamp schedules retries; leases permit recovery from interrupted processing. The current schema does not assign an ownership token to a claim, so deployments should keep a single investigator and review lease duration before increasing concurrency.

The legacy JSON/state files are backed up and imported once. Their path constants remain as stream identifiers for older tool interfaces; normal writes go to SQLite. Retention removes terminal records older than `RETENTION_DAYS`; it does not currently prune every auxiliary table or legacy backup.

## Container log ingestion

The actuator starts one supervised Docker log reader per allowlisted source: `blue`, `proxy`, `dvwa`, `honeypot`, `actuator`, `mail-worker`, and `red`. Discovery requires unique Compose project/service labels, independent of the destructive-action target allowlist. The proxy and browser read captured records from SQLite; no Docker log command is initiated by a browser request.

Readers follow `docker logs --timestamps`, consume stdout/stderr concurrently, and use a bounded queue between pipe readers and persistence. Oversized lines are drained with bounded memory and marked truncated. Common credential assignments, known secret values available to the collector, API-key patterns, and terminal controls are removed before storage. This does not guarantee arbitrary free-text secret removal.

First attachment reads up to 200 recent lines. Reattachment requests output since the source/container timestamp watermark; timestamp, stream, content digest, and occurrence distinguish replay from repeated identical messages. Each source retains at most `LOG_RETENTION_LINES` database entries, with 4096 characters per line. Containers retain two rotating 5 MB runtime log files under the supplied Compose configuration.

Readers rediscover replaced containers and report missing, stopped, reconnecting, unavailable, and stale states. The optional red service is inactive until its profile is launched; host Python process output and file-only application logs are not automatically collected. Runtime rotation, clock regressions, bounded replay bookkeeping, and retention mean ingestion is not a lossless forensic archive.

Compose runs proxy and investigator processes directly, without tee pipelines. Shared services explicitly build the base image; the actuator builds the Docker-CLI target. Collector tasks and child processes are shut down with the actuator lifecycle.

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

Live Docker smoke tests verify stdout/stderr capture across all seven source names, replay without duplicates after restart, discovery after container recreation, and log-reader cleanup. A separate test runs the built proxy and actuator images against a shared isolated volume and checks that real container output reaches the authenticated dashboard API. Browser tests cover server totals, incident links, email updates, log switching/pause/resume, SSE recovery, and safe rendering. They do not launch attacks or call paid providers.

Remaining hardening areas include full target-stack readiness across platforms, queue lease ownership, broader network isolation, scalable historical queries, and live provider/privileged-action validation. Keep the supplied stack local while those boundaries remain.
