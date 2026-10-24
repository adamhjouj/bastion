# Bastion architecture: current implementation

## Data plane

`proxy.py` is a FastAPI reverse proxy and request-log producer. Catch-all requests follow this order:

1. Read shared defenses, cached by state-file mtime.
2. Forward diverted IPs to the honeypot when configured. Diversion precedes every other defense.
3. Reject active denylisted IPs with 403; expired TTL entries do not block forwarding.
4. Apply per-IP sliding-window capacity limits (429).
5. Forward to DVWA, pinning the security cookie when `enforced_security` is set.
6. Log the observed status, request data and enforcement outcome.

There is no regex payload detector or WAF rule loop. Legacy `state['rules']` is ignored. The initial request is not held for model classification.

Management routes (`/__dashboard`, `/__state`, `/__stream`) are served before the catch-all. They currently have no authentication and bypass the application enforcement path. SSE watches file mtimes every half-second and publishes snapshots; the browser falls back to polling.

## Detection and response

`blue_agent.py` polls `events.jsonl`. Every eligible request reaches the configured model pipeline without a signature pre-gate:

- Jev enabled: `classifier.py` calls its REST API for maliciousness and attack type. Benign verdicts are dropped; flags reach the LLM if configured. Errors also reach the LLM when available.
- Jev unavailable: requests go directly to the configured LLM.
- LLM available: a manual tool-use loop supplies the environment, tool catalog, requests and existing bans. The model can investigate, contain, remediate and report.
- `JEV_AUTOBLOCK=1` with LLM: high-confidence flags may be silently diverted while the model investigates.
- `JEV_AUTOBLOCK=1` without LLM: flags trigger TTL bans and reports. No signature rules are installed.
- No engine, or Jev-only with autoblock disabled: no automatic payload containment.

The agent skips blocked requests and all IPs still present in the denylist, including expired entries. The latter is a known bug scheduled in the implementation plan.

Requests are deduplicated, then dispatched to bounded concurrent per-IP investigators (`SWARM_MAX=4`). At `SUPERVISOR_MIN=8` distinct IPs, one campaign investigator receives a compact summary. Source count selects coordination strategy, not a deterministic threat verdict. Exact request-data keys memoize Jev responses per poll; source identity is currently excluded from these keys despite being included in the classifier prompt.

`llm.py` selects DeepSeek first when its key is present, otherwise Anthropic. There are no local model calls. Without keys it returns no client.

## Tool modules

Tools are registered as `{name, schema, fn}`. `tools.catalog()` builds a grouped catalog from live registrations.

- Core agent tools: individual/bulk bans, incident reports, recorded-request inspection.
- `tools.py`: defenses, recent requests/incidents, container status.
- `honeypot_tools.py`: diversion and release.
- `remediation_tools.py`: DVWA security-level change, read-back and proxy cookie-enforcement intent.
- `actuator.py`: process/session listing and termination, network disconnect, pause/unpause and DB credential rotation.

`inspect_target` now returns recorded method/path/query/body without token signatures, endpoint allowlists or heuristic threat judgments. Recorded text is decoded and body-truncated by the proxy; it is not lossless original HTTP evidence.

The model does not receive an arbitrary shell tool. However, its process has the Docker socket in Compose. Argument validation is useful but is not a host-level privilege boundary. Boot-time process baselines also do not prove that every later process is malicious.

Regex remains for non-detection tasks such as session-ID validation, config parsing and CSRF token extraction. It does not classify HTTP traffic.

## State and observability

`store.py` defines paths under `/app/data`, shared by a Docker volume:

| File | Contents |
| --- | --- |
| `state.json` | denylist, optional honeypot diversions, optional enforced security |
| `events.jsonl` | request observations |
| `actions.jsonl` | triage and tool attempts/results |
| `incidents.jsonl` | incident records |
| `honeypot_hits.jsonl` | decoy requests |
| `logs/*.log` | process output where actually collected |

Atomic replace prevents partial state-file reads. Locks serialize writes within one Python process, not across processes. Reads load whole files; logs and limiter identity entries are unbounded.

The dashboard displays the latest 200 events and 400 actions, incidents, defenses and log tails. It now exposes diversion and enforced-security state and labels escalations as escalations. Most counters are still window-derived, bans are not filtered for expiry, and replay's 'LEAKED' label does not prove actual disclosure. These remain planned fixes.

## Demo infrastructure

`docker-compose.yml` defines DVWA, proxy, blue, honeypot and MailHog. `run.sh` builds/starts the stack. Proxy startup waits for DVWA, runs bootstrap, resets logs/defenses and starts uvicorn through tee. Compose dependency order is not a readiness guarantee.

`bootstrap_dvwa.authed_session` resets the database, logs in and selects low security. `red_agent.py` calls it at import and then runs one of two prompted lab objectives, SQL injection or command injection. Its tool does not yet enforce endpoint scope independently of the prompt.

The honeypot returns a static portal for every route, optionally delays responses and records hits. It shares a writable data volume and Docker network; stronger isolation is required before non-local use.

The default actuator project name is `breach-agent`, while Compose currently uses normal project-name discovery. Configure matching identities or actuator resolution can fail. The single shared network also means `isolate_egress` usually has no separate network to disconnect.

## Verification boundaries

`test_model_detection.py` exercises the actual proxy with ASGI transport and mocked upstreams, checks legacy regex rules are ignored, verifies bans remain effective and confirms non-signature-bearing requests reach Jev. `test_inspect.py` verifies factual inspection.

Other tests cover TTL mutation, cookies, tools, supervisor dispatch and rate limits. Several legacy scripts mutate global state at import; honeypot/rate-limit E2E scripts use replicated proxy shims. Live model behavior and real Docker remediation are not established by these mocks.

`eval_waf.py` calls the real Jev API over a small labeled dataset and reports precision/recall confidence intervals, repeated-run variance and leakage probes. It does not currently implement every metric historically advertised, and some probe-error paths are fragile.

See [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for the remaining issues, delivery order and acceptance criteria, including optional inline Jev classification to address first-request exposure without restoring payload signatures.
