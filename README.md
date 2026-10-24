# Bastion

An autonomous blue-team response lab: model-based request classification, an LLM investigator, named containment/remediation tools, a honeypot and a live dashboard around DVWA.

**Demo software. DVWA is deliberately vulnerable. Keep the stack local; do not expose it publicly.**

## Request flow

```text
attacker → proxy :8080 → honeypot diversion / active ban / rate limit → DVWA
                │
                └→ request log → Jev classifier → LLM investigation → response tools
                                                        │
                                 shared defenses ←───────┘
```

There is **no regex attack pre-filter, hardcoded attack-signature detector, or regex WAF enforcement**. All eligible logged requests reach Jev, or the LLM directly if Jev is unavailable. Old persisted `rules` are ignored. Regex used for configuration parsing and tool-argument validation is not an attack detector.

Classification currently happens **after forwarding**. The initial exploit may reach the app; subsequent requests can be contained by decisions written to shared state. Removing the old pre-filter increases model traffic and cost. Inline Jev protection is proposed, not implemented.

## Decision modes

| Configuration | Current behavior |
| --- | --- |
| LLM key, optional Jev key | Jev flags (if enabled); the LLM decides responses. Without Jev, all eligible requests go directly to the LLM. |
| LLM + Jev + `JEV_AUTOBLOCK=1` | High-confidence flags may additionally trigger a reversible honeypot diversion while the LLM investigates. |
| Jev only + `JEV_AUTOBLOCK=1` | Flagged requests trigger a provisional TTL ban and incident email. No signature rules are installed. |
| Jev only + `JEV_AUTOBLOCK=0` | Classification only; no automatic containment. |
| Neither model | No payload detection or investigation; existing defenses and rate limits still apply. |

Jev errors escalate to the LLM when configured. This is asynchronous escalation, **not fail-closed protection**. IP bans and rate limits depend on source attribution, which currently trusts X-Forwarded-For for demo purposes.

## Start the demo

Requires Docker/Compose and an API key for at least one decision engine.

```sh
cp .env.example .env
# Fill in a real provider key. Remove the sk-... placeholder.
# For Jev-only automatic containment, explicitly set JEV_AUTOBLOCK=1.
bash run.sh
```

- Dashboard: http://localhost:8080/__dashboard
- App: http://localhost:8080/
- MailHog: http://localhost:8025

DeepSeek takes precedence over Anthropic when both keys are set. `.env` is loaded into the blue container by Compose; host Python commands do not automatically load it.

**Current startup caveats:** proxy startup clears demo defenses/logs and bootstraps DVWA; the red agent's authentication helper also resets the database. Do not use this stack for data you need to preserve.

## Tools

- Investigation: `inspect_target` (recorded facts only), `get_defenses`, `recent_requests`, `recent_incidents`, `service_status`, `list_processes`, `list_sessions`.
- Containment: `blacklist_ip`, `bulk_blacklist_ip`, `divert_to_honeypot`, `undivert`, `kill_process`, `kill_session`, `isolate_egress`, `quarantine_container`, `release_container`.
- Remediation: `patch_vuln`, `rotate_secret`.
- Reporting: `raise_alert`.

Diversion precedes bans. Undivert an IP before expecting its ban to cut access. Container tools require matching Compose project labels (`BASTION_PROJECT`, currently defaulting to `breach-agent`); the checked-in Compose file does not yet enforce that project identity.

## Development and verification

```sh
uv venv
uv pip install -r requirements.txt pytest
.venv/bin/python -m pytest -q test_model_detection.py test_inspect.py
```

Legacy tests are a mix of scripts and pytest functions; some mutate module globals at import, and the old honeypot/rate-limit E2E tests exercise shims rather than the actual proxy. Do not treat a blanket test collection as isolated until those fixtures are standardized.

`eval_waf.py` retains its historical filename but evaluates Jev, not regex enforcement:

```sh
TYPESAFE_API_KEY=... .venv/bin/python eval_waf.py
```

The small labeled dataset is not evidence of production accuracy. Live evaluations incur API calls.

## Documentation

- [Current architecture](architecture.md)
- [Prioritized implementation plan and acceptance criteria](IMPLEMENTATION_PLAN.md)

Known limitations include spoofable source identity, unauthenticated management endpoints, Docker socket access in the model container, flat-file state, unbounded logs/agent loops, expired-ban investigation suppression, single-network egress limitations and demo resets. The implementation plan covers these and the remaining deployment, evaluation, dashboard and testing issues.
