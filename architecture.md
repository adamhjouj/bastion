# Architecture — Bastion (as built)

Autonomous blue-team breach damage-control system over DVWA, with a two-tier
triage (fast classifier flags, an LLM agent reasons), a privileged control plane
the LLM drives without a shell, a honeypot decoy, a provider-agnostic agent
(Claude or DeepSeek), a live SOC dashboard, and a measured classifier-evaluation
harness. This document describes **what actually exists in this repo**, file by
file, plus the data flow, the state model, the verified behavior, and the known
demo-grade ceilings.

Status legend: ✅ verified running · 🔑 implemented, needs an agent key (`ANTHROPIC_API_KEY` or `DEEPSEEK_API_KEY`) to run the system-2 path live · 🧪 module built + unit-tested, integration pending.

---

## 1. What it does

A reverse proxy sits in front of DVWA and is **both the log source and the
enforcement point**. The blue agent tails that log through a tiered triage:

1. a free **regex pre-gate** drops obvious benign traffic;
2. a system-1 classifier (**TypeSafe Jev**) scores the rest malicious/benign + attack type;
3. a **two-tier decision** — an unambiguous hit (score ≥ `AUTOBLOCK_HIGH`) gets an
   instant but **provisional** reflex ban (the live `403`); the ambiguous band
   (`MALICIOUS_THRESHOLD` ≤ score < `AUTOBLOCK_HIGH`) escalates to the **LLM agent**,
   which investigates with read-only tools and calls action tools to contain, patch,
   eradicate, divert, and alert.

Re-running the same attack then returns `403`. A scoped red-team agent discovers
and exploits one named vulnerability through the proxy, so the blue side sees real
attack traffic on stage.

One-line pitch: *"A fast classifier flags; an agent that understands its
environment investigates and decides; the proxy enforces the decision live. Not a
score→ban WAF — the reasoning the raw score lacks."*

---

## 2. System diagram

```
  ┌───────────────┐        ┌──────────────────────────────────────────────────────┐
  │  red_agent.py │  HTTP  │                   proxy.py  (:8080)                    │
  │ (Claude/      │───────▶│  source_ip() = X-Forwarded-For or client host          │
  │  DeepSeek)    │  XFF=  │  0. honeypot divert?  ─▶ decoy (honeypot_app :9000) ───┼──▶ honeypot_hits.jsonl
  │               │attacker│  1. denylist (TTL-aware)?  ─▶ 403                       │
  └───────────────┘   IP   │  2. WAF rule match?        ─▶ 403                       │        ┌────────────┐
          ▲               │  3. forward (pin security cookie if enforced) ──────────┼───────▶│ DVWA (:80) │
          │ http_request   │  4. append record → data/events.jsonl                  │◀───────│  docker    │
          │ tool           │  SSE /__stream pushes a fresh snapshot on any change     │        └────────────┘
          │                └───────────────┬────────────────────────────────────────┘
          │                                │ events.jsonl (append-only)
          │                                ▼
          │        ┌───────────────────────────────────────────────────────────────┐
          │        │                     blue_agent.py (loop)                        │
          │        │  regex pre-gate → Jev (classifier.py) → score:                  │
          │        │     ≥ AUTOBLOCK_HIGH   → autoblock(): provisional TTL IP ban     │
          │        │     ambiguous band     → analyse(): LLM agent (llm.py)           │
          │        │  agent: inspect_target · orient (tools.py) · act (tools below)   │
          │        └───────────────┬───────────────────────────────────────────────┘
          │     ┌───────────────┬──┴────────────┬──────────────┬───────────────┬──────────────┐
          │     ▼               ▼                ▼              ▼               ▼              ▼
          │  blacklist_ip   add_waf_rule   patch_vuln /     divert_to_   kill/isolate/    raise_alert
          │  (TTL or        → state.json   rotate_secret    honeypot     quarantine       → MailHog :1025
          │   durable)                     (remediation_    (honeypot_   (actuator.py,     + incidents.jsonl
          │   → state.json                  tools.py)        tools.py)    no LLM shell)
          │                                    │
          │                                    ▼
          └──────  dashboard.html  ◀── SSE /__stream  ◀── build_state() (events, funnel, incidents,
                                                          defenses, honeypot, streamed consoles)
```

All runtime state is flat files under `data/`. No database, no queue.

---

## 3. Components (file by file)

### `store.py` ✅  — shared flat-file state + log tails
Single source of truth for paths and I/O, imported everywhere.
- Files: `state.json`, `events.jsonl`, `incidents.jsonl`, **`actions.jsonl`** (unified
  agent timeline — triage verdicts + executed tool actions), and `data/logs/{dvwa,proxy,blue,red}.log`.
- `load_state()` / `save_state()` — atomic write (`.tmp` + `os.replace`), so the proxy
  never reads a half-written file.
- `append_jsonl()` / `read_jsonl(limit)`, plus `count_lines()`, `tail_lines(n)` (for the
  dashboard consoles), `now()` and **`now_plus(seconds)`** (ISO expiry for TTL bans).
- `DEFAULT_STATE = {"denylist":[], "rules":[], "seen_ips":{}}`; `honeypot` and
  `enforced_security` are added to the state dict on demand.

### `proxy.py` ✅  — reverse proxy = log source + enforcement point
FastAPI app forwarding to DVWA via async `httpx`. Explicit routes before the catch-all:
- `GET /__dashboard` → serves `dashboard.html`.
- `GET /__state` → one JSON snapshot (`build_state()`): last 200 events, `events_total`,
  last 400 actions, incidents, denylist, rules, and tails of the four container/agent logs.
- `GET /__stream` → **Server-Sent Events**: watches the mtimes of all state/log files and
  pushes a fresh snapshot (~0.5s) whenever anything changes, with a ~10s keep-alive.
- `ANY /{path:path}` → the proxy itself.

Per-request logic, **in this order**:
0. **Honeypot divert** (precedence over everything) — if the IP is in `state["honeypot"]`
   and `HONEYPOT_URL` is set, forward to the decoy and log the hit as `diverted`
   (`blocked:false`), *never* a `403`. A block would tip the attacker off; a silent
   divert keeps the TTP harvest going. `undivert` first to actually cut them off.
1. **IP denylist** (TTL-aware) — a hit `403`s, **unless** its `expires` has passed
   (provisional reflex bans auto-lift; a null/absent `expires` is permanent).
2. **WAF rules** — each compiled regex tested against the decoded `probe`; first match `403`s.
3. **Forward** — hop-by-hop headers stripped both ways; `Accept-Encoding: identity`
   upstream (fixes the gzip double-decode bug and keeps responses plaintext). If
   `state["enforced_security"]` is set, the inbound `security` cookie is stripped and
   **pinned** to that level (closes `patch_vuln`'s cookie-pinning bypass). Upstream errors → `502`.

Query/body are `unquote_plus`-decoded for logging and WAF matching (so `%27`→`'` is
matchable); forwarding uses the **original** bytes. Rule compilation is mtime-cached, so a
blue-agent write takes effect within one request, no restart.
`# ponytail`: trusts `X-Forwarded-For` for the demo's distinct attacker IP — never in prod.

### `blue_agent.py` 🔑  — detection & two-tier response loop
Standalone process (keeps slow LLM calls out of the request path).
- **`main()`** polls `events.jsonl` every 1s from the current end. For each candidate
  (not already blocked, survives the regex pre-gate):
  - `USE_JEV` off → straight to the agent (if a key is set).
  - Jev **error** → fail-safe escalate to the agent.
  - Jev **benign** → drop.
  - Jev **malicious, score ≥ `AUTOBLOCK_HIGH`** (default 0.9) → `autoblock()` now, and if an
    agent is present, also escalate so the agent owns the durable rule + incident.
  - Jev **malicious, ambiguous band** → escalate to the agent to investigate.
  - No agent available → Jev autoblock is the full responder (fail safe).
  - Every candidate writes one `record_triage()` row (powers the dashboard funnel).
- **`autoblock(event, verdict, defer_rule)`** — system-1 reflex, no LLM. Bans the IP with a
  short TTL (`AUTOBLOCK_TTL_MIN`, reversible, one attacker). The durable class-wide WAF rule
  is high-blast-radius, so it is **deferred to the agent** when one exists; only with no
  agent does the reflex also add the canned rule + email. In `AUTOBLOCK_MODE=divert` it also
  diverts the IP to the decoy from request #1 (TTL ban as backstop).
- **`do_blacklist_ip(ip, reason, expires)`** — `expires=None` is durable; an ISO timestamp is
  provisional. Re-banning only **strengthens** (TTL→durable on agent confirm; never weakens).
- **`do_inspect_target(path, method, query, body)`** — read-only structural evidence for the
  agent: decoded params, shell/SQL/XSS token presence, a file/path-param directory-escape
  check, and whether the path is a known app endpoint. Derives facts; never re-sends the request.
- **`analyse(client, events, create_kwargs)`** — sends the suspicious batch (each with its Jev
  verdict, advisory) + current defenses to the agent, runs a manual tool-use loop, and mirrors
  every executed tool onto `actions.jsonl`.
- **System prompt** is assembled at import: `tools.ENVIRONMENT` (the standing briefing) +
  `tools.catalog(TOOLS)` (the **live** tool set, grouped by purpose, generated from the
  registered tools) + the operating doctrine (investigate before acting; provisional-ban
  semantics; divert vs. ban; no duplicate actions).
- **Regex pre-gate** `SUSPICIOUS` now covers `<svg`, `onload=`, `javascript:`, and backslash
  traversal `..\` in addition to the original tokens — so XSS/traversal variants reach Jev.
- Email via `smtplib` (MailHog by default; STARTTLS + login with real creds). Mail failures
  are caught and never kill the loop.

### `classifier.py` 🔑  — system-1 triage (TypeSafe Jev)
Fast malicious/benign classification gating the agent.
- **`classify_request(event)`** — raw REST `POST https://api.typesafe.ai/v1/systemone` (via
  `httpx`). Sends the request rendered as `state` plus two Jev questions: a **Noul**
  (malicious probability) and a **Choice** (sqli / cmdi / xss / traversal / benign).
- Returns `{malicious, malicious_score, attack_type, type_confidence, probabilities}`;
  `malicious = noul ≥ MALICIOUS_THRESHOLD`. If flagged malicious but the top Choice is
  "benign", the best non-benign type is used.
- **`parse_answers()`** is pure (unit-tested); on API error returns `{error, malicious: None}`
  so the loop fails safe. `python classifier.py` runs a live SQLi + benign smoke test.

### `llm.py` 🔑  — provider shim (Claude **or** DeepSeek)
The agents are written against the Anthropic Messages API; this aims that same SDK at
Anthropic or DeepSeek's Anthropic-compatible endpoint, chosen by whichever key is set.
- **`provider()`** → `"deepseek"` (wins if `DEEPSEEK_API_KEY` is set) | `"anthropic"` | `None`.
- **`make_client()`** → `(client, create_kwargs)`. DeepSeek: `base_url=https://api.deepseek.com/anthropic`,
  no extra kwargs. Anthropic: native, `output_config={"effort":"low"}` (which DeepSeek rejects).
  No key → `(None, {})` and the blue agent falls back to Jev autoblock.
- **`model_for(env_override, default)`** — resolves the model per provider (a stale `claude-*`
  default in `.env` is ignored on DeepSeek, so the example `.env` works with just a key added).

### `tools.py` ✅  — situational awareness + the tool catalog
Makes the agent **understand** its environment, not just react.
- **Read-only ORIENT tools** (no side effects): `get_defenses` (everything currently enforced —
  bans, rules, diverts, pinned level), `recent_requests`, `recent_incidents`, `service_status`
  (container up/paused/exited via the actuator's docker boundary). Registered via the same
  `{name,schema,fn}` hook the action modules use.
- **`catalog(schemas)`** renders the **whole live tool set** into grouped text for the system
  prompt, so a newly registered tool is taught automatically — the agent is never blind to a
  tool it can call.
- **`ENVIRONMENT`** — the standing briefing (topology, proxy = sensor + enforcement, Jev may
  have pre-placed a provisional ban, "a flag is a reason to look, not proof").

### `remediation_tools.py` 🔑  — real eradication (`patch_vuln`) + enforced security
Beyond a WAF band-aid: **`patch_vuln(level)`** raises DVWA's security level so the exploited
module switches to its safe/parameterized code path, confirming on the **same session** (DVWA's
level is per-session; cross-session confirm would be a false positive) and failing **closed**.
On success it records `enforced_security` in `state.json`, and `proxy.py` pins the inbound
`security` cookie to that level — **closing the cookie-pinning bypass** (a client that pins
`security=low` otherwise dodges the raise). Setting `low` clears enforcement (reset).

### `actuator.py` 🔑  — privileged control plane, no LLM shell
The agent's "hands inside the infrastructure" that a WAF structurally lacks. **Safety model is
the point:** the LLM never emits a command string — it calls a named tool with scalar params,
each mapped to **one fixed, argument-list** `docker` call (no `shell=True`). Every target is a
logical service name validated against `ALLOWED_TARGETS` (`{"dvwa"}`) — the agent cannot touch
the proxy, itself, MailHog, or anything outside the project. Tools: `list_processes` /
`list_sessions` (grounding reads), `kill_process` (only a live, **non-baseline** pid — apache/
mysqld/init are structurally unkillable), `kill_session`, `isolate_egress`, `quarantine_container`
/ `release_container`, `rotate_secret` (fresh random DB password, **never logged**, verifies old
creds are dead and rolls back on failure). `run_tool()` never raises into the loop and audits
every attempt (ok/rejected/error) to `data/actions.jsonl`. Ships a `_selftest()` (`python actuator.py`).
`# ponytail`: reaches Docker via the mounted socket (host root) — fine on a local demo box; split
into an actuator sidecar for a real deploy.

### `honeypot_app.py` + `honeypot_tools.py` ✅  — deception
- `honeypot_app.py` — a decoy FastAPI app serving one convincing "Acme Internal Portal" page for
  every route (no tells), logging every hit (path, payload, UA) to `data/honeypot_hits.jsonl`.
  Optional `HONEYPOT_DELAY` tarpit.
- `honeypot_tools.py` — `divert_to_honeypot(ip)` / `undivert(ip)` record intent in
  `state["honeypot"]` (idempotent, symmetric); the proxy's divert step (precedence 0) does the routing.

### `rate_limit.py` 🧪  — per-IP sliding-window limiter
Caps requests per window per source IP (infrastructure-harm prevention, separate from the WAF).
`limited(ip)` over a `deque` of monotonic stamps; `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW` /
`RATE_LIMIT_ENABLED` knobs; `retry_after()` for the `429` `Retry-After` header. **Built and
unit/E2E-tested, but not yet wired into `proxy.py`'s request path** (the one-line proxy hook is
pending — see Roadmap). `# ponytail`: in-memory dict, no eviction — needs Redis + LRU at scale.

### `bootstrap_dvwa.py` ✅  — DVWA auth plumbing (reused)
Removes the #1 demo-day failure (uninitialised DVWA DB). `authed_session(base_url, xff)` scrapes
the anti-CSRF token, resets the DB, logs in (admin/password), sets Security=Low; `verify()` is the
health check `run.sh` / the entrypoint call. Reused by the red agent and `remediation_tools._login`.

### `red_agent.py` 🔑  — scoped autonomous attacker
Holds an authenticated DVWA session **through the proxy** with `X-Forwarded-For=ATTACKER_IP`, so
every probe is attributed to the attacker. One `http_request` tool; the agent (`RED_MODEL`, up to
25 turns) works one scoped objective: `sqli` (dump the users table) or `cmdi` (read `/etc/passwd`).
Scoped = reliable on stage. Runs on the same provider shim (`llm.py`).

### `dashboard.html` ✅  — live SOC view
Single self-contained page (inline CSS/JS, no framework). Connects to **`/__stream`** (SSE) and
renders: counters, a **pipeline funnel** (requests → pre-gate → Jev → reflex/agent → actions), the
live request feed (attack rows red; `403`/blocked flagged with the matched signature; `diverted`
rows marked), the incident timeline, the active-defenses panel (denylist + WAF rules + honeypot
diverts + pinned level), an **exploit-replay** panel, and the **streamed container/agent consoles**
(dvwa/proxy/blue/red). A `200 → 403` on the same attack is the visual payoff.

### Supporting files
- `docker-compose.yml` ✅ — `dvwa` (internal), `mailhog` (UI :8025), `honeypot` (decoy :9000,
  data volume only, no DVWA/MySQL access), `proxy` (:8080, WAF + dashboard, tees to `logs/proxy.log`),
  `blue` (detection loop, `.env`, docker socket mounted, tees to `logs/blue.log`).
- `entrypoint-proxy.sh` ✅ — wait for DVWA → bootstrap → reset `data/` + `logs/` → serve (tee'd).
- `run.sh` ✅ — `docker compose up --build -d` + prints URLs and the curl attack.
- `requirements.txt` — `anthropic`, `fastapi`, `uvicorn[standard]`, `httpx` (DeepSeek reuses the
  anthropic SDK; Jev is raw REST — no extra deps).
- `.env.example` — provider keys (DeepSeek/Anthropic), Jev key, SMTP, model names. **Note:** the
  newer tuning knobs (`AUTOBLOCK_HIGH`, `AUTOBLOCK_TTL_MIN`, `AUTOBLOCK_MODE`, `HONEYPOT_URL`,
  `RATE_LIMIT_*`) have sensible code defaults and are not all listed there yet.

---

## 4. State model (`data/state.json`)

```jsonc
{
  "denylist": [
    {"ip":"10.13.37.7", "reason":"Jev-flagged sql_injection (0.99); provisional 15m ban",
     "ts":"...", "expires":"2026-10-24T..Z"},   // expires=null → permanent (agent-confirmed)
  ],
  "rules":    [ {"pattern":"union\\s+select", "description":"block SQLi UNION", "ts":"..."} ],
  "honeypot": [ {"ip":"10.13.37.7", "reason":"auto-divert: Jev sqli (0.99)", "ts":"..."} ],
  "enforced_security": "impossible",            // set by patch_vuln; proxy pins the security cookie
  "seen_ips": {}
}
```
Other logs: `events.jsonl` (one per request, decoded, with `blocked`/`matched`),
`incidents.jsonl` (one per `raise_alert`), `actions.jsonl` (triage rows + executed tool actions,
drives the funnel + timeline), `honeypot_hits.jsonl` (decoy TTP capture), `logs/*.log` (consoles).

---

## 5. Request lifecycle

1. Attacker/browser/curl hits proxy `:8080`.
2. Proxy: honeypot divert? → denylist (TTL-aware)? → WAF? → forward (pinning the security cookie
   if enforced), logging the real status. SSE pushes the change to the dashboard.
3. Blue agent reads new events, pre-filters, and classifies with Jev.
4. Score ≥ `AUTOBLOCK_HIGH` → provisional TTL ban now; ambiguous → agent investigates.
5. The agent orients (read-only tools), calls `inspect_target`, and either confirms (durable
   re-ban + tight WAF rule + alert, optionally eradicate/divert/control-plane) or clears it.
6. State mutations take effect at step 2 on the next matching request. Provisional bans auto-lift;
   confirmed ones persist. Loop closed.

---

## 6. Verification status

**Verified running (no agent key needed):**
- Proxy data plane: benign→`200`, denylisted IP→`403`, `UNION SELECT` from a fresh IP→`403`,
  URL-encoded payloads decode and match, gzip double-decode fixed, honeypot divert returns the
  decoy page logged as `diverted`, TTL bans expire, enforced-security cookie pinning.
- Jev autoblock end to end (with `TYPESAFE_API_KEY`): all five classes flagged 0.91–0.99 →
  provisional ban (+ canned rule/email with no agent).
- **Test suite** (host, `.venv`): `test_pipeline` (regex → stubbed-LLM dispatch → state + incident
  + real MailHog email), `test_remediation`, `test_inspect`, `test_ban_ttl`, `test_enforce_cookie`,
  `test_honeypot_{app,tools,e2e}`, `test_rate_limit` + `test_rate_limit_e2e`, and `actuator._selftest`.
- **Jev eval harness** (`eval_waf.py`, 41-case dataset): on the current set, recall 100% (0 FN),
  precision 95.8%, F1 0.98 @ threshold 0.5; the sweep shows 0 FP / 0 FN at 0.9. Reports 95% Wilson
  CIs, run provenance, `--repeat` variance, and a label-leakage probe.

**Implemented, needs an agent key (🔑):** the system-2 path — the agent's investigation/decision
(Claude via `ANTHROPIC_API_KEY`, or DeepSeek via `DEEPSEEK_API_KEY`) and the red agent's live
exploitation. The dispatch/tool-use loop around both is proven (stubbed) and the tools are
unit-tested; only the model judgment is untested in CI.

**Built, integration pending (🧪):** the per-IP rate limiter (`rate_limit.py`) — module + tests done,
proxy hook not yet added.

---

## 7. How to run — fully dockerized

The whole stack runs in Docker: DVWA + honeypot + MailHog + reverse-proxy/WAF + blue agent. **No
agent key is required** — the blue agent defends via Jev autoblock; add a key to enable the
system-2 agent and the red agent.

```bash
cd ~/breach-agent
cp .env.example .env          # add DEEPSEEK_API_KEY or ANTHROPIC_API_KEY and/or TYPESAFE_API_KEY
./run.sh                      # docker compose up --build -d

# attack it (pure-Jev, no agent key):
curl -H 'X-Forwarded-For: 10.13.37.7' \
  "http://localhost:8080/vulnerabilities/sqli/?id=1'+OR+'1'='1&Submit=Submit"
# re-run -> 403.  Dashboard: http://localhost:8080/__dashboard   MailHog: http://localhost:8025
```

**Decision modes** (`blue_agent.py`, env-tunable): `JEV_AUTOBLOCK` + `AUTOBLOCK_HIGH` set the
reflex/escalate split; `AUTOBLOCK_TTL_MIN` the provisional-ban lifetime; `AUTOBLOCK_MODE=divert`
switches the high-confidence reflex to deception-first. `USE_REGEX_PREGATE=0` sends all traffic to
Jev. Models: `BLUE_MODEL` / `RED_MODEL` (Anthropic) or `DEEPSEEK_MODEL` (DeepSeek).

---

## 8. Demo script
1. Dashboard up, quiet; the funnel and consoles streaming.
2. `red_agent.py sqli` → feed lights up red as it probes and finds the injection (or just curl it).
3. Blue fires: Jev flags → (high score) provisional ban now, agent confirms → durable ban + tight
   WAF rule + **email in MailHog**; or (ambiguous) the agent investigates and clears/confirms.
4. Re-run the same attack → **403, blocked**. "Same exploit, now dead."
5. Show breadth: command-injection + XSS classes; `AUTOBLOCK_MODE=divert` to send an attacker to
   the decoy and show `honeypot_hits.jsonl`; `patch_vuln` raising the app's posture; `rotate_secret`.

---

## 9. Known ceilings (demo-grade, each flagged `# ponytail` in code)
| Area | Ceiling | Upgrade path |
|------|---------|--------------|
| Proxy | No TLS, single worker, body buffered in memory | Caddy / nginx + ModSecurity |
| Source IP | Trusts `X-Forwarded-For` | Real network attribution; never trust XFF in prod |
| State | Flat files, whole-file reads | Real event store / DB |
| Control plane | `docker.sock` in the blue container == host root | Actuator sidecar; the LLM container holds no socket |
| Rate limiter | In-memory, no eviction, **not yet wired into the proxy** | Wire the proxy hook; Redis + TTL/LRU at scale |
| Honeypot | One static fake page; shares the data volume | Per-path fakes; internal no-egress network |
| Detection | Classifier + regex can false +/- | Tuned detectors; feedback loop from false positives |
| Red agent | Scoped to one vuln for reliability | Broader autonomy (less stage-reliable) |
| DVWA | Port 80 exposed for proxy + bootstrap | Firewall; never expose publicly |

---

## 10. Possible next steps
- Wire `rate_limit.limited()` into `proxy.py` (after divert/denylist, around the WAF) with a `429`.
- Scripted `curl`/`sqlmap` fallback attacker so the stage demo can't flake on an LLM off-run.
- Broader red-agent objectives (XSS, path traversal, file upload).
- Model tiering / cost controls; persistent incident store and historical dashboard views.
