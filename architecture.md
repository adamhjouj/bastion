# Architecture — Breach Agent (as built)

Autonomous blue-team breach damage-control system over DVWA, with a scoped
autonomous red-team agent and a live SOC dashboard. This document describes
**what actually exists in this repo**, file by file, plus the data flow, the
verified behavior, and the known demo-grade ceilings.

Status legend: ✅ verified running · 🔑 implemented, needs an `ANTHROPIC_API_KEY` to run live.

---

## 1. What it does

A reverse proxy sits in front of DVWA and is **both the log source and the
enforcement point**. A blue-team agent tails that log, a cheap regex pre-filter
decides what is worth an LLM call, then Claude classifies suspicious traffic and
calls tools to **blacklist the attacker's IP**, **add a virtual-patch WAF rule**,
and **email an incident report**. Re-running the same attack then returns `403`.
A scoped red-team agent (Claude) discovers and exploits one named vulnerability
through the proxy, so the blue side sees real attack traffic on stage.

One-line pitch: *"We built a container simulating a live web app. An agent
autonomously found an exploit. Here's how our product detected it, shut the
attacker down, virtually patched the hole, and emailed us — live."*

---

## 2. System diagram

```
                           ┌──────────────────────────────────────────────┐
  ┌───────────────┐  HTTP  │              proxy.py  (:8080)                │  httpx  ┌────────────┐
  │  red_agent.py │───────▶│  source_ip() = X-Forwarded-For or client host │────────▶│ DVWA (:80) │
  │   (Claude)    │  XFF=  │  1. IP in denylist?            → 403          │◀────────│  docker    │
  │               │ attacker  2. decoded probe matches WAF? → 403          │         └────────────┘
  └───────────────┘  IP    │  3. forward, return response                  │
          ▲                │  4. append record → data/events.jsonl         │
          │ http_request   │  reads data/state.json each request (mtime-cached) │
          │ tool           └───────────────┬──────────────────────────────┘
          │                                │ events.jsonl (append-only)
          │                                ▼
          │                ┌──────────────────────────────────────────────┐
          │                │          blue_agent.py (loop)                 │
          │                │  tail events → regex pre-filter → Claude      │
          │                │  (tools) → execute → mutate state / email     │
          │                └───────────────┬──────────────────────────────┘
          │        ┌──────────────┬─────────┴────────┬───────────────────────┐
          │        ▼              ▼                  ▼                       ▼
          │  do_blacklist_ip  do_add_waf_rule   do_raise_alert         (append)
          │  → state.json     → state.json      → SMTP (MailHog :1025)  incidents.jsonl
          │                                       → incidents.jsonl
          │                                │
          │                                ▼
          └──────  dashboard.html  ◀──  GET /__state  (polled every 1.5s)
```

Everything shares three flat files under `data/`. No database, no queue.

---

## 3. Components (file by file)

### `store.py` ✅  — shared flat-file state
The single source of truth for paths and I/O, imported by the proxy, the blue
agent, and the test.
- `STATE_FILE = data/state.json`, `EVENTS_FILE = data/events.jsonl`, `INCIDENTS_FILE = data/incidents.jsonl`.
- `load_state()` — parse `state.json`; on missing/corrupt JSON returns a fresh
  `DEFAULT_STATE` copy (`{"denylist":[], "rules":[], "seen_ips":{}}`).
- `save_state(state)` — **atomic**: writes a `.tmp` then `os.replace()`, so the
  proxy never reads a half-written file.
- `append_jsonl(path, obj)` / `read_jsonl(path, limit=None)` — append-only log I/O
  (bad lines skipped on read).
- `now()` — UTC ISO-ish timestamp.
- `# ponytail`: whole-file reads + atomic replace; swap for a real event store at volume.

### `proxy.py` ✅  — reverse proxy = log source + enforcement point
FastAPI app forwarding to DVWA via an async `httpx` client. Three explicit routes
registered before the catch-all (registration order wins in Starlette):
- `GET /__dashboard` → serves `dashboard.html`.
- `GET /__state` → JSON for the dashboard: last 200 events (reversed), all
  incidents (reversed), current denylist, current rules.
- `ANY /{path:path}` → the proxy itself.

Per-request logic in the catch-all:
1. **`source_ip()`** — uses `X-Forwarded-For` if present, else the socket peer.
   This is how the "external attacker" gets a distinct IP (`10.13.37.7`) from
   localhost browser traffic on a single-host demo.
   `# ponytail: trust XFF for demo only — NEVER in production.`
2. **Decode** the query string and body with `unquote_plus` to build `probe`
   (used for WAF matching) and the logged event fields. **This was a real bug
   found during the build:** the proxy originally logged URL-encoded text
   (`%27`), so both the WAF regexes and the blue agent's pre-filter would miss
   encoded payloads. Forwarding to DVWA still uses the **original** encoded bytes
   (`params=dict(request.query_params)`, `content=body`), so the exploit is
   unaltered upstream.
3. **IP denylist** check → `403` + logged `blocked` event (`matched:"denylist"`).
4. **WAF rules** — each rule's compiled regex is tested against `probe`; first
   match → `403` + logged event (`matched:<description>`).
5. Otherwise **forward** (hop-by-hop headers stripped both ways), log the real
   upstream status, return the response. Upstream errors → `502`.

Rule compilation is cached and refreshed only when `state.json`'s mtime changes,
so blue-agent writes take effect within one request with no restart.

### `blue_agent.py` 🔑  — detection & response loop
A standalone process (not inside the proxy — keeps slow LLM calls out of the
request path).
- **`main()`** polls `events.jsonl` every 1s from an offset, starting at the
  current end so a restart doesn't replay history.
- **Pre-filter** `is_suspicious(ev)` — one case-insensitive regex over
  path+query+body covering SQLi / command-injection / traversal / XSS tokens
  (`union\s+select`, `or 1=1`, `;`, `|`, `$(`, backticks, `/etc/passwd`, `../`,
  `<script`, …). Only matches reach Claude, which is what makes "24/7" cheap.
  Already-blocked IPs are skipped (cool-down), so one attack ≠ an alert storm.
- **`analyse(client, events)`** — sends the suspicious batch + the current
  defenses to Claude (`claude-sonnet-5`, `output_config={"effort":"low"}`,
  `max_tokens=4096`) with three tools, runs a manual tool-use loop
  (`stop_reason=="tool_use"` → execute → feed results back → repeat until
  `end_turn`).
- **Tools** (dispatched by name):
  - `do_blacklist_ip(ip, reason)` → append to `state.denylist` (idempotent).
  - `do_add_waf_rule(pattern, description)` → validates the regex compiles, then
    appends to `state.rules`. This is the **virtual patch** — blocks the exploit
    pattern regardless of source IP.
  - `do_raise_alert(severity, attack_type, source_ip, evidence, summary)` →
    append to `incidents.jsonl` **and** `send_email()`.
- **`send_email()`** — `smtplib` to `SMTP_HOST:SMTP_PORT`. With no creds it talks
  to MailHog plain (demo default); with `SMTP_USER`/`SMTP_PASS` it does
  STARTTLS + login (real relay, e.g. Gmail). Mail failures are caught and never
  kill the loop.
- System prompt instructs tight WAF regexes (match payload tokens, not broad
  patterns), no duplicate actions, do-nothing on benign traffic.

### `bootstrap_dvwa.py` ✅  — DVWA auth plumbing (reused)
Removes the #1 demo-day failure (uninitialised DVWA DB).
- **`authed_session(base_url, xff=None)`** → a logged-in `httpx.Client` at
  Security=Low. Scrapes the DVWA anti-CSRF `user_token` from each form, then:
  resets the DB (`/setup.php`), logs in (`/login.php`, admin/password), sets
  security Low (`/security.php` + a `security=low` cookie). `xff` sets
  `X-Forwarded-For` so the red agent's session carries the attacker IP.
- **`verify(base_url)`** → runs a benign SQLi page request and checks for DVWA
  output. `python bootstrap_dvwa.py http://localhost:80` is the health check
  `run.sh` calls (verified: `OK (status 200)`).
- Reused by both `run.sh` (direct to DVWA) and `red_agent.py` (through the proxy).

### `red_agent.py` 🔑  — scoped autonomous attacker
- At import it builds an authenticated session **through the proxy** with
  `X-Forwarded-For=ATTACKER_IP`, so every probe is attributed to the attacker and
  seen by the blue agent. (Auth is plumbing; the agent's job is finding the
  payload.)
- One tool, `http_request(method, path, params, body)`, runs on that session.
- **`run(target)`** — Claude (`claude-opus-5`, `max_tokens=8000`) loops up to 25
  turns under an objective scoped to exactly one endpoint:
  - `sqli` → inject `/vulnerabilities/sqli/` `id` param to dump the users table.
  - `cmdi` → inject `/vulnerabilities/exec/` `ip` param to read `/etc/passwd`.
- Scoped objective = reliable on stage and guarantees the blue side has a matching
  response. `# ponytail: scoped, not general offense — reliability over realism.`

### `dashboard.html` ✅  — judge-facing SOC view
Single self-contained page (inline CSS/JS, no framework, works offline). Polls
`/__state` every 1.5s and renders: counters (requests / blocked / IPs banned /
WAF rules), a live request feed (attack rows red, blocked rows flagged `🛑` with
the matched signature and status), an incident timeline, and an active-defenses
panel (denylist + WAF rules, growing live). A `200 → 403` transition on the same
attack is the visual payoff.

### Supporting files
- `docker-compose.yml` ✅ — `vulnerables/web-dvwa` (:80) + `mailhog/mailhog`
  (SMTP :1025, web UI :8025). Both currently **up**.
- `run.sh` ✅ — `compose up` → wait for DVWA → bootstrap → clear `data/` for a
  fresh demo → start proxy (`uvicorn`) → start blue agent; prints the URLs; traps
  Ctrl-C to tear down.
- `requirements.txt` — `anthropic`, `fastapi`, `uvicorn[standard]`, `httpx`
  (installed: anthropic **2.3.0**, fastapi 0.162, uvicorn 0.54, httpx 0.28).
- `.env.example` — `ANTHROPIC_API_KEY`, URLs, `ATTACKER_IP`, `BLUE_MODEL`,
  `RED_MODEL`, SMTP settings (MailHog defaults).
- `test_pipeline.py` ✅ — the one runnable check (see §6).
- `README.md` — quick start + demo script.

---

## 4. Data schemas (actual fields)

```jsonc
// data/events.jsonl — one object per HTTP request (query/body DECODED)
{ "ts":"2026-10-24T03:15:02Z", "ip":"9.9.9.9", "method":"GET",
  "path":"/vulnerabilities/sqli/", "query":"id=1' OR '1'='1&Submit=Submit",
  "body":"", "status":302, "blocked":false, "matched":null }

// data/state.json — read by proxy each request, written by blue agent
{ "denylist":[ {"ip":"10.13.37.7","reason":"SQLi exfil","ts":"..."} ],
  "rules":[ {"pattern":"union\\s+select","description":"block SQLi UNION","ts":"..."} ],
  "seen_ips":{} }

// data/incidents.jsonl — one per raise_alert (drives timeline + the email)
{ "ts":"...", "severity":"high", "attack_type":"sql_injection",
  "source_ip":"10.13.37.7", "evidence":"GET /vulnerabilities/sqli/?id=...",
  "summary":"Banned IP, added WAF rule." }
```

---

## 5. Request lifecycle

1. Attacker (or browser/curl) hits proxy `:8080`.
2. Proxy resolves source IP (XFF), decodes the request, checks denylist then WAF
   → `403` on a hit (logged as `blocked`), else forwards to DVWA and logs the
   real status.
3. Blue agent reads new events, pre-filters, and on a suspicious batch calls
   Claude with the three tools.
4. Claude's tool calls mutate `state.json` (denylist/rules), append an incident,
   and send the email.
5. Dashboard reflects all of it within ~1.5s.
6. The next request from that IP / matching that pattern is `403` at step 2. Loop
   closed.

---

## 6. Verification status

**Verified running (no API key needed):**
- DVWA bootstrap → `OK (status 200)`.
- Proxy data plane (live curl):
  - benign IP + benign path → `200`
  - denylisted IP → `403` (`matched:"denylist"`)
  - different IP + `UNION SELECT` payload → `403` (`matched:"block SQLi UNION"`)
  - URL-encoded payloads decode correctly in the log and match WAF rules.
- `test_pipeline.py` → **ALL PASSED**: pre-filter classification; full `analyse()`
  with a **stubbed LLM** driving real tool dispatch → `state.json` updated,
  incident recorded, and a **real email delivered to MailHog**.
- `output_config` / `system` / `tools` confirmed accepted by anthropic 2.3.0's
  `messages.create` signature.

**Implemented, needs `ANTHROPIC_API_KEY` to run live (🔑):**
- Blue agent's real Claude *classification* (the dispatch around it is proven;
  only the model's judgment is untested live).
- Red agent actually discovering/exploiting via Claude.

The one self-test: `.venv/bin/python test_pipeline.py` (needs MailHog on :1025).

---

## 7. How to run

```bash
cd ~/breach-agent
cp .env.example .env                 # add ANTHROPIC_API_KEY
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
./run.sh                             # DVWA+MailHog, bootstrap, proxy, blue agent
# second terminal:
.venv/bin/python red_agent.py sqli   # then: red_agent.py cmdi
```
Dashboard `http://localhost:8080/__dashboard` · MailHog `http://localhost:8025` ·
browse the app through the proxy at `http://localhost:8080/`.

Models: `BLUE_MODEL=claude-sonnet-5` (cheap 24/7 classifier), `RED_MODEL=claude-opus-5`
(best at finding the exploit). Both overridable in `.env`.

---

## 8. Demo script
1. Dashboard up, quiet.
2. `red_agent.py sqli` → feed lights up red as it probes and finds the injection.
3. Blue fires: incident appears, attacker IP banned, WAF rule added, **email in MailHog**.
4. Re-run the same attack → **403, blocked**. "Same exploit, now dead."
5. `red_agent.py cmdi` → proves it defends more than one attack class.

---

## 9. Known ceilings (demo-grade, each flagged `# ponytail` in code)
| Area | Ceiling | Upgrade path |
|------|---------|--------------|
| Proxy | No TLS, single worker, body buffered in memory | Caddy / nginx + ModSecurity |
| Source IP | Trusts `X-Forwarded-For` | Real network attribution; never trust XFF in prod |
| State | Flat files, whole-file reads | Real event store / DB |
| Detection | Regex pre-filter + LLM; can false +/- | Tuned detectors; feedback loop from false positives |
| Red agent | Scoped to one vuln for reliability | Broader autonomy (less stage-reliable) |
| DVWA | Port 80 exposed to host for proxy + bootstrap | Firewall; never expose publicly |

---

## 10. Possible next steps
- Scripted `curl`/`sqlmap` fallback attacker so the stage demo can't flake if the
  LLM red agent has an off run.
- Harden the red agent's login handshake (retry/verify) against transient DVWA
  startup races.
- Embed the MailHog inbox in the dashboard via `<iframe>` so the email shows on
  one screen.
- Model tiering: Haiku 4.5 hot-path classify, escalate confirmed hits.
