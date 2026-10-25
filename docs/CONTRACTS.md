# Bastion — agent contracts (ownership, APIs, rules)

Read `PLAN.md` first for the product thesis and workstreams. This file is the binding
contract for every agent working in parallel on this repo. **If something here blocks you,
stop and report rather than editing a file you do not own.**

## 0. Hard rules (everyone)

1. **Edit only the files you own** (§1). Create new files only inside your owned paths.
2. **Never run git write commands** (no commit, stash, checkout, reset, rebase, clean). The
   working tree holds an uncommitted restructure; read-only `git diff`/`git status` is fine.
3. **Never rebuild or restart the `proxy` container** (`docker compose build/up/restart proxy`):
   every other agent tests against it live. The parent rebuilds once at the end.
   The honeypot agent MAY rebuild/restart only the `honeypot` service.
4. **Backend testing = pytest on the host**, isolated per test by `tests/conftest.py`
   (temp data dir). Run: `.venv/bin/python -m pytest -q tests/<your tests> ` and the full
   non-docker suite before you finish:
   `.venv/bin/python -m pytest -q --ignore=tests/test_docker_dashboard.py --ignore=tests/test_docker_logs.py --ignore=tests/test_score_campaign.py --ignore=tests/test_benign_eval.py`
   Baseline: 234 passed. **You may not leave it red.**
5. **Frontend testing = live proxy + Playwright** (see `frontend/pages/AGENT_CONTRACT.md`).
   Deploy ONLY your own files: `docker cp frontend/<file> bastion-proxy-1:/app/frontend/<file>`.
   Never `docker cp` the whole `frontend/` dir.
6. **Append-only audit truth.** No code path may UPDATE or DELETE a `records` row of
   `kind='actions'` (it is hash-chained). Any state change is a *new* record.
7. **Untrusted data stays data.** Request paths/bodies/log text are attacker-controlled: never
   execute, never interpolate into shell/SQL/HTML, always `textContent` in the UI, always
   pass through `bastion.privacy.redact` before persistence/LLM prompts where the codebase does.
8. **No fabricated proof** anywhere (customers, quotes, stats). Sample data is labelled as such.
9. End your final report with a single line `STATUS: done` | `STATUS: partial` | `STATUS: blocked`
   followed by what shipped, what was verified (commands + results), and anything the parent
   must do at integration (e.g. "rebuild proxy", "set env X").

## 1. Ownership matrix (disjoint — the parent owns everything not listed)

| Agent | Owns (edit/create) | Must NOT touch |
|---|---|---|
| **BE-rollback** | `bastion/rollback.py` (new), `bastion/dashboard_api.py`, `bastion/dashboard_data.py`, `tests/test_rollback.py` (new) | `store.py`, `blue_agent.py`, `proxy.py` |
| **BE-audit** | `bastion/audit.py` (new), `bastion/store.py`, `tests/test_audit.py` (new) | `dashboard_api.py`, `proxy.py` (router already wired: `bastion.audit.router`) |
| **BE-honeypot** | `bastion/honeypot_app.py`, `bastion/decoy/**` (new package), `tests/test_honeypot.py`, `tests/test_decoy*.py` (new), `docs/DECOY.md` (new), `docker-compose.yml` **honeypot service block only**, `requirements.txt` (minimal, documented), and **one** minimal guarded observe-hook in `bastion/proxy.py` (§4.3) | `dashboard_*`, `store.py`, `blue_agent.py`, `honeypot_tools.py` |
| **BE-report** (phase 2) | `bastion/notifications.py`, `bastion/mail_worker.py`, `tests/test_notifications.py` | `blue_agent.py` (keep `prepare_message(incident)` signature compatible) |
| **FE-incidents** | `frontend/pages/incidents.js`, `frontend/pages/incidents.css`, `frontend/core.js` (drawer section only; keep every export backward compatible) | other pages, shell files |
| **FE-investigator** | `frontend/pages/investigator.js`, `frontend/pages/investigator.css` | everything else |
| **FE-overview** | `frontend/pages/overview.js`, `frontend/pages/overview.css`, `frontend/index.html`, `frontend/app.js`, `frontend/app.css` | other pages, `core.js` |
| **Marketing** | `site/**` (new, standalone static site) | the app entirely |

Shared read-only references: `bastion/llm.py` (LLM client), `bastion/privacy.py`, `bastion/actuator_client.py`.

## 2. Data model you can rely on

- Store: `bastion/store.py`, SQLite WAL, table `records(id, kind, ts, data JSON, status, case_id, …)`.
  `kind ∈ {events, actions, incidents}` plus an outbox. Public helpers: `store.append_jsonl(store.ACTIONS_FILE, obj)`
  (inserts an `actions` record; **the only sanctioned way to write an action**), `store.connect()`,
  `store.state_lock`, `store.load_state()/save_state()`, `store.now()`.
- Action record `data` (written by `blue_agent.record_action`):
  `{ts, kind:'action'|'triage'|'error', tool, input, result, outcome:'ok'|'rejected'|'error', case_id}`.
  Triage rows: `{kind:'triage', case_id, ip, path, jev{malicious, malicious_score, attack_type, type_confidence}, escalated, outcome}`.
- Incident `data`: `{ts, case_id, severity, attack_type, source_ip, evidence, summary}`; `case_id` may be a comma list of event ids.
- Snapshot (`GET /__api/v1/overview`, SSE `/__api/v1/stream` event `snapshot`): `events[]≤200, actions[]≤200, incidents[]≤50, events_total, blocked_total, diverted_total, incidents_total, funnel{evaluated,flagged,escalated,actions,succeeded}, denylist[], honeypot[], vpatch[], health{}, mode, …`. Records carry their row `id`.
- Existing reverse operations: `POST /__api/v1/defenses/unban {ip}`, `POST /__api/v1/defenses/undivert {ip}`
  (dashboard_api.py); `blue_agent.do_unban_ip`; actuator `release_container`, `reconnect_egress`
  (privileged — the proxy has **no Docker socket**; call them via `bastion.actuator_client.call_tool(name, params)`);
  `remediation_tools.patch_vuln(level)` lowers/raises the virtual-patch level (via the actuator).

## 3. API contracts (new) — frontend builds against these; backend implements exactly these

### 3.1 Rollback (BE-rollback → consumed by FE-incidents, BE-report)
Annotate every action record returned by `/__api/v1/actions`, `/__api/v1/incidents/{id}.actions` and the snapshot with:
```
reversible: boolean        // tool has an inverse AND kind=='action' AND outcome=='ok' AND not yet reverted
reverted_by: int|null      // id of the compensating action, derived from records whose input.reverts == this id
reverts: int|null          // on a compensating action: the id it reverts
```
Endpoints (prefix `/__api/v1`, auth inherited):
```
GET  /actions/{id}                 -> 200 {item: <annotated action>} | 404
POST /actions/{id}/rollback        body {reason?: string}
     -> 200 {ok:true, reverted:<id>, action:<new compensating action, annotated>}
     -> 404 unknown | 409 {ok:false, error} (not reversible / already reverted / original not ok)
     -> 502 {ok:false, error, action} when the inverse operation failed downstream
        (the failed attempt is STILL recorded as an action with outcome 'error')
GET  /rollback/capabilities        -> 200 {inverse: {"blacklist_ip":"unban_ip", ...}, irreversible:[...]}
```
Inverse map (minimum): `blacklist_ip→unban_ip`, `bulk_blacklist_ip→unban_ip (each ip)`, `divert_to_honeypot→undivert`,
`virtual_patch→remove/restore` (restore prior level or remove the vpatch rule — whichever the code supports; document it),
`quarantine_container→release_container`, `isolate_egress→reconnect_egress`, `kill_process/kill_session→irreversible`,
`rotate_secret→irreversible`, read-only tools→not applicable.
The compensating action is written with `store.append_jsonl(store.ACTIONS_FILE, {ts, kind:'action', tool:'rollback',
input:{reverts:<id>, tool:<original tool>, inverse:<inverse tool>, reason, ...params}, result, outcome, case_id:<same case>})`
so it enters the hash chain. **Never mutate the original row.**

### 3.2 Audit / tamper-evident log (BE-audit → consumed by FE-investigator, BE-report)
Every `actions` record `data` gains, at insert time, inside the same `BEGIN IMMEDIATE` transaction:
```
audit: { prev: <hex sha256 of previous chained record | "0"*64 for genesis>, hash: <hex sha256> }
hash = sha256( prev + "\n" + canonical_json(data_without_audit) )   canonical = json.dumps(sort_keys=True, separators=(",",":"), ensure_ascii=False)
```
Chain order = `records.id` ascending over `kind='actions'`. Legacy rows without `audit` form an *unchained prefix*
(reported, not failed). Python API: `audit.head() -> {length, head}`, `audit.verify() -> dict below`.
Router `bastion.audit.router` (APIRouter, prefix `/__api/v1/audit`) — already included by `proxy.py`:
```
GET /audit/head    -> {length:int, head:hex|null}
GET /audit/verify  -> {intact:bool, length:int, head:hex|null, unchained:int, broken_at:int|null, checked_at:iso}
```

### 3.3 Frontend routing (parent shipped in app.js)
`#/<page>/<sub…>` → `mount(root, {sub, query})`; a page may return `unmount` with an attached
`unmount.navigate({sub, query})` to handle in-place sub-path changes. Deep link to a case file:
`#/incidents/<incident_id>`. Pages must tolerate a missing `ctx` (`mount(root)`).

### 3.4 Report deep link (BE-report)
`PUBLIC_DASHBOARD_URL` (env, default `http://localhost:8080`) → `${PUBLIC_DASHBOARD_URL}/__dash#/incidents/<incident_id>`.
No unauthenticated action links in email — the link opens the (authenticated) case file where Revert lives.

## 4. Workstream briefs (details live in the agent task; this is the shared skeleton)

### 4.1 Degrade gracefully across the seam
Frontend features that depend on §3.1/§3.2 **hide themselves** when the endpoint returns 404
(backend not deployed yet) and are tested with Playwright `context.route` fulfilling the contract.
Backend modules import each other defensively only across workstreams (`try: from bastion import audit`).

### 4.2 Design system (frontend)
Direction: **data-terminal** (tasteskill app sheet) — flat dark surfaces, hairline separation,
Public Sans + JetBrains Mono figures (self-hosted in `frontend/fonts/`), **orange `--heat` only on
data/status (threat, severity, active campaign), never on chrome**. Green `--pos` = healthy/ok,
`--neg` = failure. No gradients, glass, blur, shadows at rest, glows, tracked uppercase labels,
icons in tinted squares. Gate: `node /tmp/taste-skill/skills/taste-skill/scripts/lint.mjs --app frontend/`
must report **0 FAIL**. Rules: `/tmp/taste-skill/skills/taste-skill/references/app-screens.md`.
Full frontend contract: `frontend/pages/AGENT_CONTRACT.md`.

### 4.3 Honeypot observe-hook rule (BE-honeypot only)
If passive learning needs the proxy, add exactly one call site in `bastion/proxy.py`'s forward path,
wrapped in `try/except Exception: pass`, non-blocking (fire-and-forget / bounded queue), that passes
only redacted request facts + response status/content-type/≤N KB body to `bastion.decoy.observe(...)`.
The proxy must boot and serve with the decoy package absent or failing. Unit-test the hook.

## 5. Integration (parent, after all agents land)
Rebuild `proxy` + `honeypot` (+ `blue`, `mail-worker` if their modules changed), run the full suite,
remove the import guard around `audit_router`, walk every route headlessly, exercise rollback + verify
end-to-end, re-run the taste lint, and only then report.
