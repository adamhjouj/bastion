# Bastion dashboard — frontend page contract

Binding for every frontend agent. Read `docs/CONTRACTS.md` first (hard rules, file ownership,
API contracts) — this file adds the frontend specifics. Edit ONLY the files in your ownership
row. Another agent owns each sibling file concurrently.

## Module contract
`export function mount(root, ctx) { … ; return unmount; }`
- `ctx = {sub, query}` from the hash router (`#/incidents/123` → `sub="123"`); tolerate `ctx` undefined.
- `root` is empty. Append `<div class="page p-<X>">` and build inside it. Scope ALL CSS under `.p-<X>`.
- `unmount()` must clean up everything (store unsubscribe, logStream close, clearInterval).
  Optionally attach `unmount.navigate = ({sub, query}) => …` to handle sub-path changes in place.
- Pages import from `../core.js`: `el, clear, clip, humanize, fmt, fmtScore, clamp, smooth, hhmmss, anim,
  api, post, makeStream, store, controls, logStream, openIncident, closeDrawer, reduceMotion, API`.
  `api(path)`/`post(path, body)` prepend `/__api/v1`; `store.subscribe(fn)` → unsub (fn called immediately
  with the latest snapshot); `makeStream(container, cap, makeNode)` incremental newest-first list
  (`syncNewestFirst(items)` with stable `.k`, `appendAscending(entries, reset)`, `reset()`).

## CSP (strict: default-src 'self'; script-src 'self'; style-src 'self')
No inline `<style>`/`<script>`, no `style=""` attributes, no external fonts/scripts. Dynamic styles via
`element.style.setProperty` / classList; dynamic text via `textContent` (use `el()`); `innerHTML` only
for static markup you author. Everything in `<X>.css`.

## Design direction — data-terminal (tasteskill v2 app sheet)
A monitoring console read in long sessions. Flat, quiet, honest.
- **Surfaces:** `--ground #0b0b0d`, `--surface #121214`, `--raised #17171a`, `--sunk #0e0e10`; separation by a
  1px `--line` hairline or one tone step. **No gradients, glass, backdrop-blur, shadows at rest, glows.**
  Radius 6px on panels/controls (8px on graph nodes). Shadow only on true overlays (the drawer).
- **Type:** Public Sans (text) + JetBrains Mono (every figure, id, path, time; `tabular-nums`), self-hosted
  in `frontend/fonts/`. Sizes: title 13–15 / body 12.5–13 / small 11–12. **Nothing under 11px. No tracked
  uppercase labels** (sentence case, `--t-40`). Two greys that read apart: `--t-56` secondary, `--t-40` meta.
- **Colour budget:** orange `--heat` (#fa5d19) **only on data/status** — malicious verdicts, high/critical
  severity, rejected/error outcomes, the active campaign, the threat beam. Never on chrome, buttons, nav,
  headings. Green `--pos` = healthy/ok/verified; `--neg` = failure/integrity broken. Everything else neutral.
- **Components (global, reuse):** `.panel/.panel-head/.count/.panel-body/.empty`, `.row/.row-top/.row-type/
  .row-time/.row-sub`, `.sev[data-sev]`, `.line/.label(.act)/.text(.cmd/.sys)/.meta` (trace lines),
  `.kpi/.kpi-label/.kpi-val`, `.btn(.danger)/.ghost/.icon-btn/.cap/.tag`, `.kv`, `.mini`, `.status-pill`,
  `.evidence`, `.prose`. Buttons are outlined neutral; one filled primary at most per screen.
- **Information:** the screen's one question is answered by its biggest block; every block shares the
  screen's edges (no dead bands, no stretched empties); zeros print as `0`, missing as `—`; numbers
  right-aligned/tabular; words of the trade in labels ("Banned 203.0.113.9", not "Action executed").
  Client-facing only: no infra telemetry (freshness ages, container names) unless it changes what the
  operator should do.
- **Motion:** feedback only (hover/press/focus, row arrival ≤220ms ease-out). Honour `reduceMotion`
  (from core.js) for JS animations and `prefers-reduced-motion` in CSS. The Overview canvas is telemetry
  and keeps running under reduced motion — do not change `createScene`.
- **Gate:** `node /tmp/taste-skill/skills/taste-skill/scripts/lint.mjs --app frontend/` → **0 FAIL**
  (WARNs for mono/overlay-shadow are accepted). Rules: `/tmp/taste-skill/skills/taste-skill/references/app-screens.md`.

## Data (snapshot) — see docs/CONTRACTS.md §2 for the full shape
`events[]`, `actions[]` (kind triage|action|error; after BE-rollback lands each action carries
`reversible`, `reverted_by`, `reverts`; after BE-audit lands `audit:{prev,hash}`), `incidents[]`,
`funnel{}`, `denylist[]`, `honeypot[]`, `vpatch[]`, `health{}`, totals. Endpoints: `/incidents?before=&limit=`,
`/incidents/{id}` → `{incident, requests[], actions[], notifications[]}`, `/actions?case_id=`,
`/actions/{id}`, `POST /actions/{id}/rollback`, `/rollback/capabilities`, `/audit/verify`, `/audit/head`,
`/logs/{source}/stream`, `/control/*`. **Degrade gracefully:** if a new endpoint 404s, hide the feature.

## Deploy + test (no image rebuild, never restart the proxy)
- `TOK=$(grep '^MANAGEMENT_TOKEN=' .env | cut -d= -f2)`; dashboard `http://localhost:8080/__dash`.
- Deploy ONLY your own files: `docker cp frontend/pages/<X>.js bastion-proxy-1:/app/frontend/pages/<X>.js`
  (same for `.css`, `core.js`, `index.html`, `app.*` if you own them). Never cp the whole directory.
- Headless: `node` + `/Users/user/Desktop/soon/bastion/node_modules/playwright`;
  `newContext({ httpCredentials:{username:'admin',password:TOK}, viewport:{width:1440,height:900},
  deviceScaleFactor:2, colorScheme:'dark', reducedMotion:'reduce' })`; `goto(..., {waitUntil:'load'})`
  then `location.hash` + `waitForSelector('.p-<X>')`. **Never `networkidle`** (SSE holds the connection).
  Write scripts to files (inline quoting breaks). Use `context.route(...)` to fulfil contract responses for
  endpoints the backend hasn't shipped yet (`/__api/v1/stream` as `text/event-stream` with `event: snapshot`).
- Free traffic: `curl -s -o /dev/null http://localhost:8080/` (benign) and
  `curl -s -o /dev/null "http://localhost:8080/s?id=1%27+OR+%271%27=%271"` (classified malicious in ~5s).
  Campaigns (`/control/run`) are real LLM runs — allowed, but not needed for layout work.
- Verify: rich render + empty states, zero console/page errors, reduced motion, 1440/1024/768 (+390 for
  Overview/Attacker), clean unmount (navigate away and back), lint 0 FAIL. View your own screenshots.
- Clean up /tmp artifacts. End with `STATUS: done|partial|blocked` + evidence.
