# Bastion dashboard — page agent contract

You are building ONE page of a CSP-safe ES-module SPA. Read this fully, then read:
`/Users/user/.agents/skills/emil-design-eng/SKILL.md` (apply it), `frontend/core.js`
(exact exports), `frontend/app.css` + `frontend/pages/overview.css` (design tokens +
components to reuse). Overview (`frontend/pages/overview.js`) is the reference for quality.

## Ownership (hard boundary)
Edit ONLY your two files: `frontend/pages/<X>.js` and `frontend/pages/<X>.css`
(X = incidents | investigator | attacker). DO NOT touch any other file — not app.js,
core.js, index.html, app.css, overview.*, or the other pages. DO NOT rebuild/recreate
the docker image. Another agent owns each sibling page concurrently.

## Module contract
`export function mount(root) { … ; return function unmount(){…}; }`
- `root` is an empty container. Append a `<div class="page p-<X>">` and build inside it.
- Subscribe to live data in mount; return an `unmount` that cleans up EVERYTHING
  (store unsubscribe, logStream close, clearInterval). The router calls unmount on nav away;
  leaking intervals/EventSources is a bug — verify by navigating away and back.
- Scope ALL your CSS under `.p-<X>`.

## Imports (from `../core.js`)
`el, clear, clip, humanize, fmt, fmtScore, clamp, smooth, hhmmss, anim, api, post,
makeStream, store, controls, logStream, openIncident, closeDrawer, reduceMotion, API`
- `store.subscribe(fn)->unsub` — fn(snapshot) on every snapshot and immediately with the latest.
  Also `store.latest`, `store.conn`, `store.onConn(fn)`.
- `makeStream(container, cap, makeNode)` — incremental newest-on-top live list:
  `.syncNewestFirst(items)` (each item needs a stable `.k`), `.appendAscending(entries, reset)`, `.reset()`.
- `api(path)` / `post(path, body)` — authed same-origin fetch; base `/__api/v1` is prepended.
- `controls.status() | run(job) | stop() | reset()`.
- `logStream(source, onPage)->close` — SSE container log; onPage receives `{entries:[{id,ts,text,stream}], reset}`.
- `openIncident(id)` — opens the shared incident detail drawer (markup already in index.html).
- `el(tag, cls, text)` builds elements with textContent; `anim(elm, keyframes, opts)` = WAAPI wrapper.

## CSP (strict: default-src 'self'; script-src 'self'; style-src 'self')
NO inline `<style>`/`<script>`, NO `style="…"` attributes. Dynamic styles via
`element.style.setProperty(...)` / `element.style.x` / `classList` only. Dynamic text via
`textContent` (use `el()`), never innerHTML with data. innerHTML is allowed ONLY for static
markup you author (no inline style/script; SVG `fill`/`stroke` presentation attrs are fine).
Put all styling in `<X>.css`.

## Live data shape (snapshot from store.subscribe)
`mode, events_total, incidents_total, blocked_total`;
`funnel{evaluated, flagged, escalated, actions, succeeded}`;
`events[]` (≤200: id, ts, ip, method, path, query, body, content_type, blocked, status,
matched('diverted'|'denylist'|'vpatch'|'rate_limit'|'classifier'|null),
verdict{malicious, malicious_score, attack_type, type_confidence}|null, case_id, processing_status, duration_ms);
`actions[]` (≤200: kind 'triage'|'action'|'error'; triage→{ip,path,jev{malicious,malicious_score,attack_type,type_confidence},escalated,outcome}; action→{tool,input{reason,ip,path,…},result,outcome,case_id}; error→{error,case_id}; all have ts,id);
`incidents[]` (≤50: id, ts, case_id, severity('low'|'medium'|'high'|'critical'), attack_type, source_ip, evidence, summary);
`denylist[]{ip,reason,ts,expires}`, `honeypot[]{ip,reason,ts}`, `vpatch[]{id,path,pattern,attack_type,reason,ts}`;
`enforced_security, health{<name>:{…,ts,age_seconds,stale, ready|available}}, recent_outcomes[],
latest_containment{seconds,case_id}, allow_destructive, notifications[]`.
Endpoints (via api/post): `/incidents?before=&limit=`, `/incidents/{id}` → `{incident, requests[], actions[], notifications[]}`,
`/actions?case_id=&before=&limit=`, `/requests?before=&limit=`, `/notifications`,
`/logs/{source}` + `/logs/{source}/stream` (sources: blue, proxy, dvwa, honeypot, actuator, mail-worker, red),
`/control/status|run|stop|reset`.

## Design system (reuse; match exactly)
Tokens (CSS vars in app.css): `--bg #090909, --bg-2, --line, --line-2, --heat #fa5d19,
--heat-hi #ff8a4c, --text, --t-88…--t-4 (white alpha tiers), --glass, --card-sh, --mono,
--ease-out`. Reusable components (global): `.panel/.panel-head/.count/.panel-body/.empty`,
`.row/.row-top/.row-type/.row-time/.row-sub`, `.sev[data-sev]`, `.line/.label(.act)/.text(.cmd/.sys)/.meta`,
`.kpi/.kpi-label/.kpi-val`, `.btn(.danger)/.ghost/.icon-btn/.cap/.tag(.red)`, drawer styles.
ACCENT DISCIPLINE: orange is reserved for threat/response signal only (malicious, high/critical
severity, escalation, active/running); everything else neutral white tiers. Minimal, self-explanatory
text — no verbose descriptions. The page scrolls internally if needed (the `.content` host is fixed-height; your `.p-<X>` is `height:100%`).

## Deploy + test (NO image rebuild)
- `TOK=$(grep '^MANAGEMENT_TOKEN=' .env | cut -d= -f2)`
- Deploy ONLY your two files (served live via FileResponse):
  `docker cp frontend/pages/<X>.js bastion-proxy-1:/app/frontend/pages/<X>.js`
  `docker cp frontend/pages/<X>.css bastion-proxy-1:/app/frontend/pages/<X>.css`
  Do NOT `docker cp` the whole `frontend/` dir (you'd clobber sibling agents' files).
- Headless: `node` with `/Users/user/Desktop/soon/bastion/node_modules/playwright`,
  `newContext({ httpCredentials:{username:'admin',password:TOK}, viewport:{width:1512,height:945},
  deviceScaleFactor:2, colorScheme:'dark', reducedMotion:'reduce' })`, goto
  `http://localhost:8080/__dash` waitUntil 'load', then `page.evaluate(()=>location.hash='#/<X>')`,
  `waitForSelector('.p-<X>')`. Assert rich render from live data, empty states, zero console/page
  errors, works under reduced motion, and unmount leaks nothing (nav away/back). Clean up /tmp artifacts.
- Need data? curl benign `curl -s -o /dev/null http://localhost:8080/` and injections
  `curl -s -o /dev/null "http://localhost:8080/s?id=1%27+OR+%271%27=%271"`. Attacker page may launch a
  real short campaign via `/control/run` (LLM credits — sparingly; stop after).

## Output
Concise report: what you built, data/components used, verification evidence (screens/errors), and any
assumptions. Do NOT bake the image (the parent bakes all pages together at the end). Stop/ask if the
contract or data is insufficient rather than editing shared files.
