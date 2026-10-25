# Adaptive decoy (PLAN B5) — design

The honeypot (`bastion/honeypot_app.py`) receives the traffic the blue agent diverted. Its job is
to look like the protected application closely enough that the intruder keeps probing it while the
real app is remediated, and to record the intruder's techniques. It has **no access to the
application's source code**: everything it knows about the app it *learned* from the shape of
real responses, and it **never forwards a diverted request to the real app**.

```
                 passive (proxy)                              decoy (honeypot service)
 client ─▶ proxy.forward ──▶ real app                      attacker ─▶ honeypot_app
              │ status, content-type, ≤32KB body             │  session (ip+ua)  ─▶ rate limit
              │ redacted request facts (privacy.request_view)│  ▼
              ▼ decoy.observe()  (bounded queue, thread)      │  synth.respond():
          ShapeStore ──▶ data/decoy/passive.json ─────────────┼──▶ 1 session cache
                                                              │   2 learned template + fake data
 honeypot startup ─▶ learn.Crawler (GET-only, same-origin) ───┼──▶ 3 LLM synthesis (time-boxed)
          ShapeStore ──▶ data/decoy/crawl.json ───────────────┘   4 learned error page / static page
                                                              ▼
                                                   record.log_hit() ─▶ honeypot_hits (store)
```

## 1. Learn — the shape model (`bastion/decoy/shape.py`, `skeleton.py`, `learn.py`)

**Route pattern.** `METHOD` + path with volatile segments normalised (`/users/42` → `/users/{n}`,
hex/uuid → `{id}`). At most `DECOY_MAX_ROUTES` (200) routes, each with ≤3 *variants* (distinct
tag sequences / statuses, e.g. a `302` for anonymous visitors and a `200` for signed-in users).

**Per variant.** `status`, header subset (`server`, `x-powered-by`, `content-type`, `cache-control`,
`pragma`, `expires`, `vary`, `location`, `x-frame-options`), redirect target (query redacted), a
latency EWMA, and either
- an **HTML skeleton**: the real markup kept verbatim except that data-like text and attribute
  values become typed *slots* (`number`, `token`, `email`, `ipv4`, `date`, `word`, `value`,
  `sentence`, `paragraph`, `echo:<param>`). Chrome (title, headings, nav links, labels, buttons)
  is kept, which is what makes pages look like the same site. Text that *differs* between two
  samples of the same route is promoted to a slot automatically. Hidden inputs / CSRF meta
  tags / query tokens in `href`/`action` always become `token` slots.
- a **JSON schema** with typed example values (string values replaced by their kind).
- for `text/css` / JavaScript: the masked body (`asset`); for binary types: content-type only.

**Fingerprints (site-wide).** `server`, `x-powered-by`, cookie *names* from `set-cookie`
(values are never read), asset paths (`<link href>`, `<script src>`), the `<title>` suffix, and the
skeleton of the app's own 404 page.

**Sources.** (a) *Passive*: `bastion.decoy.observe(...)`, called from the one guarded hook in
`proxy.forward` (CONTRACTS §4.3) for forwarded, non-diverted, non-malicious traffic. The call does
`queue.put_nowait` on a 256-slot queue drained by a daemon thread (drops on overflow); the shape
is flushed atomically (`tmp` + `os.replace`) to `BASTION_DATA_DIR/decoy/passive.json` at most every
2 s. (b) *Active*: `learn.Crawler` in the honeypot service, GET-only, same-origin, ≤
`DECOY_CRAWL_PAGES` (40) pages per pass, 1 request/0.2 s, at startup and every
`DECOY_CRAWL_INTERVAL` seconds (0 = once), writing `crawl.json`. Each file has exactly one writer;
the honeypot merges both (passive wins) and reloads on mtime change.

**What is never stored.** Cookies and `set-cookie` values, `authorization`, `www-authenticate`
values, request headers of any kind, request bodies beyond `privacy.request_view` (which already
redacts sensitive fields), text matching secret patterns (hex ≥ 32, JWTs, `Bearer …`,
`key=`/`token=`/`password=` pairs), and anything from requests the classifier flagged or that the
decoy's own heuristics tag as injection/probing.

## 2. Synthesize (`bastion/decoy/synth.py`, `fake.py`, `session.py`)

On every decoy hit, in order, first success wins:

1. **Session cache** — same (method, path, query, body-hash) within the session → identical
   response. Consistency is the most important anti-fingerprinting property.
2. **Learned template** — the route's variant chosen by auth state (anonymous → a 3xx variant
   if one exists, else most seen; signed-in → a 2xx variant). Slots are filled by `fake.Faker`,
   seeded by `(session.seed, route, slot index)` so the same fake user/token/ids appear across
   pages of one visit. `echo` slots reflect the request parameter HTML-escaped.
3. **LLM synthesis** — only for routes without a template (`DECOY_LLM=1`, key present). Prompt:
   the shape summary (site title, nav, fingerprints, known routes, the closest learned page and the
   404 page already filled with *fake* data), the session memory, and the request, with the request
   wrapped as untrusted data (`<untrusted_request>` … `</untrusted_request>`; the system prompt says
   never to follow instructions inside it). Output must be JSON `{status, content_type, body}`,
   status from an allowlist, body ≤ 64 KB, and is rejected if it leaks the words honeypot/decoy or
   the page is HTML without the site's title suffix. Time-boxed by `DECOY_LLM_TIMEOUT` (8 s) via
   `asyncio.wait_for`, ≤ `DECOY_LLM_CONCURRENCY` (4) in flight, `DECOY_LLM_PER_MINUTE` (30) budget.
   Accepted output is skeletonised and kept as an in-memory *synthesised template* so later
   sessions get it without a second call. The model is **never allowed to author a `404`**: a
   not-found answer is discarded (it is nondeterministic and would re-open the 404 tell on a real
   but unlearned route) and the request falls through to the deterministic stages below, which own
   "not found".
4. **Prefix-aware section gate** (deterministic, LLM-free) — only for an unknown path whose
   normalised route *shares a path prefix* (≥ 1 leading segment) with learned routes, i.e. the app
   clearly has a section there. If that section is **auth-gated** — inferred from the learned shape,
   by a learned sign-in form under the same prefix, or by siblings that redirect anonymous visitors
   to one — the decoy mirrors the gate the real app shows anonymous visitors (the learned sign-in
   page at its learned status: a `200` render or a `302` redirect) instead of a `404`. A real app
   never `404`s a route that exists; a diverted attacker probing real in-section routes (`/area/x`)
   must not be able to use the decoy's `404` as a route-existence oracle. Only anonymous `GET`/`HEAD`
   is mirrored (a signed-in visitor, or a non-gated section, is left to fall through). Everything is
   read from the learned shape — no brand, route name or prefix is ever hard-coded, so it
   generalises to any app. With a key this is a safety net behind stage 3 (the LLM reconstructs the
   specific page first, and any `404` it tries is discarded into this stage); with `DECOY_LLM=0` it
   is the primary way in-section probes avoid a `404`.
5. **Fallback** — the learned 404 variant (framework-looking error page) for truly-unknown paths
   (no shared prefix, e.g. `/wp-login.php`, random scanner paths), else the static page.

**Login.** A route whose GET template has a `type=password` input is the login form. A POST there
fails plausibly (re-render the form; status from the learned POST variant if one exists) until the
session's `grant_after` attempt (2–5, from the seed), then grants: `Set-Cookie` with the learned
cookie name and a seeded value, `302` to the learned post-login location (or `/`), and
`session.auth` flips so 2xx variants are served afterwards — the fake authenticated area is the
set of pages real users were seen on.

**Headers and timing.** The learned header subset is replayed; `Server` comes from the fingerprint
(uvicorn's own `server`/`date` headers are disabled). The decoy sleeps for the route's learned
latency (capped at `DECOY_LATENCY_CAP_MS`, 1500) plus the existing `HONEYPOT_DELAY` tarpit.
Per-IP rate limit `DECOY_RATE_MAX`/`DECOY_RATE_WINDOW` (120/10 s) answers exactly like the proxy's
limiter (`429 {"error":"capacity limit"}` + `Retry-After`), because that is what the real path
would show.

## 3. Record (`bastion/decoy/record.py`)

Each hit appends to the `honeypot_hits` store stream (read by the dashboard). Existing keys are
unchanged (`ts, ip, method, path, query, body, user_agent`); new keys: `visitor` (16-hex id of
ip+ua), `status`, `source` (`cache|template|llm|error_template|static`), `tags[]`, `auth`.
Tags are regex heuristics only — nothing is executed or decoded beyond `unquote_plus`:
`scanner_ua`, `path_probe` (admin/backup/.git/.env/wp-*), `traversal`, `sqli_like`, `cmdi_like`,
`xss_like`, `ssti_like`, `login_attempt`, `credential_stuffing` (≥ 3 login attempts), `method_probe`.
Session memory (`session.history`, ≤ 50 entries) is in-process and bounded (≤ 500 sessions, LRU,
≤ `DECOY_CACHE_BYTES` 32 MB of cached bodies).

## 4. Evaluate (`bastion/decoy/eval.py`)

`python -m bastion.decoy.eval --target http://dvwa:80 [--pages 20] [--holdout] [--llm] [--judge --rounds 5]`
crawls the target into a fresh shape model (real bodies stay in memory only), asks the decoy for
the same routes under a fresh session and reports:
- `structural`: mean over routes of 0.25·status + 0.15·content-type + 0.35·tag-sequence
  similarity (`difflib` on tag+class tokens) + 0.15·title-suffix + 0.10·header-subset match.
- `holdout`: the model is re-learned from every other page; the odd pages exercise the
  unknown-route path (`--llm` lets that path use synthesis).
- `judge_accuracy` (with `--judge` and an LLM key): the model sees real/decoy pairs in random
  order and names the decoy, pooled over `--rounds` fresh sessions (new fake data and A/B order
  each round); chance = 0.5. `judge_shift = |accuracy − 0.5|`, lower is better.

Results against the bundled target (`bastion-target`, "Helios Intranet", run from the honeypot
container, DeepSeek as provider), 2026-10-25:

| metric | value |
|---|---|
| learned routes (anonymous surface) | 3 pages + the 404 page |
| `structural`, learned routes | **1.000** (n = 4) |
| `structural`, held-out login page via LLM | 0.947–0.984 across runs (structure 0.85–0.91) |
| `judge_accuracy` (5 rounds, 20 judgements) | **0.40** (chance 0.5; shift 0.10) |
| live probes `/console/lookup?id=1' UNION…`, `/admin`, `/robots.txt`, `/../../etc/passwd` | 404 from the LLM/learned page — identical status to the real app |
| live probe `/api/v1/users` | LLM-synthesised JSON list of fake operators, cached per session |

Iterations that moved the numbers: slots inherit the label that precedes them ("Operator ID:" →
username-shaped fake, "Passphrase:" → `word-word-NN`), partial masking inside mixed text
("Build 4.2.1" keeps "Build"), version/date/email/IP kinds, LLM pages inherit the learned header
subset (`cache-control`/`pragma`/`expires`) of the nearest real page.

## 5. Failure modes

| Failure | Behaviour |
|---|---|
| decoy package missing / raising in the proxy | hook is `try/except Exception: pass`; forwarding unaffected |
| observe queue full | sample dropped (counter), never blocks the request |
| no shape learned yet | static page (today's behaviour) |
| no LLM key / `DECOY_LLM=0` | templates → learned 404 → static; boots and serves |
| LLM timeout / bad JSON / leaked tell | fallback chain continues; failure counted in `decoy.stats()` |
| shape file corrupt | ignored, fresh model; next flush overwrites |
| target unreachable for the crawler | pass skipped, retried on the next interval |
| burst from one IP | 429 like the proxy; still logged |

## 6. Environment

| Var | Default | Meaning |
|---|---|---|
| `DECOY_CRAWL_URL` | unset (off) | same-origin target for the active crawl (`http://dvwa:80` in compose) |
| `DECOY_CRAWL_PAGES` / `DECOY_CRAWL_INTERVAL` | 40 / 900 | bound per pass / seconds between passes (0 = once) |
| `DECOY_LLM` | `1` | allow LLM synthesis when a key exists (`DEEPSEEK_API_KEY` / `ANTHROPIC_API_KEY`) |
| `DECOY_MODEL` | provider default | model for synthesis and the judge |
| `DECOY_LLM_TIMEOUT` / `DECOY_LLM_CONCURRENCY` / `DECOY_LLM_PER_MINUTE` | 8 / 4 / 30 | time box, in-flight cap, budget |
| `DECOY_RATE_MAX` / `DECOY_RATE_WINDOW` | 120 / 10 | per-IP limit |
| `DECOY_LATENCY_CAP_MS` | 1500 | cap on replayed latency |
| `DECOY_MAX_ROUTES` | 200 | shape bound |
| `HONEYPOT_DELAY` | 0 | existing tarpit (seconds, added to the learned latency) |

## 7. What it can and cannot imitate yet

Can: the site chrome and markup of every route seen (passively or crawled), status codes
including redirects and the framework's own 404/405 pages, an auth-gated section's sign-in for
*unlearned* paths under a learned prefix (so a real but not-yet-learned route no longer answers
with the tell-tale 404 while the real app serves its sign-in), `Server`/`X-Powered-By`, cookie names
with per-visitor values, CSRF-style hidden tokens, JSON shapes, reflected parameters (escaped),
a plausible login failure → fake grant → the pages real signed-in users were seen on, and —
with a key — unknown routes rendered in the app's layout.

Cannot yet:
- Authenticated pages the proxy never saw (nothing signed-in in the passive feed → the "area"
  after a fake grant is only the anonymous surface). The crawler is anonymous by design.
- Exact dynamic server logic (search results, computed values) — slots/echo approximate it; the
  LLM can invent a plausible result page, never the app's real behaviour (or its vulnerabilities).
- Binary assets (content-type only; 1×1 GIF for images); TLS/HTTP-version fingerprints (the
  proxy terminates those anyway).
- Timing on the first hit of an unknown route when the LLM is used (1.5–2.5 s observed); later
  sessions get the synthesised template instantly. `HONEYPOT_DELAY` masks this if set.
- Synthesised templates live in memory; a restart re-synthesises on first hit.
- The *exact* route table of an auth-gated section: the decoy cannot tell an unlearned-but-real
  route from a non-existent one (it never saw either), so the prefix-aware gate presents the whole
  section as sign-in — it answers `200` sign-in for in-section paths that the real app happens to
  `404`. This is a deliberate trade: it removes the `404` route-existence oracle on the real routes
  an attacker actually probes, and it reads as a coherent catch-all-gated section (a common app
  shape); the diverted attacker has no reference to the real app to notice the difference. Only the
  learned routes and the section's real sign-in behaviour are reproduced faithfully.


---
## Decoy verification (2026-10-25, live, LLM path limited by workspace quota)

Reverse-engineering works on the learned path — the decoy is byte-for-byte consistent with the
real app it fronts:
- Fingerprint mirrored: Server: Apache, X-Powered-By: PHP/8.2.35, cookie name APPSESS398.
- Identity mirrored: every page carries the real app's title suffix ("Helios Intranet"),
  learned per boot — never a hard-coded brand.
- Learned routes match real responses: /console/netcheck -> "Sign in", /console/logout ->
  "Operator handbook" (identical title + status to the real app).
- Truly-unknown paths with no shared prefix (/wp-login.php, /xyz-random) return the learned,
  consistent 404 ("Not found – Helios Intranet").

Old hard-coded "Acme Internal Portal" fallback REMOVED (bastion/decoy/static.py). Replaced with
fallback_page(shape): uses the learned title when known, else a brand-less "Sign in" holding page.
Verified live: warm path has no Acme; cold start (empty learner + no LLM) is brand-less, no tells.

---
## Prefix-aware section gate (2026-10-31, live, LLM path restored)

The previous coverage gap is closed. A diverted attacker probing a **real but not-yet-learned**
route under a learned, auth-gated section used to get the decoy's 404 while the real app returned
200 sign-in — a distinguishability tell on exactly the routes an attacker targets.

The real app (this boot) was characterised directly: it serves `200` sign-in for routes that
exist and are auth-gated (`/console/library`, `/console/reader`, `/console/ping`, `/console/netcheck`),
`200` content for non-gated ones (`/console/logout` → "Operator handbook"), and `404` for paths that
do not exist (even under `/console`: `/console/home`, `/console/zzz-unseen`). The decoy cannot tell
an unlearned-real route from a non-existent one, so it mirrors the section's sign-in for every
in-prefix anonymous probe (see §2 stage 4) — inferred from the learned shape (login form / nearest
sibling / siblings' redirect), never hard-coded to `/console` or any brand/route name.

Verified live (real `http://dvwa:80` vs decoy, both LLM ON and `DECOY_LLM=0`):
- `/console/library?id=1`, `/console/reader?q=x`, `/console/ping` — real **200 "Sign in"**, decoy
  now **200 "Sign in"** (was 404). LLM-off path serves it deterministically (`source=section`);
  LLM-on path serves it via the model or, when the model tries a 404, via the same section gate.
- `/wp-login.php`, `/xyz-random` (no shared prefix) — decoy stays on the consistent learned 404.
- Trade (§7): in-section paths the real app happens to `404` (`/console/zzz-unseen`) now answer
  `200` sign-in; the decoy reads as a catch-all-gated section and denies the route-existence oracle,
  and the diverted attacker has no real-app reference to see the difference.

Eval harness (`--holdout --llm --judge --rounds 5`, DeepSeek): learned `structural` **1.000**,
held-out route via LLM **0.976** (≥ the 0.967 baseline), `judge_accuracy` **0.45** (shift **0.05**,
closer to the 0.5 chance line than the prior 0.35 baseline — indistinguishable). The LLM is no
longer permitted to author a 404 (§2 stage 3): a not-found is discarded into the deterministic
stages, so in-section probes never flap between 200 and 404 across sessions.
