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
   sessions get it without a second call.
4. **Fallback** — the learned 404 variant (framework-looking error page), else the static page.

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
including redirects and the framework's own 404/405 pages, `Server`/`X-Powered-By`, cookie names
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
