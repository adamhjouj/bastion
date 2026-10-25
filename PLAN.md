# Bastion — Implementation Plan

> Autonomous blue‑team agent that fronts **any** web app, classifies every request with a
> zero‑shot model (no training), and on attack takes **least‑risk** containment + remediation
> on its own — writing every action to a **tamper‑evident log you can roll back**, and emailing a
> human‑readable incident report. A first responder, not a permanent fix: minimize short‑term
> damage, keep full reversibility, put a human in the loop.

This doc has two halves: **(A) where we are** — the real system, honestly mapped — and
**(B) where we're going** — workstreams from high level down to concrete tasks.

---

## A. Current state

### A.1 One request, end to end

```
          ┌─────────────────────────────────────────────────────────────────────┐
client ──▶│ PROXY (proxy.py :8080)                                               │
          │  rate_limit → denylist(ban?) → diversion(honeypot IP?) → vpatch      │
          │  build redacted event (privacy.py) ─▶ JEV classify (classifier.py)   │
          │     {malicious, score, attack_type, confidence}  ← zero‑shot, no train│
          │  route: forward ▸ real app │ divert ▸ honeypot │ block               │
          │  record event ─▶ STORE (store.py, SQLite WAL queue, kind=events)      │
          └───────────────┬─────────────────────────────────────────────────────┘
                          │ durable queue
                          ▼
          ┌─────────────────────────────────────────────────────────────────────┐
          │ BLUE AGENT (blue_agent.py) — autonomous investigator                 │
          │  dequeues flagged events, LLM reasoning loop + tool calls:           │
          │   read:  inspect_target, recent_requests, get_defenses, service_status│
          │   act:   blacklist_ip, divert_to_honeypot, virtual_patch, unban_ip,   │
          │          quarantine/release, cut/reconnect egress, raise_alert        │
          │  EVERY call ─▶ record_action(tool, input, result, outcome, case_id)   │
          └───────┬───────────────────────────────────┬─────────────────────────┘
                  │ privileged ops                     │ raise_alert
                  ▼                                     ▼
          ┌───────────────────────┐     ┌──────────────────────────────────────┐
          │ ACTUATOR (actuator.py)│     │ incident (kind=incidents) + mail outbox│
          │  Docker socket, FIXED │     │ MAIL WORKER (mail_worker.py)           │
          │  argv. quarantine,    │     │  notifications.py ─▶ emailed REPORT     │
          │  egress, patch_vuln   │     │  = the human‑in‑the‑loop review        │
          └───────────────────────┘     └──────────────────────────────────────┘

   HONEYPOT (honeypot_app.py)  — diverted traffic hits a static decoy; hits logged
                                  to honeypot_hits.jsonl (TTP harvest) + optional tarpit.
   LOG COLLECTOR (log_collector/log_store) — tails every container's logs for the console.
   DASHBOARD (dashboard_api SSE + dashboard_data snapshot + frontend/) — operator console.
   RED AGENT (red_agent.py) — LLM attacker for demos/eval (sqli/cmdi/lfi/xss).
```

### A.2 Component maturity

| Component | File | State | Notes |
|---|---|---|---|
| Zero‑shot classification | `classifier.py` | **Real** | External System‑One API; structured Q&A; no training; IP excluded from input. |
| Reverse‑proxy routing + enforcement | `proxy.py`, `security.py`, `rate_limit.py` | **Real** | ban / divert / vpatch / rate‑limit all live. |
| Autonomous blue agent | `blue_agent.py` (28 KB) | **Real** | Reasoning loop; read + act tools; dedup; **every action recorded with `case_id`**. |
| Privileged actuation | `actuator.py` (33 KB), `remediation_tools.py` | **Real** | Fixed‑argv Docker ops; quarantine/egress/patch; **reverse primitives exist** (release, reconnect, lower level, `unban_ip`). |
| Durable store / audit | `store.py` (SQLite WAL) | **Real, not yet tamper‑evident** | Transactional `records` (events/actions/incidents) + outbox; sha256 used for keys/log digests, **but no hash chain**. |
| Incident + emailed report | `blue_agent.do_raise_alert`, `mail_worker.py`, `notifications.py` | **Real** | Atomic incident + mail queue; dedup window. The human‑review loop. |
| Honeypot | `honeypot_app.py` | **Real but shallow** | One static "Acme portal" page for every route + hit log + tarpit. Scales, but easy to fingerprint. |
| Operator dashboard | `dashboard_*.py`, `frontend/` | **Real, redesigned** | Flat data‑terminal UI; Overview (graph + live tape), Incidents, Investigator, Attacker. |
| Red agent (demo) | `red_agent.py` | **Real (demo)** | Not a product surface; eval/marketing only. |

### A.3 What the thesis needs that we *don't* fully have yet

| Thesis pillar | Have | Gap |
|---|---|---|
| Glass box — see exactly what the agent did | actions recorded per `case_id` | **not surfaced**: no per‑incident reasoning + tool‑call case file in the UI |
| Reversibility — undo short‑term damage | reverse primitives exist | **not exposed**: no action→inverse mapping, no rollback endpoint, no UI |
| Tamper‑evident log — trust the autonomy | transactional + durable | **not verifiable**: no hash chain, no verify/anchor |
| Scales to any app | classification does (no train) | **onboarding not productized** (point‑at‑app, learn shape); honeypot still generic |
| Deception at scale | static decoy + TTP log | **no adaptive/LLM decoy** |
| Human‑in‑the‑loop | emailed report | report could carry *what changed* + verify + rollback links |
| The story | n/a | **no marketing homepage**; dashboard still shows infra noise (health ages) |

---

## B. Where we're going

Seven workstreams, ordered by leverage. Each: **current → target → concrete tasks** (FE = frontend, BE = backend) → rough size.

### B1 — Surface the glass box (the showcase) · FE · **do first**
*Current:* per‑case reasoning + tool calls exist in data but are scattered (Investigator shows a global stream; Incidents shows only an outcome timeline).
*Target:* **Incidents = the case file.** Open an incident → the whole story: triage verdict (Jev score/type), the agent's reasoning, **every tool call with its input + result + outcome**, the containment taken, and the emailed report. Investigator becomes the *live/global* agent feed + the audit ledger (no duplication).
*Tasks:*
- Incident detail (`/incidents/{id}` already returns `actions`): render a chronological **reasoning + tool‑call trace** (reuse the `.line` trace component), each call expandable to input/result.
- Move the dense per‑case content out of Investigator; keep Investigator as "what is the agent doing right now" + the ledger.
- Copy: name tools in operator language ("Banned 203.0.113.9", "Virtual‑patched /lookup to prepared statements").
*Size:* S–M, pure frontend, data already present.

### B2 — Reversibility / one‑click rollback · BE (small) + FE · **do next**
*Current:* inverse functions exist (`unban_ip`, `release_container`, `reconnect_egress`, lower vpatch level); undivert referenced in agent policy. No dashboard path.
*Target:* every reversible action in the case file has **Revert**; rollback is itself a logged, compensating action (append‑only — you never delete history).
*Tasks:*
- BE: inverse map `blacklist_ip→unban_ip`, `divert_to_honeypot→undivert`, `virtual_patch→restore level`, `quarantine→release`, `cut_egress→reconnect`; mark `rotate_creds` **non‑reversible**.
- BE: `POST /__api/v1/actions/{id}/rollback` → dispatch the inverse via the existing actuator/operator path, **record a new action** (`tool=rollback`, `reverts=<id>`), flag the original `reverted`.
- FE: Revert button (confirm dialog that states the effect), reverted‑state styling, link to the compensating action.
- Guardrails: only reversible tools; idempotent; auth (already behind `MANAGEMENT_TOKEN`).
*Size:* M. This is the feature that makes autonomy *safe to sell*.

### B3 — Tamper‑evident audit log · BE · **do next**
*Current:* durable SQLite, sha256 already used for keys/digests; no chain.
*Target:* the action log is a **verifiable hash chain**; the UI can prove it's intact; the report carries the head hash.
*Tasks:*
- BE: on each `actions` insert, store `prev_hash` + `hash = sha256(prev_hash ‖ canonical_json(payload))`; keep a head pointer.
- BE: `GET /__api/v1/audit/verify` recomputes from genesis → `{intact, head, length, broken_at?}`.
- FE: a quiet "Audit log verified ✓ (N actions)" chip in the ledger; "Verify" re‑runs it.
- v2 (trust beyond the DB): **anchor** the head hash externally — include it in the incident email and/or publish periodically (a notary / object store). That's what lets a customer prove *we* didn't edit it either.
*Size:* M (v1), the anchoring is a follow‑up.

### B4 — Kill infra noise, make metrics *understandings* · FE · **do first, cheap**
*Current:* health strip (`blue 0s / proxy 7s …`), `agent · live` scope — DevOps telemetry shown as client value; triage funnel is 4 abstract bars.
*Target:* client‑facing outcomes only.
*Tasks:*
- Remove the health strip (or demote to a single **"All systems nominal / degraded"** dot); reduce scope line to a quiet live/offline indicator.
- **Triage funnel → "defense pipeline"** on the Home page beside the graph: `21 screened → 2 threats caught → 10 actions taken → 0 reached the app`, drop‑off made visual. Graph = routing; pipeline = decisions; together they answer "what happened" on one screen.
*Size:* S.

### B5 — Deception at scale (adaptive honeypot) · BE · **later / moat**
*Current:* one static decoy page.
*Target (staged):*
- **v1 (have):** static decoy + tarpit + TTP log.
- **v2 — learned templating:** passively learn the real app's routes + response skeletons from proxy traffic; serve learned variants with fake data. One service, per‑tenant templates.
- **v3 — LLM‑synthesized decoy:** on a honeypot hit, generate a response consistent with (a) the learned app shape, (b) prior responses to *this* attacker session (cache for consistency + cost), (c) the request — an **undetectable clone with no source code**. Tarpit throttles; only attacker traffic hits it, so cost is bounded. Must treat attacker input as untrusted (same prompt‑injection discipline as Jev).
*Why it scales:* diverted traffic is tiny vs. legitimate; caching + tarpit cap LLM spend; nothing is cloned or maintained per app.
*Size:* L (v3). Write the **design doc first**.

### B6 — Human‑in‑the‑loop report · BE/content · **after B1–B3**
*Target:* the emailed incident report becomes the review surface the thesis describes: *what the agent saw, what it did, what changed, how to verify, and a one‑click link to roll back.* Expect volume to **decline** as `virtual_patch` hardens the app — surface that trend ("reports ↓ 40% this month") as a value metric.
*Tasks:* enrich `notifications.prepare_message` with the action list + audit head + deep links; add a "containment summary" and a rollback link (tokenized).
*Size:* M.

### B7 — Marketing homepage (the story) · FE · **parallel track**
*Decision needed:* public **marketing landing page** (product story, taste‑skill *page* run, lives on the marketing domain) vs. a dashboard **"Home" summary tab**. My rec: the marketing page — it tells exactly the story in your brain dump (no‑train classification, glass‑box reversible agent, adaptive honeypot, human‑in‑the‑loop). The dashboard already has its command‑center Overview.
*Size:* M, separate from the app.

---

## C. Roadmap

| Horizon | Ships | Outcome |
|---|---|---|
| **Now** | B1 (case file), B4 (de‑noise + pipeline) | The product *looks and reads* like a glass‑box agent; no infra noise. |
| **Next** | B2 (rollback), B3 (tamper‑evident v1) | The two claims that make autonomy sellable are *real and demoable*. |
| **Then** | B6 (report), B3 anchoring | The human‑in‑the‑loop loop is tight; trust extends beyond our DB. |
| **Later** | B5 (adaptive honeypot), onboarding productization, B7 | The moat + the pitch. |

## D. Open questions / risks
1. **Homepage:** marketing page or dashboard tab? (B7)
2. **Rollback + hash chain backend:** in scope now, or keep this iteration frontend‑only? (B2/B3)
3. **Honeypot:** design doc first, or prototype the LLM decoy? (B5)
4. **Autonomy boundary:** which actions may the agent take fully autonomously vs. propose‑and‑wait? Reversibility makes "act then review" defensible, but destructive/irreversible ops (`rotate_creds`) should likely be propose‑only.
5. **LLM hallucination containment:** prompt for least‑risk fixes, prefer reversible tools, cap blast radius (never destructive without a reversible fallback), and lean on the human review + rollback. Make this an explicit, tested policy, not a hope.
6. **Classifier dependency:** Jev is an external API — need graceful degradation (fail‑open vs fail‑closed per tenant policy) and budget controls (already has `MODEL_CALLS_PER_MINUTE`).
```
