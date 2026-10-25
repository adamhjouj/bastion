# Feature 1 — End-to-End Red-vs-Blue Scoring Harness (plan)

**Status:** plan only. No existing file is touched. One new module (`score_campaign.py`)
plus one test (`test_score_campaign.py`). Everything else is reuse.

## The gap this closes

`eval_live.py` already runs benign + attack traffic through the live stack and scores
**per-request classifier quality** (precision / recall / FP-rate, Wilson CIs). That is
*"did Jev label each request correctly."*

It does **not** answer the scoreboard the project implies:

> Run the red agent against the live stack with blue on. **Did the attacker reach its
> goal (creds exfiltrated? RCE?) and how fast did blue contain it (MTTD / MTTR)?**

That is a different axis — **mission outcome + containment latency**, not per-request
labels. It's almost pure orchestration over parts that already exist. This plan builds
only that axis.

## What we reuse (do not rebuild)

| Need | Already exists | Source |
| --- | --- | --- |
| Drive live attacks (replay corpus) | `eval_live.replay`, `eval_live.load_attacks` | `eval_live.py` |
| Drive live attacks (autonomous agent) | `eval_live._run_red_agent`, `red_agent.py sqli\|cmdi` | — |
| Benign cross-traffic (Tier-1 #3 is DONE) | `benign_agent.run(duration=, proxy=, stop=)` | `benign_agent.py` |
| Preflight the stack / identity propagation | `eval_live.preflight` | `eval_live.py` |
| Read persisted verdicts/events over the mgmt API | `eval_live._api_pages`, `read_verdicts_api` | `eval_live.py` |
| Second-resolution UTC timestamps | `store.now()` | `store.py` |
| Confidence intervals (if we want CI on outcome rate) | `eval_waf.wilson` | `eval_waf.py` |

No new dependency. No change to the proxy, blue agent, actuator, or store.

## Signals (all already persisted — we only read them)

Read per attack source IP (`10.13.37.7` agent, `203.0.113.7` replay) inside the campaign window,
via `/__api/v1` (`requests`, `actions`), because the live DB is in a named volume:

- **First attack request** `t0` — earliest `events`/`requests` row for the attacker IP.
- **Detection** `t_det` — earliest of: a `triage`/event row for the attacker IP with
  `jev.malicious == true`, **or** an inline `403` on the attacker IP.
- **Containment** `t_cont` — earliest *effective block* of the attacker IP:
  a `blacklist_ip`/`bulk_blacklist_ip` `action` row for that IP (agent / classifier-contain),
  or the first inline `403` when the mode blocks per-request without a persistent ban
  (then `t_cont == t_det`).
- **Breach** `t_breach` (if any) — see oracle below.

```
MTTD = t_det  - t0        MTTR = t_cont - t0        (seconds)
```

## Goal oracle — "did the attacker actually win?"

The oracle lives **at the attack source**, not in the store — the harness sends the attack,
so it holds the real HTTP response and needs nothing from the proxy's (bounded, redacted)
event bodies.

- **replay attack:** after the campaign, the harness fires the goal payload once itself and
  inspects the response it gets back. Goal reached ⇔ status ∉ {403, 429} **and** body matches
  the per-goal success regex:
  - `sqli`  → credential-dump signature (e.g. `admin` row + an MD5-shaped hash `[0-9a-f]{32}`)
  - `cmdi`  → `/etc/passwd` signature `root:.*:0:0:`
- **agent attack:** `red_agent.py` already **stops and reports** when it reaches the goal, and
  `_run_red_agent` already captures stdout. Parse that self-report, and corroborate with one
  independent verification probe (same regex) so the score isn't the attacker's word alone.

`t_breach` = time the goal-reaching response came back during the live window.

## Outcome per attack

```
BREACH     if goal reached AND (t_cont is None OR t_breach <= t_cont)   # won before contained
CONTAINED  if t_cont exists AND NOT BREACH                              # blocked in time
LEAKY      if goal reached AND t_cont exists AND t_breach > t_cont      # contained, but too late
OPEN       otherwise                                                    # neither — vuln open, blue idle
```

This is the real scoreboard: a mode "defends well" only when attacks land `CONTAINED`.

## New module: `score_campaign.py`

Thin orchestrator. Shape:

```
run_attack(objective, mode, before, during, after, proxy) -> AttackResult
    # optional benign thread (reuse benign_agent.run on a stop Event, as eval_live does)
    # t0 = store.now(); fire attack (replay | agent); window-bound; drain async verdicts
    # oracle -> goal_reached, t_breach
    # read API -> t_det, t_cont
    # return {objective, mode, outcome, mttd, mttr, goal_reached, counts...}

scoreboard(results) -> dict          # aggregate: per-objective + overall, mean MTTD/MTTR,
                                     #   breach-rate (+ Wilson CI via eval_waf.wilson)
print_scoreboard(results)            # the human table
main()                               # argparse: --objectives sqli,cmdi  --mode  --attack replay|agent
                                     #           --before/--during/--after  --json out.json
```

CLI example:

```
python score_campaign.py --objectives sqli,cmdi --attack agent \
    --mode classifier-contain --before 15 --during 90 --after 15 --json score.json
```

Output (one row per attack, then aggregate):

```
OBJECTIVE  MODE                ATTACK  OUTCOME    MTTD   MTTR   GOAL
sqli       classifier-contain  agent   CONTAINED   3s     3s    no
cmdi       classifier-contain  agent   BREACH      7s     —     yes
---
2 attacks | contained 1/2 (50%, CI 9–91%) | mean MTTD 5s | mean MTTR 3s
```

`--json` emits the same data as a machine record so Tier-2 #5 can later wire it into CI as a
regression gate (e.g. fail if breach-rate rises or MTTR regresses). Not built now.

## The one runnable check (ponytail)

`test_score_campaign.py` — unit-test the pure logic with **no stack, no provider key**, exactly
how `test_benign_eval.py` already tests `eval_live.score` against a temp DB:

- `outcome()` truth table: feed synthetic `(t0, t_det, t_cont, t_breach)` tuples → assert
  BREACH / CONTAINED / LEAKY / OPEN.
- `oracle_match()`: assert the sqli/cmdi regexes fire on a known-good dump and reject a 403 body.

MTTD/MTTR extraction over the API and the live campaign stay behind an opt-in flag
(`RUN_LIVE_SCORE`), mirroring `eval_live`'s `RUN_LIVE_EVAL`, so CI never needs the stack or a key.

## Deliberate ceilings (`ponytail:` notes to carry into the code)

- `# ponytail: second-resolution timestamps (store.now()); sub-second MTTD/MTTR not measurable.`
  Fine for a demo; only matters if containment ever drops under ~1s.
- `# ponytail: oracle is per-goal regex on the attack response; add a goal per new red objective.`
- Agent-mode breach timing uses red_agent's stop-and-report; the verification probe corroborates
  it, but exact `t_breach` is as precise as the agent's final turn.

## Explicitly out of scope (don't build in Feature 1)

- Benign/background traffic generator — **already done** (`benign_agent.py`).
- Classifier precision/recall on live traffic — **already done** (`eval_live.py`); the scoreboard
  can print it by calling `eval_live.score`, but it is not this feature's job.
- Tier-2 scenario runner / one-command stack-up-attack-reset, threshold/PR-curve sweep, CI gate.
- More red objectives (XSS/LFI/upload) — Feature 2; this harness takes any `red_agent` objective
  as `--objectives`, so it absorbs them for free when they land.

## Build order

1. `score_campaign.py`: `oracle_match`, `outcome`, `AttackResult`, `scoreboard`, `print_scoreboard` (pure).
2. `test_score_campaign.py`: truth-table + oracle tests (green with no stack).
3. `run_attack` + `main`, reusing `eval_live`/`benign_agent`/`store`; smoke behind `RUN_LIVE_SCORE`.
4. Run live once per mode (`classifier-contain`, `agent`) × (`sqli`, `cmdi`); capture `score.json`.

Est. ~150–200 LOC in one module; the hard parts (traffic drive, API read, benign gen, CIs) are reuse.
