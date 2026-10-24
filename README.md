<a id="readme-top"></a>

<!-- PROJECT SHIELDS -->
<div align="center">

[![MIT License][license-shield]][license-url]
![Python][python-shield]
![Status][status-shield]

</div>

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <h3 align="center">Bastion</h3>
  <p align="center">
    An autonomous blue-team agent that lives in your server or containers 24/7, detects attacks in real time, and runs damage control on its own
    <br />
    <a href="https://github.com/adamhjouj/bastion/blob/main/architecture.md"><strong>Explore the docs &raquo;</strong></a>
    <br />
    <br />
    <a href="https://github.com/adamhjouj/bastion/issues/new?labels=bug">Report Bug</a>
    &middot;
    <a href="https://github.com/adamhjouj/bastion/issues/new?labels=enhancement">Request Feature</a>
  </p>
</div>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#how-it-works">How It Works</a></li>
        <li><a href="#the-two-tier-thesis">The Two-Tier Thesis</a></li>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
        <li><a href="#configuration">Configuration</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#the-agents-toolbox">The Agent's Toolbox</a></li>
    <li><a href="#measuring-the-classifier">Measuring the Classifier</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->
## About The Project

Bastion is a 24/7 blue-team agent that embeds alongside your services (a server, a set of containers, or any app behind it), watches their request logs, and runs damage control automatically the moment an attack lands. It does not just block — it **reasons**: a fast classifier flags suspicious traffic, and an LLM agent investigates with read-only tools before it acts, so an obvious exploit is contained in milliseconds while an ambiguous request is examined, not blindly banned. On a confirmed attack it bans the source IP, virtually patches the vulnerability with a WAF rule, can eradicate the hole at the app, divert the attacker to a decoy, reach into the infrastructure to kill a process or rotate stolen credentials, and email a structured incident report — no human in the loop.

It ships with a live SOC dashboard and a self-contained demo: a bundled vulnerable sample app, a honeypot decoy, a local mail catcher, and a scoped autonomous red-team agent, so you can watch the full detect-investigate-respond loop end to end on your machine before pointing Bastion at your real services. The demo target is deliberately vulnerable, so keep it local and never expose it publicly.

Key capabilities:
* **Tiered triage that reasons** — a free regex pre-gate drops obvious benign traffic; a fast system-1 classifier (TypeSafe Jev) scores what survives as malicious/benign + attack type; a **high-confidence reflex** contains unambiguous attacks instantly, while an **ambiguous band escalates to the LLM agent** (Claude or DeepSeek) to investigate and decide. Only confirmed attacks trigger durable, high-blast-radius actions.
* **Provisional, self-healing bans** — the instant reflex ban is a short-TTL, single-IP containment that auto-lifts; the agent re-bans durably only if it confirms the attack, so a false flag costs nothing and expires on its own.
* **An agent that understands its environment** — it is taught the topology, its live tool catalog, and a standing doctrine, and orients with read-only tools (current defenses, recent traffic, incidents, container state) *before* it acts.
* **Layered response** — containment (IP ban, honeypot divert, egress isolation, container quarantine, process/session kill), virtual patch (WAF rule), real eradication (raise the app's security posture; rotate stolen DB credentials), and alerting (email + incident record) — each a named, validated tool; the LLM never gets a shell.
* **Deception** — divert a confirmed attacker to a convincing decoy from request #1 (no `403` tip-off) and bank their techniques to `honeypot_hits.jsonl`.
* **Proxy as enforcement point** — the same reverse proxy that produces the logs enforces the denylist, WAF rules, honeypot diverts, and a pinned app-security level, so a tool call takes effect on the very next matching request (no restart).
* **Provider-agnostic** — the agents are written against the Anthropic Messages API and run unchanged on Claude or on DeepSeek's Anthropic-compatible endpoint, chosen by whichever key is set.
* **Live SOC dashboard** — a built-in view at `/__dashboard` streams (Server-Sent Events) the request feed, a pipeline funnel, incidents, bans, WAF rules, honeypot diverts, an exploit-replay panel, and the live container/agent consoles.
* **Measured, not asserted** — a Jev evaluation harness reports precision/recall/F1 with 95% Wilson confidence intervals, a threshold sweep, run-to-run variance, and a label-leakage probe over a labeled dataset.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### How It Works

A reverse proxy sits in front of the app you want to protect and is both the log source and the enforcement point. The blue agent tails its log through a tiered triage, then — for anything it is not certain about — an LLM agent investigates with read-only tools and calls action tools to contain, patch, eradicate, divert, and alert. Re-running the same attack then returns `403` live.

```
 red_agent ─▶ proxy :8080 ──────────────▶ app :80 (DVWA)
   (Claude/   │  honeypot divert? ─▶ decoy :9000 (logs TTPs)
   DeepSeek)  │  denylist (TTL-aware) / WAF rule / enforced security-cookie → 403
              │  logs every request → data/events.jsonl   (+ SSE push to dashboard)
              ▼
        blue_agent loop:
          regex pre-gate ─▶ Jev (system-1) ─▶ score ≥ 0.9  ─▶ REFLEX: provisional TTL ban (live 403)
                                             0.5 ≤ s < 0.9 ─▶ AGENT (system-2): investigate → decide
              │                                                 │
              │                         inspect · orient · contain · patch · eradicate · divert · alert
              ▼
        dashboard (/__dashboard, SSE) · MailHog (email) · actions.jsonl (timeline)
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### The Two-Tier Thesis

A bare "score → ban" is exactly a commodity WAF, and it is wrong the moment a benign request looks scary (a legitimate `?ip=127.0.0.1` ping, a file param that stays inside its directory). Bastion splits the decision:

* **System-1 (Jev, reflex)** — cheap, fast, twitchy. A flag is a reason to **look**, not proof. On an unambiguous hit (score ≥ `AUTOBLOCK_HIGH`, default `0.9`) it applies an instant but **provisional** IP ban (short TTL, one attacker, cheap to reverse) so the live `403` lands immediately.
* **System-2 (the LLM agent)** — the ambiguous band (`MALICIOUS_THRESHOLD` ≤ score < `AUTOBLOCK_HIGH`) escalates here. The agent calls `inspect_target` and the read-only orientation tools for structural evidence, then either **confirms** (re-ban durably + add a tight WAF rule + alert, and optionally eradicate/divert) or **clears** it ("no threat" — the provisional ban simply expires).

With no agent key set, the system still defends: Jev autoblock becomes the full responder (contain + canned WAF rule + alert).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

* [![Python][Python-badge]][Python-url]
* [![Anthropic][Anthropic-badge]][Anthropic-url]
* [![DeepSeek][DeepSeek-badge]][DeepSeek-url]
* [![TypeSafe Jev][Jev-badge]][Jev-url]
* [![FastAPI][FastAPI-badge]][FastAPI-url]
* [![Uvicorn][Uvicorn-badge]][Uvicorn-url]
* [![Docker][Docker-badge]][Docker-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->
## Getting Started

### Prerequisites

* Python 3.10+
* Docker and Docker Compose (for the bundled demo target, honeypot, and MailHog)
* **One agent key (optional):** an Anthropic API key **or** a DeepSeek API key for the system-2 agent. With neither, the blue agent still defends via Jev system-1 autoblock.
* **A TypeSafe (Jev) API key (optional):** enables the system-1 classifier tier; without it the agent falls back to the regex pre-gate alone.

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/adamhjouj/bastion.git
   cd bastion
   ```

2. Copy the example environment file and add a key
   ```sh
   cp .env.example .env
   ```

3. Bring up the whole stack
   ```sh
   ./run.sh
   ```

   `run.sh` builds and runs the full dockerized stack (DVWA + honeypot decoy + MailHog + reverse-proxy/WAF + blue agent). The proxy container waits for DVWA, bootstraps it, resets demo state, then serves. To protect your own service instead, point the proxy at it with `DVWA_URL` in `.env`.

4. Open the dashboard and the mailbox
   * Dashboard: [http://localhost:8080/__dashboard](http://localhost:8080/__dashboard)
   * MailHog: [http://localhost:8025](http://localhost:8025)

### Configuration

Everything is driven by `.env`. The most important knobs:

| Variable | Default | What it does |
|----------|---------|--------------|
| `DEEPSEEK_API_KEY` | — | Routes the system-2 agent through DeepSeek's Anthropic-compatible endpoint. **Wins if set.** |
| `ANTHROPIC_API_KEY` | — | Native Claude for the system-2 agent (used if no DeepSeek key). |
| `TYPESAFE_API_KEY` | — | Enables the Jev system-1 classifier; unset → regex pre-gate only. |
| `MALICIOUS_THRESHOLD` | `0.5` | Jev score at/above which a request is "malicious" (the **look** line). |
| `AUTOBLOCK_HIGH` | `0.9` | Score at/above which the reflex bans instantly; between this and the threshold escalates to the agent (the **investigate** band). |
| `AUTOBLOCK_TTL_MIN` | `15` | Minutes a provisional reflex ban lives before auto-lifting. |
| `AUTOBLOCK_MODE` | `ban` | `ban` = TTL IP ban on a high-confidence hit; `divert` = deception-first (also route to the decoy from request #1, TTL ban as backstop). |
| `JEV_AUTOBLOCK` | `1` | Enable the system-1 reflex at all. |
| `USE_REGEX_PREGATE` | `1` | Run the free regex pre-gate before Jev (`0` sends all traffic to Jev). |
| `HONEYPOT_URL` | `http://honeypot:9000` (compose) | Decoy base URL; divert is disabled if unset. |
| `RATE_LIMIT_MAX` / `RATE_LIMIT_WINDOW` | `100` / `10.0` | Per-IP sliding-window limiter knobs (module built + tested; see Roadmap for wiring status). |

Email defaults target MailHog (no auth) so the demo never flakes; set `SMTP_USER`/`SMTP_PASS` for a real relay (STARTTLS + login).

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- USAGE -->
## Usage

**Attack it — pure Jev, no agent key needed**

With the stack up, from another terminal:
```sh
curl -H 'X-Forwarded-For: 10.13.37.7' \
  "http://localhost:8080/vulnerabilities/sqli/?id=1'+OR+'1'='1&Submit=Submit"
# re-run the same curl -> 403 (Jev banned the IP; the agent, if present, added a WAF rule)
```
The dashboard feed lights up, an incident is filed, an email drops into MailHog, and the replay returns `403`. Try the command-injection and XSS cases too — it defends more than one attack class.

**Run the autonomous red-team agent** (needs an agent key)

```sh
.venv/bin/python red_agent.py sqli     # SQL injection, data exfiltration
.venv/bin/python red_agent.py cmdi     # command injection, RCE
```
The red agent probes the proxied target with a distinct attacker IP and finds the exploit live, so the blue side sees real attack traffic on stage.

**Deception-first mode**

Set `AUTOBLOCK_MODE=divert` in `.env` and restart: a high-confidence attacker is silently routed to the decoy from request #1 (no `403` tip-off) while the TTL ban stands by as a backstop. Their probes land in `data/honeypot_hits.jsonl`.

**Smoke-test the classifier**

```sh
.venv/bin/python classifier.py        # runs a built-in malicious + benign sample live (needs TYPESAFE_API_KEY)
```

**Notes**

The bundled demo target is deliberately vulnerable — keep it local and never expose it publicly. The `# ponytail` comments in the code flag the demo-grade corners and their upgrade paths. See `architecture.md` for the full design.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## The Agent's Toolbox

The system-2 agent is taught its environment and the **live** tool catalog in its system prompt (generated from the registered tools, so a newly added tool is taught automatically). Tools are grouped by purpose:

* **Situational awareness (read-only — orient first):** `get_defenses`, `recent_requests`, `recent_incidents`, `service_status`, `inspect_target`, `list_processes`, `list_sessions`.
* **Containment:** `blacklist_ip` (TTL-aware), `divert_to_honeypot` / `undivert`, `isolate_egress`, `quarantine_container` / `release_container`, `kill_process`, `kill_session`.
* **Eradication / virtual patch:** `add_waf_rule`, `patch_vuln` (raise the app's security posture + pin the security cookie at the proxy), `rotate_secret` (rotate stolen DB credentials, secret never logged).
* **Alerting:** `raise_alert` (email + incident record).

The privileged control-plane actions (`actuator.py`) never give the LLM a shell: each tool maps to **one fixed, argument-validated** `docker` call, every target is validated against an allow-list, only attacker-spawned (non-baseline) processes are killable, and every attempt is audited to `data/actions.jsonl`.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

## Measuring the Classifier

`eval_waf.py` runs a labeled dataset (`eval_dataset.jsonl`) through the real Jev classifier and reports a confusion matrix, precision/recall/F1 with **95% Wilson confidence intervals** (N is small — the interval is the honest number), attack-type accuracy, the actual FP/FN cases, a **threshold sweep** (tune `MALICIOUS_THRESHOLD` with no extra API calls), run-to-run **variance** (`--repeat N`), run **provenance** (dataset hash, git sha, model, threshold), and a **label-leakage probe** (does the verdict follow the payload or just the path?).

```sh
TYPESAFE_API_KEY=... .venv/bin/python eval_waf.py
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ROADMAP -->
## Roadmap

- [x] Reverse proxy that is both log source and enforcement point (denylist, WAF, honeypot divert, pinned security cookie)
- [x] Tiered triage: regex pre-gate → Jev system-1 → **two-tier** (high-confidence reflex vs. agent-investigate band)
- [x] Provisional short-TTL reflex bans that auto-lift; durable re-ban on agent confirmation
- [x] System-2 agent with environment briefing + live tool catalog + read-only orientation tools
- [x] Containment, virtual patch, real eradication (`patch_vuln` + enforced security cookie), credential rotation
- [x] Privileged control plane with no LLM shell (process/session kill, egress isolation, quarantine)
- [x] Honeypot decoy + divert tools + deception-first autoblock mode
- [x] Provider-agnostic agent (Claude **or** DeepSeek)
- [x] Live SOC dashboard over Server-Sent Events (funnel, replay, bans, rules, diverts, streamed consoles)
- [x] Jev evaluation harness (Wilson CIs, threshold sweep, variance, leakage probe)
- [x] Scoped autonomous red-team agent (SQL injection, command injection)
- [ ] Wire the per-IP rate limiter (`rate_limit.py`) into the proxy request path (module + tests done)
- [ ] Broader red-agent coverage (XSS, path traversal, file upload objectives)
- [ ] Persistent incident/event store (swap the flat files for a real store at volume)
- [ ] Configurable detection policy / per-rule tuning without code changes

See the [open issues](https://github.com/adamhjouj/bastion/issues) for a full list of proposed features and known bugs.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTRIBUTING -->
## Contributing

Contributions are welcome. If you have a suggestion, please fork the repo and open a pull request, or file an issue with the `enhancement` label.

1. Fork the project
2. Create your feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a pull request

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTACT -->
## Contact

Project Link: [https://github.com/adamhjouj/bastion](https://github.com/adamhjouj/bastion)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & BADGES -->
[license-shield]: https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge
[license-url]: https://github.com/adamhjouj/bastion/blob/main/LICENSE
[python-shield]: https://img.shields.io/badge/Python-3.10%2B-3776AB.svg?style=for-the-badge&logo=python&logoColor=white
[status-shield]: https://img.shields.io/badge/status-demo-orange.svg?style=for-the-badge

[Python-badge]: https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white
[Python-url]: https://www.python.org/
[Anthropic-badge]: https://img.shields.io/badge/Anthropic-191919?style=for-the-badge&logo=anthropic&logoColor=white
[Anthropic-url]: https://www.anthropic.com/
[DeepSeek-badge]: https://img.shields.io/badge/DeepSeek-4D6BFE?style=for-the-badge&logoColor=white
[DeepSeek-url]: https://www.deepseek.com/
[Jev-badge]: https://img.shields.io/badge/TypeSafe_Jev-4B2ECC?style=for-the-badge&logoColor=white
[Jev-url]: https://typesafe.ai/
[FastAPI-badge]: https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white
[FastAPI-url]: https://fastapi.tiangolo.com/
[Uvicorn-badge]: https://img.shields.io/badge/Uvicorn-2094F3?style=for-the-badge&logo=gunicorn&logoColor=white
[Uvicorn-url]: https://www.uvicorn.org/
[Docker-badge]: https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white
[Docker-url]: https://www.docker.com/
