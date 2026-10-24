<a id="readme-top"></a>

<!-- PROJECT SHIELDS -->
<div align="center">

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]

</div>

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <h3 align="center">Bastion</h3>
  <p align="center">
    An autonomous blue-team agent that watches a live web app, detects attacks in real time, and runs damage control on its own
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
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#roadmap">Roadmap</a></li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->
## About The Project

Bastion is a 24/7 blue-team agent that sits in front of a live web app, watches its request logs, and runs damage control automatically the moment an attack lands: it blacklists the attacker's IP, virtually patches the vulnerability with a WAF rule, and emails an incident report. It ships with a live dashboard and a scoped autonomous red-team agent that finds the exploit on stage, so you can watch an attack succeed and then watch the same attack get killed seconds later.

The target is [DVWA](https://github.com/digininja/DVWA) (Damn Vulnerable Web Application) running locally at Security=Low, a standard training app for this kind of work. Everything runs on your machine; nothing is ever meant to be exposed publicly.

Key capabilities:
* **Real-time detection**: a reverse proxy tails every request; a cheap regex pre-filter gates what reaches the model, so Claude only classifies traffic that looks suspicious
* **Automatic damage control**: on a confirmed attack the blue agent blocks the source IP, adds a virtual-patch WAF rule, and emails a structured incident report, no human in the loop
* **Proxy as enforcement point**: the same reverse proxy that produces the logs also enforces the denylist and WAF rules, so re-running an attack returns `403` live
* **Scoped red-team agent**: an autonomous attacker demonstrates SQL injection and command injection against the stage so the defense has something real to react to
* **Live dashboard**: a built-in view at `/__dashboard` shows the request feed, incidents, bans, and WAF rules as they happen

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### How It Works

A reverse proxy sits in front of DVWA and is both the log source and the enforcement point. The blue agent tails its log, a regex pre-filter gates what reaches Claude, then Claude classifies the request and calls tools to block, patch, and alert. Re-running the same attack then returns `403` live.

```
red_agent -> proxy :8080 -> DVWA :80
                 | logs + enforces (denylist + WAF)
                 v
           blue_agent -> Claude -> blacklist / WAF rule / email
                 |
           dashboard (/__dashboard)
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

* [![Python][Python-badge]][Python-url]
* [![Anthropic][Anthropic-badge]][Anthropic-url]
* [![FastAPI][FastAPI-badge]][FastAPI-url]
* [![Uvicorn][Uvicorn-badge]][Uvicorn-url]
* [![Docker][Docker-badge]][Docker-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->
## Getting Started

### Prerequisites

* Python 3.10+
* Docker and Docker Compose (for DVWA and MailHog)
* An Anthropic API key

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/adamhjouj/bastion.git
   cd bastion
   ```

2. Copy the example environment file and add your API key
   ```sh
   cp .env.example .env
   ```

   Only `ANTHROPIC_API_KEY` is required for the demo. The email defaults target
   MailHog (no auth) so the demo never flakes:
   ```env
   ANTHROPIC_API_KEY=sk-ant-...
   DVWA_URL=http://localhost:80
   PROXY_URL=http://localhost:8080
   BLUE_MODEL=claude-sonnet-5
   RED_MODEL=claude-opus-5
   SMTP_HOST=localhost
   SMTP_PORT=1025
   ALERT_TO=soc@yourteam.com
   ```

3. Create a virtual environment and install dependencies
   ```sh
   python3 -m venv .venv
   .venv/bin/pip install -r requirements.txt
   ```

4. Bring up the whole stack
   ```sh
   ./run.sh
   ```

   `run.sh` starts DVWA and MailHog, bootstraps DVWA (creates the DB, logs in,
   sets Security=Low), then starts the reverse proxy on `:8080` and the
   blue-team agent.

5. Open the dashboard and the mailbox
   * Dashboard: [http://localhost:8080/__dashboard](http://localhost:8080/__dashboard)
   * MailHog: [http://localhost:8025](http://localhost:8025)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- USAGE -->
## Usage

**Run the red-team agent**

With the stack up, attack it from another terminal. The red agent probes the
proxied DVWA and finds the exploit live:
```sh
.venv/bin/python red_agent.py sqli     # SQL injection, data exfiltration
.venv/bin/python red_agent.py cmdi     # command injection, RCE
```

**Watch the blue agent respond**

As the red agent probes, the dashboard feed lights up. On a confirmed attack the
blue agent files an incident, bans the attacker's IP, adds a WAF rule, and drops
an email into MailHog. Re-run the same attack and the proxy now returns `403`:
same exploit, now dead. Running the command-injection case proves it defends more
than one attack class.

**Manual test (no agents)**

You can exercise the pipeline directly with curl. Send a benign request (200),
then an obvious SQLi (the blue agent should ban within about 2 seconds), then the
same request again (403):
```sh
curl -s -o /dev/null -w "%{http_code}\n" -H 'X-Forwarded-For: 9.9.9.9' \
  "http://localhost:8080/vulnerabilities/sqli/?id=1%27+OR+%271%27=%271&Submit=Submit"
```

**Notes**

DVWA runs at Security=Low, which is the red agent's target. Everything is local;
never expose DVWA publicly. The `# ponytail` comments in the code flag the
demo-grade corners and their upgrade paths. See `architecture.md` for the full
design.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ROADMAP -->
## Roadmap

- [x] Reverse proxy that is both log source and enforcement point (denylist + WAF)
- [x] Blue-team agent: real-time detect, IP blacklist, virtual patch, email incident report
- [x] Regex pre-filter to gate what reaches the model and keep cost predictable
- [x] Live dashboard at `/__dashboard`
- [x] Scoped autonomous red-team agent (SQL injection, command injection)
- [ ] Broader attack coverage (XSS, path traversal, file upload)
- [ ] Persistent incident store and historical dashboard views
- [ ] Configurable detection policy and per-rule tuning without code changes

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
[contributors-shield]: https://img.shields.io/github/contributors/adamhjouj/bastion.svg?style=for-the-badge&cacheSeconds=60
[contributors-url]: https://github.com/adamhjouj/bastion/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/adamhjouj/bastion.svg?style=for-the-badge&cacheSeconds=60
[forks-url]: https://github.com/adamhjouj/bastion/network/members
[stars-shield]: https://img.shields.io/github/stars/adamhjouj/bastion.svg?style=for-the-badge&cacheSeconds=60
[stars-url]: https://github.com/adamhjouj/bastion/stargazers
[issues-shield]: https://img.shields.io/github/issues/adamhjouj/bastion.svg?style=for-the-badge&cacheSeconds=60
[issues-url]: https://github.com/adamhjouj/bastion/issues
[license-shield]: https://img.shields.io/github/license/adamhjouj/bastion.svg?style=for-the-badge&cacheSeconds=60
[license-url]: https://github.com/adamhjouj/bastion/blob/main/LICENSE

[Python-badge]: https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white
[Python-url]: https://www.python.org/
[Anthropic-badge]: https://img.shields.io/badge/Anthropic-191919?style=for-the-badge&logo=anthropic&logoColor=white
[Anthropic-url]: https://www.anthropic.com/
[FastAPI-badge]: https://img.shields.io/badge/FastAPI-009688?style=for-the-badge&logo=fastapi&logoColor=white
[FastAPI-url]: https://fastapi.tiangolo.com/
[Uvicorn-badge]: https://img.shields.io/badge/Uvicorn-2094F3?style=for-the-badge&logo=gunicorn&logoColor=white
[Uvicorn-url]: https://www.uvicorn.org/
[Docker-badge]: https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white
[Docker-url]: https://www.docker.com/
