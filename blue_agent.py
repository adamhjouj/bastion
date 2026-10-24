"""Autonomous blue-team agent. Tails the proxy's request log, cheap regex
pre-filter gates what reaches the LLM (so it idles for free on benign traffic),
then Claude classifies suspicious batches and calls tools to blacklist the IP,
add a virtual-patch WAF rule, and email an incident report."""
import json
import os
import re
import smtplib
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.message import EmailMessage
from urllib.parse import parse_qs, unquote_plus

import llm
import store
from classifier import classify_request

try:  # eradication tools live in a sibling module; keep the agent runnable without them
    from remediation_tools import REGISTER as REMEDIATION_REGISTER
except Exception:
    REMEDIATION_REGISTER = None

try:  # control-plane actions (kill_session/egress/quarantine); LLM stays unprivileged — see actuator.py
    from actuator import REGISTER as CONTROL_REGISTER
except Exception:
    CONTROL_REGISTER = None

try:  # soft containment: divert a confirmed attacker to a decoy instead of a hard ban
    from honeypot_tools import REGISTER as HONEYPOT_REGISTER
except Exception:
    HONEYPOT_REGISTER = None

# Read-only situational-awareness tools + the tool catalog/environment briefing the
# agent is taught in its system prompt (see tools.py).
from tools import ORIENT_REGISTER, catalog, ENVIRONMENT

MODEL = llm.model_for(os.environ.get("BLUE_MODEL"), "claude-sonnet-5")
POLL = 1.0
# System-1 triage via Jev (auto-off if no key); regex pre-gate keeps Jev off benign traffic.
USE_JEV = os.environ.get("USE_JEV", "1") == "1" and bool(os.environ.get("TYPESAFE_API_KEY"))
USE_REGEX_PREGATE = os.environ.get("USE_REGEX_PREGATE", "1") == "1"
# DESIGN: Jev FLAGS, the agent DECIDES. Jev has NO authority to block — a bare score->ban
# is just a worse Cloudflare and steals the agent's whole reason to exist. Default: every
# flagged request is handed to the agent, which owns ALL enforcement (ban / WAF rule /
# divert / patch / incident). JEV_AUTOBLOCK is OFF by default; it is only insurance:
#   - agent present + JEV_AUTOBLOCK=1: on a very-high-confidence flag Jev may take ONE
#     reversible holding action — a silent DIVERT to the decoy (never a ban) — while the
#     agent is still handed the case. Buys latency without Jev deciding anything.
#   - no agent available (no LLM key): Jev contains on its own (TTL ban + canned rule +
#     email). The sole case Jev enforces, because nothing else can.
JEV_AUTOBLOCK = os.environ.get("JEV_AUTOBLOCK", "0") == "1"
# Confidence at/above which the opt-in reflex may fire its reversible divert.
AUTOBLOCK_HIGH = float(os.environ.get("AUTOBLOCK_HIGH", "0.9"))
# No-agent fallback bans are provisional: a short-TTL IP ban that auto-lifts (cheap to be
# wrong about — one IP, not a class-wide rule).
AUTOBLOCK_TTL_MIN = int(os.environ.get("AUTOBLOCK_TTL_MIN", "15"))
# The LLM agent (system-2) is optional enrichment; on if an Anthropic OR DeepSeek
# key is present (see llm.py for provider selection).
USE_AGENT = llm.provider() is not None
# Swarm: max concurrent defenders (one per distinct attacker IP) per poll. Caps spend/
# rate under a flood; attackers beyond the cap wait their turn in the pool queue.
SWARM_MAX = int(os.environ.get("SWARM_MAX", "4"))
# Botnet tier: at/above this many distinct source IPs in one poll, stop fighting each IP
# and hand the whole batch to ONE campaign-level SUPERVISOR (commander) — a class-wide WAF
# rule + bulk ban + one consolidated incident, instead of N per-IP defender loops. Below
# it, the per-IP swarm handles the handful of distinct attackers.
SUPERVISOR_MIN = int(os.environ.get("SUPERVISOR_MIN", "8"))

# Deterministic virtual-patch rules per attack type (used by autoblock, no LLM).
CANNED_WAF = {
    "sql_injection": r"(?i)(union\s+select|\bor\s+1\s*=\s*1|'\s*or\s*'|information_schema|\bsleep\s*\(|--\s|\bupdatexml\b)",
    # Require a shell-metachar / command context — NOT bare words like "id",
    # which would match the ubiquitous ?id= parameter and over-block everything.
    "command_injection": r"(?i)(;\s*\w|&&\s*\w|\|\s*(cat|whoami|id|ls|uname|sh|bash|nc|wget|curl|echo|ping)\b|\$\(|`|/etc/(passwd|shadow)|/bin/)",
    "xss": r"(?i)(<script|onerror\s*=|onload\s*=|javascript:)",
    "path_traversal": r"(?i)(\.\./|\.\.\\|%2e%2e|/etc/passwd)",
}

# Gate: only requests containing these tokens are worth an LLM call.
# ponytail: naive signature pre-filter — it only decides what to *look* at;
# the LLM makes the actual call, so a miss here just means no alert, not a bad one.
SUSPICIOUS = re.compile(r"""(?ix)
    ( union\s+select | or\s+1=1 | '\s*or\s*' | \bsleep\s*\( | information_schema
    | --\s | \# | ;\s*\w | \|\| | && | \$\( | `.*` | /bin/ | /etc/passwd
    | \bcat\s | \bwhoami\b | \bnc\s | \bwget\s | \bcurl\s
    | \.\./ | \.\.\\ | <script | <svg | onerror= | onload\s*= | javascript: | %2e%2e )
""")

SYSTEM = (
    "You are an autonomous SOC blue-team agent protecting a web application. You "
    "receive recent HTTP requests captured at a reverse proxy in front of the app. "
    "Decide whether any request is a real attack. Known classes: SQL injection, "
    "command injection, path traversal, XSS.\n\n"
    "You are the SOLE decision-maker. Jev (system-1) only FLAGS what deserves a look — "
    "it has NO authority to block. Every enforcement action (blacklist, WAF rule, "
    "divert, patch, incident) is yours to take or withhold.\n\n"
    "The Jev system-1 classifier already flagged these as SUSPICIOUS, but it is "
    "twitchy and advisory — a flag is a reason to LOOK, not proof of an attack. "
    "Before acting on any request you are not certain about, call inspect_target "
    "to get read-only structural evidence (decoded params, path-escape check, "
    "shell/SQL/XSS tokens, whether the endpoint is real). If that evidence shows the "
    "request is benign (e.g. a bare host like ip=127.0.0.1 with no shell metacharacters, "
    "or a file param that stays inside its directory), reply 'no threat' and take NO "
    "action — do not blacklist or add a rule. Only act on a confirmed attack.\n\n"
    "For each distinct attacker you CONFIRM is malicious:\n"
    "1. call blacklist_ip on the source IP;\n"
    "2. call add_waf_rule with a TIGHT regex that blocks that specific exploit "
    "pattern (match the payload tokens, e.g. 'union\\s+select' or ';\\s*cat', NOT "
    "broad patterns that would block normal traffic);\n"
    "3. call raise_alert with concrete evidence and a one-line summary of what "
    "happened and what you did.\n"
    "4. if patch_vuln is available and containment alone is insufficient, call it "
    "to raise the app's security posture (real eradication beyond the WAF). Note "
    "it hardens the whole app, so reserve it for a confirmed, serious exploit.\n\n"
    "A very-high-confidence flag may already have been DIVERTED to the decoy by the "
    "reflex as a reversible holding action (the IP appears in the honeypot list, NOT "
    "banned). Confirm it, then decide the durable response: keep diverting to harvest, "
    "and/or blacklist_ip + add the tight WAF rule. If it was a false flag, call "
    "undivert(ip). The reflex never bans — every ban is your decision.\n\n"
    "Soft-containment alternative: if divert_to_honeypot is available and you want to "
    "harvest the attacker's techniques or buy a remediation window rather than ban "
    "immediately, call divert_to_honeypot(ip) to silently route them to a decoy (a hard "
    "ban tips them off; a divert does not). undivert(ip) reverses it — use it to release "
    "a false positive.\n\n"
    "RESPONSE PLAYBOOK — match the situation to the right tool, don't stop at ban+rule:\n"
    "- Recon/probing you want to study -> divert_to_honeypot to harvest TTPs; undivert to release.\n"
    "- SQLi / XSS / path traversal (payload-pattern attacks) -> blacklist_ip + a TIGHT add_waf_rule; "
    "patch_vuln if the hole is serious.\n"
    "- Command injection / RCE -> besides the WAF rule, call list_processes on the target and "
    "kill_process any [NEW] (non-baseline) pid (e.g. a reverse shell), and isolate_egress to cut "
    "C2 / data exfil / second-stage payload pulls.\n"
    "- Confirmed credential exposure (SQLi dumped creds, config/file read, secrets read via RCE) -> "
    "rotate_secret so stolen DB credentials are instantly useless.\n"
    "- Authenticated or agentic attacker, or one rotating source IPs -> kill_session (an IP ban won't "
    "help; the source IP is client-asserted and spoofable); prefer a class-wide add_waf_rule over an IP ban.\n"
    "- Active, ongoing, high-severity compromise you cannot otherwise contain -> quarantine_container "
    "(freezes the target); release_container once safe. Nuclear, last resort.\n"
    "Orient before acting: get_defenses (what you already enforce; never duplicate it), recent_requests "
    "(is this IP still probing / is it a flood), service_status (is the target already quarantined). "
    "Act proportionally to the confirmed severity, then stop.\n\n"
    "If traffic is benign, do nothing and reply 'no threat'. Never duplicate an "
    "action already listed in current defenses. Be decisive."
)

# Botnet / distributed-campaign commander. Used instead of the per-IP doctrine when many
# source IPs attack at once (see SUPERVISOR_MIN). Fight the CAMPAIGN, not each bot.
SUPERVISOR_DOCTRINE = (
    "You are the INCIDENT COMMANDER for a COORDINATED, MULTI-SOURCE attack: many source IPs "
    "hitting the app at once — a botnet or distributed campaign, likely one shared technique. "
    "Do NOT fight each IP separately; that doesn't scale and misses the point. Respond at the "
    "CAMPAIGN level, with a handful of class-wide actions, not hundreds of per-IP ones:\n"
    "1. PRIMARY WEAPON: one TIGHT class-wide add_waf_rule per distinct technique. A WAF rule "
    "matches the payload regardless of source IP, so ONE rule blocks the WHOLE botnet at once. "
    "Match the shared payload tokens (e.g. 'union\\s+select', ';\\s*cat'), never broad patterns "
    "that would block normal traffic.\n"
    "2. bulk_blacklist_ip the observed participant IPs in ONE call (a list) as a second layer — "
    "not blacklist_ip per IP.\n"
    "3. If the sheer VOLUME threatens availability (not just exploitation), the proxy already "
    "rate-limits per IP; escalate with isolate_egress or (last resort) quarantine_container on "
    "the target.\n"
    "4. patch_vuln if the underlying hole is serious.\n"
    "5. raise ONE consolidated raise_alert describing the campaign (scale, sources, technique, "
    "your response) — not one alert per IP.\n"
    "Orient first with get_defenses so you don't duplicate a rule already in place. Be decisive "
    "and economical. If a cluster looks benign on inspection, say so and don't act on it."
)

TOOLS = [
    {"name": "blacklist_ip",
     "description": "Block all current and future requests from this source IP at the proxy.",
     "input_schema": {"type": "object",
                      "properties": {"ip": {"type": "string"},
                                     "reason": {"type": "string"}},
                      "required": ["ip", "reason"]}},
    {"name": "bulk_blacklist_ip",
     "description": "Block MANY source IPs at once (botnet / distributed campaign). One call, "
                    "a list of IPs — far better than calling blacklist_ip per IP. Prefer a "
                    "class-wide add_waf_rule as the primary weapon; use this to sweep the "
                    "observed participants.",
     "input_schema": {"type": "object",
                      "properties": {"ips": {"type": "array", "items": {"type": "string"},
                                             "description": "source IPs to ban"},
                                     "reason": {"type": "string"}},
                      "required": ["ips", "reason"]}},
    {"name": "add_waf_rule",
     "description": "Virtually patch a vulnerability by blocking any request whose "
                    "method/path/query/body matches this Python regex (case-insensitive), "
                    "regardless of source IP.",
     "input_schema": {"type": "object",
                      "properties": {"pattern": {"type": "string"},
                                     "description": {"type": "string"}},
                      "required": ["pattern", "description"]}},
    {"name": "inspect_target",
     "description": "Read-only investigation of a flagged request. Returns structural "
                    "evidence (url-decoded params, whether a file/path param escapes its "
                    "directory, presence of shell/SQL/XSS tokens, whether the endpoint is "
                    "a real app endpoint). Does NOT re-send or execute the request. Use it "
                    "to confirm or clear a suspicious request before acting.",
     "input_schema": {"type": "object",
                      "properties": {"method": {"type": "string"},
                                     "path": {"type": "string"},
                                     "query": {"type": "string"},
                                     "body": {"type": "string"}},
                      "required": ["path"]}},
    {"name": "raise_alert",
     "description": "Email a human-readable incident report and record the incident.",
     "input_schema": {"type": "object",
                      "properties": {
                          "severity": {"type": "string",
                                       "enum": ["low", "medium", "high", "critical"]},
                          "attack_type": {"type": "string"},
                          "source_ip": {"type": "string"},
                          "evidence": {"type": "string"},
                          "summary": {"type": "string"}},
                      "required": ["severity", "attack_type", "source_ip",
                                   "evidence", "summary"]}},
]


def is_suspicious(ev):
    blob = f"{ev.get('path', '')} {ev.get('query', '')} {ev.get('body', '')}"
    return bool(SUSPICIOUS.search(blob))


# ---- tool implementations ----

def _apply_ban(denylist, ip, reason, expires):
    """Strengthen-only denylist mutation on an in-memory list (caller holds state_lock and
    saves). A durable ban (expires=None) overrides a TTL; a later TTL extends an earlier one;
    never weakens. Returns True if it changed anything. Single source for the ban rule, so
    do_blacklist_ip and do_bulk_blacklist_ip stay identical."""
    existing = next((d for d in denylist if d["ip"] == ip), None)
    if existing is None:
        denylist.append({"ip": ip, "reason": reason, "ts": store.now(), "expires": expires})
        return True
    cur = existing.get("expires")
    if expires is None and cur is not None:              # TTL -> durable (agent confirmed)
        existing.update({"expires": None, "reason": reason})
        return True
    if expires is not None and cur is not None and expires > cur:  # extend TTL
        existing["expires"] = expires
        return True
    return False


def do_blacklist_ip(ip, reason, expires=None):
    """Ban an IP. expires=None is a durable ban (agent-confirmed); an ISO timestamp is
    a provisional TTL ban (system-1 reflex). Re-banning only STRENGTHENS (see _apply_ban)."""
    with store.state_lock:  # serialize read-modify-write so concurrent defenders don't clobber
        st = store.load_state()
        if _apply_ban(st["denylist"], ip, reason, expires):
            store.save_state(st)
    return f"IP {ip} blacklisted." + (f" (expires {expires})" if expires else "")


def do_bulk_blacklist_ip(ips, reason, expires=None):
    """Ban MANY IPs in one call (botnet containment) under ONE state_lock / ONE save_state —
    not N serialized writes. Accepts a list or a comma-separated string. Strengthen-only per IP."""
    if isinstance(ips, str):
        ips = [p.strip() for p in ips.split(",") if p.strip()]
    ips = [i for i in (ips or []) if i]
    changed = 0
    with store.state_lock:
        st = store.load_state()
        for ip in ips:
            changed += _apply_ban(st["denylist"], ip, reason, expires)
        if changed:
            store.save_state(st)
    shown = ", ".join(ips[:10]) + ("…" if len(ips) > 10 else "")
    return f"Bulk-blacklisted {len(ips)} IP(s) ({changed} new/strengthened): {shown}"


def do_add_waf_rule(pattern, description):
    try:
        re.compile(pattern)
    except re.error as e:
        return f"Invalid regex, not added: {e}"
    with store.state_lock:  # serialize read-modify-write (swarm-safe)
        st = store.load_state()
        if not any(r["pattern"] == pattern for r in st["rules"]):
            st["rules"].append({"pattern": pattern, "description": description, "ts": store.now()})
            store.save_state(st)
    return f"WAF rule added: {description}"


# Real DVWA endpoints (from the vulnerables/web-dvwa image) — a request to anything
# outside this set is itself a weak signal (scanning / unexpected path).
KNOWN_ENDPOINTS = {
    "/login.php", "/index.php", "/security.php", "/instructions.php", "/setup.php",
    "/logout.php", "/about.php", "/phpinfo.php", "/ids_log.php",
    "/vulnerabilities/sqli/", "/vulnerabilities/sqli_blind/", "/vulnerabilities/exec/",
    "/vulnerabilities/fi/", "/vulnerabilities/xss_r/", "/vulnerabilities/xss_s/",
    "/vulnerabilities/xss_d/", "/vulnerabilities/csrf/", "/vulnerabilities/brute/",
    "/vulnerabilities/upload/", "/vulnerabilities/captcha/", "/vulnerabilities/csp/",
    "/vulnerabilities/javascript/",
}
# NB: bare '&' is HTTP form-param syntax (ip=x&Submit=y), NOT a shell op — exclude it;
# '&&' (real chained command) stays as an explicit alternative.
_SHELL_META = re.compile(r"[;|`]|\$\(|\|\||&&|>")
_SQL_TOK = re.compile(r"(?i)union\s+select|\bor\s+1\s*=\s*1|'\s*or\s*'|information_schema|--\s|\bsleep\s*\(")
_XSS_TOK = re.compile(r"(?i)<script|onerror\s*=|onload\s*=|javascript:")


def do_inspect_target(path, method="GET", query="", body=""):
    """Read-only structural evidence for the agent to judge a flagged request.
    Derives facts; never re-sends or executes anything (the proxy already ran it)."""
    params = {k: v[0] for k, v in
              parse_qs(unquote_plus(query) + "&" + unquote_plus(body)).items()}
    blob = " ".join([unquote_plus(query), unquote_plus(body)])
    ev = {"known_endpoint": path in KNOWN_ENDPOINTS,
          "shell_metachars": bool(_SHELL_META.search(blob)),
          "sql_tokens": bool(_SQL_TOK.search(blob)),
          "xss_tokens": bool(_XSS_TOK.search(blob)),
          "decoded_params": params}
    # File-inclusion / traversal check: does a path-like param escape its directory?
    for k, val in params.items():
        if "/" in val or ".." in val or "\\" in val:
            norm = os.path.normpath(val.replace("\\", "/"))
            ev["path_param"] = {"name": k, "value": val, "normalized": norm,
                                "escapes_dir": norm.startswith("..") or norm.startswith("/")}
            break
    return json.dumps(ev)


def do_raise_alert(severity, attack_type, source_ip, evidence, summary):
    inc = {"ts": store.now(), "severity": severity, "attack_type": attack_type,
           "source_ip": source_ip, "evidence": evidence, "summary": summary}
    store.append_jsonl(store.INCIDENTS_FILE, inc)
    send_email(inc)
    return "Alert raised and email sent."


DISPATCH = {"blacklist_ip": do_blacklist_ip, "bulk_blacklist_ip": do_bulk_blacklist_ip,
            "add_waf_rule": do_add_waf_rule,
            "raise_alert": do_raise_alert, "inspect_target": do_inspect_target}

# Register eradication tools (patch_vuln, and future lock_egress/kill_session/…).
# Each REGISTER entry is {"name", "schema", "fn"}; accepts a single dict or a list.
if REMEDIATION_REGISTER:
    for _reg in (REMEDIATION_REGISTER if isinstance(REMEDIATION_REGISTER, list)
                 else [REMEDIATION_REGISTER]):
        TOOLS.append(_reg["schema"])
        DISPATCH[_reg["name"]] = _reg["fn"]

# Control-plane actions, folded in via the same {name,schema,fn} hook, with
# dedupe so we never register a tool name the remediation module already took.
if CONTROL_REGISTER:
    _have = {t["name"] for t in TOOLS}
    for _reg in CONTROL_REGISTER:
        if _reg["name"] in _have:
            continue
        TOOLS.append(_reg["schema"])
        DISPATCH[_reg["name"]] = _reg["fn"]
        _have.add(_reg["name"])

# Honeypot divert tools (divert_to_honeypot / undivert), same {name,schema,fn} hook.
if HONEYPOT_REGISTER:
    _have = {t["name"] for t in TOOLS}
    for _reg in HONEYPOT_REGISTER:
        if _reg["name"] in _have:
            continue
        TOOLS.append(_reg["schema"])
        DISPATCH[_reg["name"]] = _reg["fn"]
        _have.add(_reg["name"])

# Read-only orientation tools (get_defenses / recent_requests / recent_incidents /
# service_status), same {name,schema,fn} hook — so the agent can SEE its environment.
_have = {t["name"] for t in TOOLS}
for _reg in ORIENT_REGISTER:
    if _reg["name"] in _have:
        continue
    TOOLS.append(_reg["schema"])
    DISPATCH[_reg["name"]] = _reg["fn"]
    _have.add(_reg["name"])

# Teach the agent its environment + the full, live tool set (every registered tool,
# grouped by purpose) by prepending them to the doctrine above. Generated from TOOLS,
# so a newly registered tool is taught automatically — the agent is never blind to a
# tool it can call.
SYSTEM = (ENVIRONMENT
          + "\n\nYOUR TOOLS — call them by exact name (orient with the read-only ones "
            "before you act):\n" + catalog(TOOLS)
          + "\n\n--- OPERATING DOCTRINE ---\n" + SYSTEM)

# Commander prompt for the botnet tier — same environment + tool catalog, campaign doctrine.
SUPERVISOR_SYSTEM = (ENVIRONMENT
                     + "\n\nYOUR TOOLS — call them by exact name:\n" + catalog(TOOLS)
                     + "\n\n--- COMMANDER DOCTRINE ---\n" + SUPERVISOR_DOCTRINE)


def record_action(tool, inp, result):
    # mirror every executed action onto the dashboard timeline (actions.jsonl),
    # whether it came from Claude's dispatch loop or from Jev autoblock.
    store.append_jsonl(store.ACTIONS_FILE, {
        "ts": store.now(), "kind": "action", "tool": tool, "input": inp, "result": result,
    })


def record_triage(e, escalated, outcome):
    # one triage record per candidate the agent evaluated; powers the funnel + action log.
    store.append_jsonl(store.ACTIONS_FILE, {
        "ts": store.now(), "kind": "triage", "ip": e.get("ip"),
        "method": e.get("method"), "path": e.get("path"), "query": e.get("query"),
        "regex_hit": USE_REGEX_PREGATE, "jev": e.get("_jev"),
        "escalated": escalated, "outcome": outcome,
    })


def reflex_divert(event, verdict):
    """Opt-in insurance (JEV_AUTOBLOCK=1), agent present: on a very-high-confidence flag,
    silently DIVERT the IP to the decoy as a REVERSIBLE holding action while the agent is
    handed the case. No ban, no rule, no email — Jev makes NO enforcement decision here;
    the agent owns ban/patch/divert/incident. No-op if no honeypot tool is wired."""
    if "divert_to_honeypot" not in DISPATCH:
        return
    ip = event["ip"]
    atk = verdict["attack_type"]
    score = verdict.get("malicious_score") or 0.0
    dreason = f"reflex-divert: Jev {atk} ({score:.2f}) pending agent triage"
    rd = DISPATCH["divert_to_honeypot"](ip=ip, reason=dreason)
    record_action("divert_to_honeypot", {"ip": ip, "reason": dreason}, rd)
    print(f"[blue] REFLEX-DIVERT {ip} ({atk}, {score:.2f}) -> decoy (reversible); "
          f"agent decides the response", flush=True)


def autoblock(event, verdict):
    """NO-AGENT FALLBACK ONLY: with no system-2 agent available, Jev contains on its own —
    the sole case Jev enforces, because nothing else can. Provisional TTL IP ban + canned
    virtual-patch rule + email. When an agent is present it owns all enforcement and this
    is never called."""
    ip = event["ip"]
    atk = verdict["attack_type"]
    score = verdict.get("malicious_score") or 0.0
    evidence = f"{event.get('method')} {event.get('path')}?{event.get('query', '')} {event.get('body', '')}".strip()
    expires = store.now_plus(AUTOBLOCK_TTL_MIN * 60)
    reason = f"Jev-only fallback {atk} ({score:.2f}); provisional {AUTOBLOCK_TTL_MIN}m ban"
    r1 = do_blacklist_ip(ip, reason, expires=expires)
    record_action("blacklist_ip", {"ip": ip, "reason": reason, "expires": expires}, r1)
    actions = [r1]
    rule = CANNED_WAF.get(atk)
    if rule:
        desc = f"auto: block {atk} (Jev, no-agent fallback)"
        r2 = do_add_waf_rule(rule, desc)
        record_action("add_waf_rule", {"pattern": rule, "description": desc}, r2)
        actions.append(r2)
    sev = "critical" if score >= 0.9 else "high"
    summary = "Jev system-1 (no agent) contained attack; " + "; ".join(actions)
    r3 = do_raise_alert(sev, atk, ip, evidence, summary)
    record_action("raise_alert", {"severity": sev, "attack_type": atk, "source_ip": ip,
                                   "evidence": evidence, "summary": summary}, r3)
    print(f"[blue] AUTOBLOCK {ip} ({atk}, {score:.2f}) -> {AUTOBLOCK_TTL_MIN}m IP ban + "
          f"{'canned WAF rule + ' if rule else ''}email (no agent)", flush=True)


def _markdown_report(inc):
    """Organized Markdown incident report — the email body AND the .md attachment."""
    return (
        f"# 🛡️ Security Incident Report\n\n"
        f"| Field | Value |\n"
        f"|---|---|\n"
        f"| **Severity** | {inc['severity'].upper()} |\n"
        f"| **Attack type** | {inc['attack_type']} |\n"
        f"| **Source IP** | `{inc['source_ip']}` |\n"
        f"| **Detected** | {inc['ts']} |\n"
        f"| **Reported by** | Bastion autonomous blue-team agent |\n\n"
        f"## Evidence\n\n"
        f"```\n{inc['evidence']}\n```\n\n"
        f"## Response taken\n\n"
        f"{inc['summary']}\n\n"
        f"---\n"
        f"_Automated incident report generated by Bastion. Containment was applied at "
        f"the reverse proxy and takes effect on the next matching request._\n"
    )


def send_email(inc):
    host = os.environ.get("SMTP_HOST", "localhost")
    port = int(os.environ.get("SMTP_PORT", "1025"))
    user, pw = os.environ.get("SMTP_USER"), os.environ.get("SMTP_PASS")
    report = _markdown_report(inc)
    fname = f"incident-{inc['attack_type']}-{inc['source_ip'].replace(':', '_')}.md"
    msg = EmailMessage()
    msg["Subject"] = f"[{inc['severity'].upper()}] {inc['attack_type']} from {inc['source_ip']}"
    msg["From"] = os.environ.get("ALERT_FROM", "blue-agent@breach-agent.local")
    msg["To"] = os.environ.get("ALERT_TO", "soc@example.com")
    msg.set_content(report)  # Markdown report as the body
    # ...and the same report as a downloadable .md attachment.
    msg.add_attachment(report.encode("utf-8"), maintype="text", subtype="markdown",
                       filename=fname)
    try:
        with smtplib.SMTP(host, port, timeout=10) as s:
            if user and pw:
                s.starttls()
                s.login(user, pw)
            s.send_message(msg)
        print(f"[blue] incident report emailed to {msg['To']} (+{fname})", flush=True)
    except Exception as e:  # never let a mail failure kill the loop
        print(f"[blue] email send failed: {e}", file=sys.stderr)


def _run_agent(client, system, user_text, create_kwargs=None):
    """Drive one tool-use loop: send the case, execute each tool call (dispatched by name,
    audited to the dashboard timeline), feed the results back, repeat until the model stops.
    Shared by the per-IP defender (analyse) and the campaign commander (supervise)."""
    create_kwargs = create_kwargs or {}
    messages = [{"role": "user", "content": user_text}]
    while True:
        resp = client.messages.create(
            model=MODEL, max_tokens=4096, system=system, tools=TOOLS,
            messages=messages, **create_kwargs)
        if resp.stop_reason != "tool_use":
            break
        messages.append({"role": "assistant", "content": resp.content})
        results = []
        for b in resp.content:
            if b.type == "tool_use":
                fn = DISPATCH.get(b.name)
                out = fn(**b.input) if fn else f"unknown tool {b.name}"
                print(f"[blue] ACTION {b.name}({b.input}) -> {out}")
                record_action(b.name, b.input, out)  # onto the dashboard timeline
                results.append({"type": "tool_result", "tool_use_id": b.id, "content": out})
        messages.append({"role": "user", "content": results})


def analyse(client, events, create_kwargs=None):
    """Per-IP defender: hand one attacker's flagged requests (+ Jev verdicts) and the current
    defenses to the agent, which investigates and responds with the full toolset."""
    st = store.load_state()
    payload = []
    for e in events:
        item = {k: e.get(k) for k in ("ts", "ip", "method", "path", "query", "body", "status")}
        if e.get("_jev"):
            item["jev_classifier"] = e["_jev"]  # system-1 verdict (advisory)
        payload.append(item)
    user = ("Suspicious HTTP requests flagged at the reverse proxy, each with the "
            "system-1 classifier (Jev) verdict (advisory — confirm before acting):\n\n"
            + json.dumps(payload, indent=2)
            + "\n\nCurrent defenses already in place:\n"
            + json.dumps({"denylist": st["denylist"], "rules": st["rules"]}, indent=2))
    _run_agent(client, SYSTEM, user, create_kwargs)


def _dedupe(events):
    """Collapse identical (ip, method, path, query, body) requests to one representative,
    so a flood of the same payload becomes ONE case instead of N agent calls. Keeps the
    first occurrence (it carries that request's Jev verdict)."""
    seen = {}
    for e in events:
        key = (e.get("ip"), e.get("method"), e.get("path"), e.get("query"), e.get("body"))
        seen.setdefault(key, e)
    return list(seen.values())


def _sig(e):
    """Normalized attack signature (method+path+query+body, whitespace-collapsed and
    lowercased) so trivially-mutated floods (case/whitespace) still collapse to one — used
    to classify an identical-payload flood with ONE Jev call instead of N."""
    blob = f"{e.get('method', '')} {e.get('path', '')} {e.get('query', '')} {e.get('body', '')}"
    return re.sub(r"\s+", " ", blob).strip().lower()


def _campaign_summary(events):
    """Aggregate a flood into a COMPACT brief for the commander: per attack-type cluster, the
    participant-IP count + a sample of IPs and payloads. Stays small even at hundreds of IPs
    (the prompt never carries one line per request)."""
    clusters = {}
    for e in events:
        atk = (e.get("_jev") or {}).get("attack_type") or "unknown"
        c = clusters.setdefault(atk, {"ips": [], "payloads": set(), "paths": set()})
        if e.get("ip") not in c["ips"]:
            c["ips"].append(e.get("ip"))
        c["payloads"].add(f"{e.get('method')} {e.get('path')}?{e.get('query', '')} "
                          f"{e.get('body', '')}".strip())
        c["paths"].add(e.get("path"))
    total = len({e.get("ip") for e in events})
    lines = [f"COORDINATED MULTI-SOURCE ATTACK: {total} distinct source IP(s) hitting the app "
             f"in this window. Treat it as ONE campaign, not {total} separate incidents.\n"]
    for atk, c in clusters.items():
        ips = c["ips"]
        lines.append(f"[{atk}] {len(ips)} source IP(s); path(s): {sorted(c['paths'])}")
        for p in list(c["payloads"])[:4]:
            lines.append(f"    payload: {p[:200]}")
        shown = ips[:40]
        more = len(ips) - len(shown)
        lines.append(f"    source IPs: {shown}"
                     + (f" (+{more} more — a class-wide WAF rule covers them all "
                        f"regardless of IP)" if more > 0 else ""))
    return "\n".join(lines)


def supervise(client, events, create_kwargs):
    """Botnet tier: ONE campaign-level commander for the whole flood — a class-wide WAF rule
    + a bulk ban + one consolidated incident — instead of N per-IP defender loops."""
    st = store.load_state()
    user = (_campaign_summary(events)
            + "\n\nCurrent defenses already in place:\n"
            + json.dumps({"denylist_count": len(st["denylist"]), "rules": st["rules"]}, indent=2))
    _run_agent(client, SUPERVISOR_SYSTEM, user, create_kwargs)


def dispatch_swarm(client, events, create_kwargs):
    """Fan out ONE concurrent defender per distinct attacker IP (bounded by SWARM_MAX),
    each running its own analyse() tool-use loop focused on that IP — so swarms of attackers
    get swarms of defenders instead of one serialized batch. Per-IP requests are deduped
    first; all state writes are store.state_lock-guarded so concurrent bans/rules/diverts
    don't clobber each other. Waits for the poll's defenders to finish before returning."""
    deduped = _dedupe(events)
    by_ip = {}
    for e in deduped:
        by_ip.setdefault(e.get("ip"), []).append(e)
    # Botnet tier: many distinct source IPs at once -> ONE campaign commander, not N defenders.
    if len(by_ip) >= SUPERVISOR_MIN:
        print(f"[blue] SUPERVISOR: {len(by_ip)} source IPs -> one campaign commander "
              f"(class-wide response, not {len(by_ip)} per-IP defenders)", flush=True)
        supervise(client, deduped, create_kwargs)
        return
    print(f"[blue] swarm: {len(by_ip)} attacker IP(s) -> "
          f"{min(len(by_ip), SWARM_MAX)} concurrent defenders (cap {SWARM_MAX})", flush=True)
    with ThreadPoolExecutor(max_workers=SWARM_MAX) as pool:
        futs = {pool.submit(analyse, client, evs, create_kwargs): ip
                for ip, evs in by_ip.items()}
        for fut in as_completed(futs):
            try:
                fut.result()
            except Exception as ex:
                print(f"[blue] defender {futs[fut]} error: {ex}", file=sys.stderr, flush=True)


def main():
    client, create_kwargs = llm.make_client()
    agent_label = llm.provider() or "agent"
    mode = "+".join(m for m, on in (("regex", USE_REGEX_PREGATE), ("Jev", USE_JEV),
                                    ("autoblock", JEV_AUTOBLOCK and USE_JEV),
                                    (agent_label, USE_AGENT)) if on) or "none"
    print(f"[blue] watching {store.EVENTS_FILE}; pipeline: {mode}", flush=True)
    if not USE_JEV and not USE_AGENT:
        print("[blue] WARNING: no decision engine (no Jev key, no agent key)",
              file=sys.stderr, flush=True)
    offset = len(store.read_jsonl(store.EVENTS_FILE))  # skip pre-existing lines
    while True:
        evs = store.read_jsonl(store.EVENTS_FILE)
        new, offset = evs[offset:], len(evs)
        blocked_ips = {d["ip"] for d in store.load_state()["denylist"]}
        candidates = [e for e in new if not e["blocked"] and e["ip"] not in blocked_ips
                      and (not USE_REGEX_PREGATE or is_suspicious(e))]
        to_claude = []
        jev_cache = {}  # per-poll memo: an identical-payload flood is classified ONCE, not per IP
        for e in candidates:
            if not USE_JEV:
                e["_jev"] = None
                if USE_AGENT:
                    to_claude.append(e)
                    record_triage(e, escalated=True, outcome="claude")
                else:
                    record_triage(e, escalated=False, outcome="no_engine")
                continue
            sig = _sig(e)
            v = jev_cache.get(sig)
            if v is None:
                v = classify_request(e)
                jev_cache[sig] = v
            e["_jev"] = v
            if v.get("error"):                     # couldn't classify -> Claude if available
                print(f"[blue] jev error ({e['ip']} {e['path']}): {v['error']}",
                      file=sys.stderr, flush=True)
                if USE_AGENT:
                    to_claude.append(e)
                    record_triage(e, escalated=True, outcome="claude")
                else:
                    record_triage(e, escalated=False, outcome="jev_error")
                continue
            if not v.get("malicious"):             # Jev says benign -> drop
                record_triage(e, escalated=False, outcome="benign")
                continue
            score = v.get("malicious_score") or 0.0
            print(f"[blue] jev FLAG: {e['ip']} {e['method']} {e['path']} -> "
                  f"{v['attack_type']} ({score:.2f})", flush=True)
            if USE_AGENT:
                # Jev FLAGS -> the agent DECIDES (owns ban/rule/divert/patch/incident).
                # Optional reversible holding action only; Jev enforces nothing itself.
                if JEV_AUTOBLOCK and score >= AUTOBLOCK_HIGH:
                    reflex_divert(e, v)
                to_claude.append(e)
                record_triage(e, escalated=True, outcome="claude")
            elif JEV_AUTOBLOCK:
                autoblock(e, v)                    # no agent -> Jev-only fallback containment
                record_triage(e, escalated=True, outcome="autoblock_fallback")
            else:
                record_triage(e, escalated=False, outcome="no_engine")
        if to_claude and client is not None:
            print(f"[blue] {len(to_claude)} flagged -> {agent_label} swarm (system-2)", flush=True)
            try:
                dispatch_swarm(client, to_claude, create_kwargs)
            except Exception as ex:
                print(f"[blue] swarm error: {ex}", file=sys.stderr, flush=True)
        time.sleep(POLL)


if __name__ == "__main__":
    main()
