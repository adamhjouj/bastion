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
from email.message import EmailMessage

import anthropic

import store
from classifier import classify_request

try:  # eradication tools live in a sibling module; keep the agent runnable without them
    from remediation_tools import REGISTER as REMEDIATION_REGISTER
except Exception:
    REMEDIATION_REGISTER = None

MODEL = os.environ.get("BLUE_MODEL", "claude-sonnet-5")
POLL = 1.0
# System-1 triage via Jev (auto-off if no key); regex pre-gate keeps Jev off benign traffic.
USE_JEV = os.environ.get("USE_JEV", "1") == "1" and bool(os.environ.get("TYPESAFE_API_KEY"))
USE_REGEX_PREGATE = os.environ.get("USE_REGEX_PREGATE", "1") == "1"
# Jev's verdict drives the WAF directly (fast reflex, no Claude needed).
JEV_AUTOBLOCK = os.environ.get("JEV_AUTOBLOCK", "1") == "1"
# Claude (system-2) is optional enrichment; on only if an Anthropic key is present.
USE_CLAUDE = bool(os.environ.get("ANTHROPIC_API_KEY"))

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
    | \.\./ | <script | onerror= | %2e%2e )
""")

SYSTEM = (
    "You are an autonomous SOC blue-team agent protecting a web application. You "
    "receive recent HTTP requests captured at a reverse proxy in front of the app. "
    "Decide whether any request is a real attack. Known classes: SQL injection, "
    "command injection, path traversal, XSS.\n\n"
    "For each distinct attacker you are confident about:\n"
    "1. call blacklist_ip on the source IP;\n"
    "2. call add_waf_rule with a TIGHT regex that blocks that specific exploit "
    "pattern (match the payload tokens, e.g. 'union\\s+select' or ';\\s*cat', NOT "
    "broad patterns that would block normal traffic);\n"
    "3. call raise_alert with concrete evidence and a one-line summary of what "
    "happened and what you did.\n"
    "4. if patch_vuln is available and containment alone is insufficient, call it "
    "to raise the app's security posture (real eradication beyond the WAF). Note "
    "it hardens the whole app, so reserve it for a confirmed, serious exploit.\n\n"
    "If traffic is benign, do nothing and reply 'no threat'. Never duplicate an "
    "action already listed in current defenses. Be decisive."
)

TOOLS = [
    {"name": "blacklist_ip",
     "description": "Block all current and future requests from this source IP at the proxy.",
     "input_schema": {"type": "object",
                      "properties": {"ip": {"type": "string"},
                                     "reason": {"type": "string"}},
                      "required": ["ip", "reason"]}},
    {"name": "add_waf_rule",
     "description": "Virtually patch a vulnerability by blocking any request whose "
                    "method/path/query/body matches this Python regex (case-insensitive), "
                    "regardless of source IP.",
     "input_schema": {"type": "object",
                      "properties": {"pattern": {"type": "string"},
                                     "description": {"type": "string"}},
                      "required": ["pattern", "description"]}},
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

def do_blacklist_ip(ip, reason):
    st = store.load_state()
    if not any(d["ip"] == ip for d in st["denylist"]):
        st["denylist"].append({"ip": ip, "reason": reason, "ts": store.now()})
        store.save_state(st)
    return f"IP {ip} blacklisted."


def do_add_waf_rule(pattern, description):
    try:
        re.compile(pattern)
    except re.error as e:
        return f"Invalid regex, not added: {e}"
    st = store.load_state()
    if not any(r["pattern"] == pattern for r in st["rules"]):
        st["rules"].append({"pattern": pattern, "description": description, "ts": store.now()})
        store.save_state(st)
    return f"WAF rule added: {description}"


def do_raise_alert(severity, attack_type, source_ip, evidence, summary):
    inc = {"ts": store.now(), "severity": severity, "attack_type": attack_type,
           "source_ip": source_ip, "evidence": evidence, "summary": summary}
    store.append_jsonl(store.INCIDENTS_FILE, inc)
    send_email(inc)
    return "Alert raised and email sent."


DISPATCH = {"blacklist_ip": do_blacklist_ip, "add_waf_rule": do_add_waf_rule,
            "raise_alert": do_raise_alert}

# Register eradication tools (patch_vuln, and future lock_egress/kill_session/…).
# Each REGISTER entry is {"name", "schema", "fn"}; accepts a single dict or a list.
if REMEDIATION_REGISTER:
    for _reg in (REMEDIATION_REGISTER if isinstance(REMEDIATION_REGISTER, list)
                 else [REMEDIATION_REGISTER]):
        TOOLS.append(_reg["schema"])
        DISPATCH[_reg["name"]] = _reg["fn"]


def autoblock(event, verdict):
    """Jev-driven WAF enforcement — no LLM. Ban the IP, add the canned virtual
    patch for the attack type, and alert. This is 'Jev in the WAF'."""
    ip = event["ip"]
    atk = verdict["attack_type"]
    score = verdict.get("malicious_score") or 0.0
    evidence = f"{event.get('method')} {event.get('path')}?{event.get('query', '')} {event.get('body', '')}".strip()
    actions = [do_blacklist_ip(ip, f"Jev-confirmed {atk} (score {score:.2f})")]
    rule = CANNED_WAF.get(atk)
    if rule:
        actions.append(do_add_waf_rule(rule, f"auto: block {atk} (Jev)"))
    sev = "critical" if score >= 0.9 else "high"
    do_raise_alert(sev, atk, ip, evidence,
                   "Jev system-1 confirmed attack; " + "; ".join(actions))
    print(f"[blue] AUTOBLOCK {ip} ({atk}, {score:.2f}) -> banned + "
          f"{'WAF rule + ' if rule else ''}email", flush=True)


def send_email(inc):
    host = os.environ.get("SMTP_HOST", "localhost")
    port = int(os.environ.get("SMTP_PORT", "1025"))
    user, pw = os.environ.get("SMTP_USER"), os.environ.get("SMTP_PASS")
    msg = EmailMessage()
    msg["Subject"] = f"[{inc['severity'].upper()}] {inc['attack_type']} from {inc['source_ip']}"
    msg["From"] = os.environ.get("ALERT_FROM", "blue-agent@breach-agent.local")
    msg["To"] = os.environ.get("ALERT_TO", "soc@example.com")
    msg.set_content(
        "SECURITY INCIDENT — automated by the blue-team agent\n\n"
        f"Time:      {inc['ts']}\n"
        f"Severity:  {inc['severity']}\n"
        f"Attack:    {inc['attack_type']}\n"
        f"Source IP: {inc['source_ip']}\n\n"
        f"Evidence:\n{inc['evidence']}\n\n"
        f"Action taken:\n{inc['summary']}\n"
    )
    try:
        with smtplib.SMTP(host, port, timeout=10) as s:
            if user and pw:
                s.starttls()
                s.login(user, pw)
            s.send_message(msg)
    except Exception as e:  # never let a mail failure kill the loop
        print(f"[blue] email send failed: {e}", file=sys.stderr)


def analyse(client, events):
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
    messages = [{"role": "user", "content": user}]
    while True:
        resp = client.messages.create(
            model=MODEL, max_tokens=4096, system=SYSTEM, tools=TOOLS,
            output_config={"effort": "low"}, messages=messages)
        if resp.stop_reason != "tool_use":
            break
        messages.append({"role": "assistant", "content": resp.content})
        results = []
        for b in resp.content:
            if b.type == "tool_use":
                fn = DISPATCH.get(b.name)
                out = fn(**b.input) if fn else f"unknown tool {b.name}"
                print(f"[blue] ACTION {b.name}({b.input}) -> {out}")
                results.append({"type": "tool_result", "tool_use_id": b.id, "content": out})
        messages.append({"role": "user", "content": results})


def main():
    client = anthropic.Anthropic() if USE_CLAUDE else None
    mode = "+".join(m for m, on in (("regex", USE_REGEX_PREGATE), ("Jev", USE_JEV),
                                    ("autoblock", JEV_AUTOBLOCK and USE_JEV),
                                    ("Claude", USE_CLAUDE)) if on) or "none"
    print(f"[blue] watching {store.EVENTS_FILE}; pipeline: {mode}", flush=True)
    if not USE_JEV and not USE_CLAUDE:
        print("[blue] WARNING: no decision engine (no Jev key, no Anthropic key)",
              file=sys.stderr, flush=True)
    offset = len(store.read_jsonl(store.EVENTS_FILE))  # skip pre-existing lines
    while True:
        evs = store.read_jsonl(store.EVENTS_FILE)
        new, offset = evs[offset:], len(evs)
        blocked_ips = {d["ip"] for d in store.load_state()["denylist"]}
        candidates = [e for e in new if not e["blocked"] and e["ip"] not in blocked_ips
                      and (not USE_REGEX_PREGATE or is_suspicious(e))]
        to_claude = []
        for e in candidates:
            if not USE_JEV:
                if USE_CLAUDE:
                    to_claude.append(e)
                continue
            v = classify_request(e)
            e["_jev"] = v
            if v.get("error"):                     # couldn't classify -> Claude if available
                print(f"[blue] jev error ({e['ip']} {e['path']}): {v['error']}",
                      file=sys.stderr, flush=True)
                if USE_CLAUDE:
                    to_claude.append(e)
                continue
            if not v.get("malicious"):             # Jev says benign -> drop
                continue
            print(f"[blue] jev: {e['ip']} {e['method']} {e['path']} -> "
                  f"{v['attack_type']} ({v['malicious_score']:.2f})", flush=True)
            if JEV_AUTOBLOCK:
                autoblock(e, v)                    # Jev drives the WAF directly
            elif USE_CLAUDE:
                to_claude.append(e)
        if to_claude and client is not None:
            print(f"[blue] {len(to_claude)} -> Claude (system-2)", flush=True)
            try:
                analyse(client, to_claude)
            except Exception as ex:
                print(f"[blue] analyse error: {ex}", file=sys.stderr, flush=True)
        time.sleep(POLL)


if __name__ == "__main__":
    main()
