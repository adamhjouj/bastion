"""Autonomous blue-team agent. Tails the proxy's request log, cheap regex
pre-filter gates what reaches the LLM (so it idles for free on benign traffic),
then Claude classifies suspicious batches and calls tools to blacklist the IP,
add a virtual-patch WAF rule, and email an incident report."""
import os
import re
import smtplib
import sys
import time
from email.message import EmailMessage

import anthropic

import store

MODEL = os.environ.get("BLUE_MODEL", "claude-sonnet-5")
POLL = 1.0

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
    "happened and what you did.\n\n"
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
    import json
    user = ("Recent suspicious HTTP requests captured at the reverse proxy:\n\n"
            + json.dumps(events, indent=2)
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
    client = anthropic.Anthropic()
    print(f"[blue] watching {store.EVENTS_FILE} with {MODEL}", flush=True)
    offset = len(store.read_jsonl(store.EVENTS_FILE))  # skip pre-existing lines
    while True:
        evs = store.read_jsonl(store.EVENTS_FILE)
        new, offset = evs[offset:], len(evs)
        blocked_ips = {d["ip"] for d in store.load_state()["denylist"]}
        suspicious = [e for e in new
                      if not e["blocked"] and is_suspicious(e) and e["ip"] not in blocked_ips]
        if suspicious:
            print(f"[blue] {len(suspicious)} suspicious request(s) -> analysing", flush=True)
            try:
                analyse(client, suspicious)
            except Exception as e:
                print(f"[blue] analyse error: {e}", file=sys.stderr, flush=True)
        time.sleep(POLL)


if __name__ == "__main__":
    main()
