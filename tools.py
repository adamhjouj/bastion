"""The blue-team agent's situational awareness + tool catalog.

Two jobs, both about making the agent actually UNDERSTAND its environment and its
toolbox instead of only reacting to a flagged request:

  1. ORIENT tools (defined here) — read-only "look around" actions with NO side
     effects, so the agent can see the environment it is defending before it acts:
     its own current defenses, the recent request traffic, the incidents it has
     already raised, and which containers are up/paused/isolated. These plug into
     the agent's tool-use loop via the same {name,schema,fn} REGISTER hook the
     action modules (remediation_tools / actuator / honeypot_tools) use.

  2. catalog(schemas) — renders the WHOLE registered tool set (core + every
     module + these orient tools) into the text the agent is taught in its system
     prompt, grouped by purpose. Driven by the live schema list, so a tool that is
     registered but not yet hand-documented still shows up — the agent is never
     blind to a tool it can call.

ENVIRONMENT is the standing briefing (what the app/proxy/network are) prepended to
that catalog. Together they are the "understands where it is, what its job is, and
what it can do" context the agent was missing.
"""
import json

import store

# ---- read-only orientation tools (no side effects) -------------------------


def do_get_defenses(**_):
    """Everything the agent is CURRENTLY enforcing — so it can avoid duplicate
    actions and reason about what is already contained."""
    st = store.load_state()
    return json.dumps({
        "denylist": [d for d in st.get("denylist", []) if store.active_ban(d)],
        "honeypot_diverts": st.get("honeypot", []),   # IPs silently routed to the decoy
        "enforced_security": st.get("enforced_security"),  # app hardening pinned by patch_vuln
    }, indent=2)


def do_recent_requests(limit=20, **_):
    """The last `limit` HTTP requests the proxy saw (decoded), newest last. The
    agent's window onto live traffic beyond the single batch it was handed."""
    limit = _clamp(limit, 1, 200, 20)
    evs = store.read_jsonl(store.EVENTS_FILE, limit=limit)
    keep = ("ts", "ip", "method", "path", "query", "status", "blocked", "matched")
    return json.dumps([{k: e.get(k) for k in keep} for e in evs], indent=2)


def do_recent_incidents(limit=10, **_):
    """Incidents already raised (what the SOC has been alerted to), newest last."""
    limit = _clamp(limit, 1, 100, 10)
    return json.dumps(store.read_jsonl(store.INCIDENTS_FILE, limit=limit), indent=2)


def do_service_status(**_):
    """Which containers make up the environment and their state (running / paused /
    exited) — so the agent knows what it is defending and whether a prior containment
    action (quarantine/isolate) is in effect. Best-effort; needs the docker socket."""
    from actuator_client import call_tool
    return call_tool("service_status", {})


def _clamp(v, lo, hi, default):
    try:
        v = int(v)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, v))


_SCHEMA = lambda name, desc, props=None, req=None: {  # noqa: E731 - tiny local helper
    "name": name, "description": desc,
    "input_schema": {"type": "object", "properties": props or {}, "required": req or []},
}

ORIENT_REGISTER = [
    {"name": "get_defenses", "fn": do_get_defenses, "schema": _SCHEMA(
        "get_defenses",
        "Read-only. List everything you are CURRENTLY enforcing: banned IPs (with any "
        "'expires' for provisional bans), honeypot diverts, and the "
        "pinned app security level. Call this FIRST to orient and to avoid duplicating "
        "an action already in place.")},
    {"name": "recent_requests", "fn": do_recent_requests, "schema": _SCHEMA(
        "recent_requests",
        "Read-only. Return the last N HTTP requests the proxy observed (decoded path/"
        "query/body, status, whether blocked). Use to see the attacker's broader "
        "activity or to check whether an IP is still probing.",
        {"limit": {"type": "integer", "description": "how many recent requests (1-200, default 20)"}})},
    {"name": "recent_incidents", "fn": do_recent_incidents, "schema": _SCHEMA(
        "recent_incidents",
        "Read-only. Return incidents already raised (what the SOC has been alerted to). "
        "Use to avoid re-alerting on something already reported.",
        {"limit": {"type": "integer", "description": "how many recent incidents (1-100, default 10)"}})},
    {"name": "service_status", "fn": do_service_status, "schema": _SCHEMA(
        "service_status",
        "Read-only. List the containers in this environment and their state (running/"
        "paused/exited) — e.g. whether the target is already quarantined. Grounds any "
        "container-level action.")},
]


# ---- tool catalog rendering (drives the system prompt) ---------------------

# Purpose grouping for the catalog. A tool not listed here still appears, under
# "Other" — so the agent is never blind to a registered tool.
_GROUPS = [
    ("SITUATIONAL AWARENESS (read-only — orient with these BEFORE you act)",
     ["get_defenses", "recent_requests", "recent_incidents", "service_status",
      "inspect_target", "list_processes", "list_sessions"]),
    ("CONTAINMENT (stop/limit the attacker)",
     ["blacklist_ip", "bulk_blacklist_ip", "divert_to_honeypot", "undivert", "isolate_egress",
      "quarantine_container", "release_container", "kill_process", "kill_session", "unban_ip"]),
    ("REMEDIATION (fix or neutralize the hole)",
     ["patch_vuln", "rotate_secret"]),
    ("ALERTING",
     ["raise_alert"]),
]


def catalog(schemas):
    """Render the live tool set into grouped `- name: one-line purpose` text for the
    system prompt. `schemas` is the agent's actual TOOLS list, so every registered
    tool is taught — nothing the agent can call is left undocumented."""
    by_name = {s["name"]: s.get("description", "") for s in schemas}
    placed = set()
    lines = []
    for title, names in _GROUPS:
        present = [n for n in names if n in by_name]
        if not present:
            continue
        lines.append(title + ":")
        for n in present:
            lines.append(f"  - {n}: {_tag(by_name[n])}")
            placed.add(n)
        lines.append("")
    other = [n for n in by_name if n not in placed]
    if other:
        lines.append("OTHER:")
        for n in other:
            lines.append(f"  - {n}: {_tag(by_name[n])}")
    return "\n".join(lines).rstrip()


def _tag(desc, limit=72):
    """Short purpose tag for the catalog. The FULL description is already sent in the
    tool schema, so the catalog only needs grouping + a one-glance tag — this keeps the
    system prompt lean (no duplicated paragraphs). Takes the first sentence, drops the
    'Read-only.' prefix (the group title already says it), and caps length."""
    d = " ".join(desc.split())
    if d.startswith("Read-only."):
        d = d[len("Read-only."):].strip()
    d = d.split(". ", 1)[0].rstrip(".")       # first sentence/clause only
    return d if len(d) <= limit else d[:limit - 1].rstrip() + "…"


ENVIRONMENT = (
    "ENVIRONMENT — know where you are:\n"
    "You are an autonomous blue-team SOC agent defending a live web application (DVWA) "
    "in a Docker network. A reverse proxy sits in front of the app and is BOTH your "
    "sensor and your enforcement point: it logs every HTTP request, and on each request "
    "it reads your denylist, honeypot diverts, and pinned security level from "
    "transactional state and enforces committed defenses on subsequent requests. "
    "Model classification may be inline or asynchronous according to deployment policy.\n"
    "Topology: attacker → proxy (:8080) → DVWA (:80). A honeypot decoy exists "
    "for diversion; alert email is captured by MailHog. You reach DVWA's own container "
    "through an authenticated isolated actuator. Tools are named, validated and "
    "independently gated by deployment policy; you do not have Docker or shell access.\n"
    "A fast system-1 classifier (Jev), when configured, flags requests and may have ALREADY "
    "placed a reversible diversion on an IP. A flag is a reason to LOOK, not proof. "
    "Your job (system-2) is to investigate with the read-only tools, decide with judgment, "
    "and respond proportionally — then stop. You are the reasoning the raw score lacks."
)
