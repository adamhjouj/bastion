"""Read-only investigation tools and the agent's environment/tool catalog."""
import json

from bastion import store

# ---- read-only orientation tools (no side effects) -------------------------


def do_get_defenses(**_):
    """Return active defenses to ground subsequent actions."""
    st = store.load_state()
    return json.dumps({
        "denylist": [d for d in st.get("denylist", []) if store.active_ban(d)],
        "honeypot_diverts": st.get("honeypot", []),
        "enforced_security": st.get("enforced_security"),
    }, indent=2)


def do_recent_requests(limit=20, **_):
    """Return bounded recent request observations, newest last."""
    limit = _clamp(limit, 1, 200, 20)
    evs = store.read_jsonl(store.EVENTS_FILE, limit=limit)
    keep = ("ts", "ip", "method", "path", "query", "status", "blocked", "matched")
    return json.dumps([{k: e.get(k) for k in keep} for e in evs], indent=2)


def do_recent_incidents(limit=10, **_):
    """Incidents already raised (what the SOC has been alerted to), newest last."""
    limit = _clamp(limit, 1, 100, 10)
    return json.dumps(store.read_jsonl(store.INCIDENTS_FILE, limit=limit), indent=2)


def do_service_status(**_):
    """Query target container status through the authenticated actuator."""
    from bastion.actuator_client import call_tool
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

# Unclassified registrations appear under Other.
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
    """Render registered tools into a grouped prompt catalog."""
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
    """Use a capped first sentence; full descriptions remain in tool schemas."""
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
    "for diversion; alert email is queued for Resend delivery. You reach DVWA's own container "
    "through an authenticated isolated actuator. Tools are named, validated and "
    "independently gated by deployment policy; you do not have Docker or shell access.\n"
    "A fast system-1 classifier (Jev), when configured, flags requests and may have ALREADY "
    "placed a reversible diversion on an IP. A flag is a reason to LOOK, not proof. "
    "Your job (system-2) is to investigate with the read-only tools, decide with judgment, "
    "and respond proportionally — then stop. You are the reasoning the raw score lacks."
)
