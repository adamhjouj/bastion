"""Persist per-source diversion decisions for the proxy's honeypot routing."""
import store


def divert_to_honeypot(ip, reason):
    """Idempotent: route `ip` to the decoy. Appends once; re-diverting is a no-op."""
    with store.state_lock:  # swarm-safe read-modify-write
        st = store.load_state()
        hp = st.setdefault("honeypot", [])
        if not any(d["ip"] == ip for d in hp):
            hp.append({"ip": ip, "reason": reason, "ts": store.now()})
            store.save_state(st)
    return (f"{ip} diverted to honeypot ({reason}) — now routed to the decoy "
            f"instead of the real app.")


def undivert(ip):
    """Release `ip` from the honeypot (symmetry): stop diverting, route it normally again."""
    with store.state_lock:  # swarm-safe read-modify-write
        st = store.load_state()
        hp = st.setdefault("honeypot", [])
        kept = [d for d in hp if d["ip"] != ip]
        if len(kept) != len(hp):
            st["honeypot"] = kept
            store.save_state(st)
            released = True
        else:
            released = False
    return (f"{ip} released from honeypot — requests route to the real app again."
            if released else f"{ip} was not diverted; nothing to release.")


def do_divert_to_honeypot(ip, reason, **_):
    """Dispatch wrapper: returns a human-readable string for the tool_result."""
    return divert_to_honeypot(ip, reason)


def do_undivert(ip, **_):
    """Dispatch wrapper: returns a human-readable string for the tool_result."""
    return undivert(ip)


DIVERT_TOOL = {
    "name": "divert_to_honeypot",
    "description": ("Silently route ALL requests from this source IP to a decoy honeypot "
                    "instead of the real application. The attacker keeps probing a fake "
                    "target — wasting their time and revealing their techniques — while you "
                    "remediate the real vulnerability and prepare a ban. Prefer this over an "
                    "immediate hard 403 ban when you want intel or a remediation window; a "
                    "hard ban tips the attacker off, a divert does not."),
    "input_schema": {
        "type": "object",
        "properties": {
            "ip": {"type": "string"},
            "reason": {"type": "string"},
        },
        "required": ["ip", "reason"],
    },
}

UNDIVERT_TOOL = {
    "name": "undivert",
    "description": ("Stop diverting this source IP to the honeypot and route its requests "
                    "back to the real application. Use to release a false positive or after "
                    "a ban supersedes the divert."),
    "input_schema": {
        "type": "object",
        "properties": {
            "ip": {"type": "string"},
        },
        "required": ["ip"],
    },
}

REGISTER = [
    {"name": "divert_to_honeypot", "schema": DIVERT_TOOL, "fn": do_divert_to_honeypot},
    {"name": "undivert", "schema": UNDIVERT_TOOL, "fn": do_undivert},
]
