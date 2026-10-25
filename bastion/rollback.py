"""One-click reversibility (PLAN B2): inverse map, annotation and compensating actions.

A rollback never edits history. The inverse is executed and a NEW `actions` record with
`tool='rollback'` and `input.reverts=<original id>` is appended through
`store.append_jsonl` (the same hash-chained path every other action uses). Everything the
UI shows (`reversible`, `reverted_by`, `reverts`) is derived from the records themselves.

Inverse choices for the two patch tools (CONTRACTS §3.1 asks to document them):
  - `virtual_patch` (proxy rule in state.vpatch) -> `remove_vpatch`: the rule is dropped from
    shared state, keyed by the same (path, pattern) the agent installed it with. The proxy
    stops enforcing it on its next request. Nothing else in the codebase edits vpatch rules.
  - `patch_vuln` (target security level, privileged) -> `patch_vuln` via the actuator with
    the level restored to the previous successful `patch_vuln` recorded in the action log,
    or the lab's exploitable default (`LAB_DEFAULT_LEVEL`, as `remediation_tools.restore_lab`)
    when there is none. The original record does not carry the prior level.
Privileged inverses (`release_container`, `reconnect_egress`, `patch_vuln`) go through
`bastion.actuator_client.call_tool` because the proxy has no Docker socket.
"""
import ipaddress
import json

from bastion import actuator_client
from bastion import store
from bastion.security import canonical_vpatch

INVERSE = {
    "blacklist_ip": "unban_ip",
    "bulk_blacklist_ip": "unban_ip",
    "divert_to_honeypot": "undivert",
    "virtual_patch": "remove_vpatch",
    "patch_vuln": "patch_vuln",
    "quarantine_container": "release_container",
    "isolate_egress": "reconnect_egress",
}
IRREVERSIBLE = frozenset({"kill_process", "kill_session", "rotate_secret"})
LAB_DEFAULT_LEVEL = "medium"
# Same convention as blue_agent.execute_tool: tools report failure in the result prefix.
_FAILURE_PREFIXES = ("ERROR", "REJECTED", "UNKNOWN")


class RollbackRefused(Exception):
    """The record cannot be rolled back (HTTP 409): no inverse, not ok, already reverted."""


def reverts_id(record):
    """The original action id a compensating record reverts, or None for every other record."""
    if record.get("tool") != "rollback" or not isinstance(record.get("input"), dict):
        return None
    target = record["input"].get("reverts")
    return target if isinstance(target, int) and not isinstance(target, bool) else None


def is_reversible(record, reverted_by=None):
    return (record.get("kind") == "action" and record.get("outcome") == "ok"
            and record.get("tool") in INVERSE and reverted_by is None)


def annotate(records, known_reverted=None):
    """Pure: add `reversible`, `reverted_by`, `reverts` to each record and return new dicts.

    `reverted_by` is derived from successful compensating records in `records`; the data
    layer may pass `known_reverted` ({original id: rollback id}) for compensations that live
    outside the page being annotated.
    """
    reverted = dict(known_reverted or {})
    for record in sorted(records, key=lambda r: r.get("id") or 0):
        target = reverts_id(record)
        if target is not None and record.get("outcome") == "ok" and record.get("id") is not None:
            reverted.setdefault(target, record["id"])
    annotated = []
    for record in records:
        reverted_by = reverted.get(record.get("id"))
        annotated.append({**record, "reversible": is_reversible(record, reverted_by),
                          "reverted_by": reverted_by, "reverts": reverts_id(record)})
    return annotated


def reverted_map(db):
    """{original id: compensating id} for every successful rollback on record."""
    rows = db.execute("SELECT id, json_extract(data,'$.input.reverts') AS target FROM records "
                      "WHERE kind='actions' AND json_extract(data,'$.tool')='rollback' "
                      "AND json_extract(data,'$.outcome')='ok' ORDER BY id").fetchall()
    result = {}
    for row in rows:
        if isinstance(row["target"], int):
            result.setdefault(row["target"], row["id"])
    return result


def load_action(action_id):
    """One annotated action record by row id, or None when unknown."""
    with store.connection() as db:
        row = db.execute("SELECT id,data,status FROM records WHERE kind='actions' AND id=?", (action_id,)).fetchone()
        if row is None:
            return None
        record = {**json.loads(row["data"]), "id": row["id"], "processing_status": row["status"]}
        return annotate([record], reverted_map(db))[0]


# ---- proxy-side inverses (shared with the operator /defenses endpoints) ----

def release_ban(ip):
    """Drop every active ban for `ip` from shared state; returns how many were removed."""
    with store.state_lock:
        st = store.load_state()
        before = len(st["denylist"])
        st["denylist"] = [d for d in st["denylist"] if d["ip"] != ip]
        store.save_state(st)
    return before - len(st["denylist"])


def release_diversion(ip):
    """Stop routing `ip` to the honeypot; returns how many diversions were removed."""
    with store.state_lock:
        st = store.load_state()
        before = len(st.get("honeypot", []))
        st["honeypot"] = [d for d in st.get("honeypot", []) if d["ip"] != ip]
        store.save_state(st)
    return before - len(st["honeypot"])


def remove_vpatch(path, pattern):
    """Drop the proxy virtual-patch rule(s) installed for (path, pattern); returns the count."""
    with store.state_lock:
        st = store.load_state()
        rules = st.get("vpatch", [])
        st["vpatch"] = [r for r in rules if not (r.get("path") == path and r.get("pattern") == pattern)]
        store.save_state(st)
    return len(rules) - len(st["vpatch"])


def _ip(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        raise RollbackRefused("original action has no valid source IP to release")


def prior_patch_level(record):
    """Level the target had before `record` raised it: the latest earlier successful
    `patch_vuln` (direct or via rollback), else the lab default."""
    with store.connection() as db:
        row = db.execute("SELECT data FROM records WHERE kind='actions' AND id<? "
                          "AND json_extract(data,'$.outcome')='ok' "
                          "AND (json_extract(data,'$.tool')='patch_vuln' OR "
                          "(json_extract(data,'$.tool')='rollback' AND json_extract(data,'$.input.inverse')='patch_vuln')) "
                          "ORDER BY id DESC LIMIT 1", (record["id"],)).fetchone()
    if row is None:
        return LAB_DEFAULT_LEVEL
    earlier = json.loads(row["data"]).get("input") or {}
    return earlier.get("level") or LAB_DEFAULT_LEVEL


def execute_inverse(record):
    """Run the inverse of an original action. Returns (params, result, outcome).
    Downstream failures are reported in `outcome`, never raised."""
    tool = record.get("tool")
    inp = record.get("input") if isinstance(record.get("input"), dict) else {}
    if tool == "blacklist_ip":
        ip = _ip(inp.get("ip"))
        removed = release_ban(ip)
        return {"ip": ip}, f"Removed {removed} ban(s) for {ip}", "ok"
    if tool == "bulk_blacklist_ip":
        ips = inp.get("ips")
        if not isinstance(ips, list) or not ips:
            raise RollbackRefused("original action has no source IPs to release")
        ips = sorted({_ip(ip) for ip in ips})
        removed = sum(release_ban(ip) for ip in ips)
        return {"ips": ips}, f"Removed {removed} ban(s) for {len(ips)} source(s)", "ok"
    if tool == "divert_to_honeypot":
        ip = _ip(inp.get("ip"))
        removed = release_diversion(ip)
        return {"ip": ip}, f"Released {removed} diversion(s) for {ip}", "ok"
    if tool == "virtual_patch":
        path, pattern = inp.get("path"), canonical_vpatch(inp.get("attack_type")) or inp.get("pattern")
        if not path or not pattern:
            raise RollbackRefused("original action does not identify a virtual-patch rule")
        removed = remove_vpatch(path, pattern)
        return {"path": path, "pattern": pattern}, f"Removed {removed} virtual patch(es) on {path}", "ok"
    if tool == "patch_vuln":
        params = {"level": prior_patch_level(record)}
    elif tool in ("quarantine_container", "isolate_egress"):
        target = inp.get("target")
        if not isinstance(target, str) or not target:
            raise RollbackRefused("original action does not identify a target container")
        params = {"target": target}
    else:
        raise RollbackRefused(f"{tool!r} has no inverse")
    result = str(actuator_client.call_tool(INVERSE[tool], params))
    return params, result, "error" if result.startswith(_FAILURE_PREFIXES) else "ok"


def rollback(action_id, reason=""):
    """Revert one action. Returns (compensating action, annotated).

    Raises LookupError (unknown id) or RollbackRefused (409 conditions). A downstream
    failure still appends a compensating record with outcome 'error' so the attempt is
    on the chain; the caller maps that outcome to HTTP 502.
    """
    original = load_action(action_id)
    if original is None:
        raise LookupError(action_id)
    if original["reverted_by"] is not None:
        raise RollbackRefused(f"action {action_id} was already reverted by action {original['reverted_by']}")
    if original.get("tool") in IRREVERSIBLE:
        raise RollbackRefused(f"{original['tool']} is irreversible")
    if not original["reversible"]:
        raise RollbackRefused(f"action {action_id} is not reversible "
                              f"(tool={original.get('tool')!r}, kind={original.get('kind')!r}, outcome={original.get('outcome')!r})")
    params, result, outcome = execute_inverse(original)
    new_id = store.append_jsonl(store.ACTIONS_FILE, {
        "ts": store.now(), "kind": "action", "tool": "rollback",
        "input": {"reverts": action_id, "tool": original["tool"], "inverse": INVERSE[original["tool"]],
                  "reason": str(reason or "")[:500], **params},
        "result": result, "outcome": outcome, "case_id": original.get("case_id")})
    return load_action(new_id)
