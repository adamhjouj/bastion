"""Server-side virtual patch for the Bastion target, applied through the actuator.

The de-fingerprinted target has no DVWA /security.php, no `security` cookie and no
admin/password login. Its difficulty level lives in a per-boot generated
`data/instance.php` (see target_app/bootstrap.php), and the two vulnerable modules
branch on `cfg('level')`:
  - lookup.php (SQLi): low = quote breakout, medium = unquoted-numeric/UNION, and
    any higher level selects a bound-parameter (prepared) path.
  - netcheck.php (cmdi): low = no filter, medium = DVWA's `&&`/`;` blacklist, and
    any higher level selects an escapeshellarg() path.
So raising the effective level to 'high'/'impossible' switches BOTH modules to their
hardened code path: the exploit that just worked now fails while the app still serves.

This runs inside the actuator container (the only side with the Docker socket), so it
mutates the live instance.php in place via `docker exec` — reusing actuator._resolve /
actuator._docker — then reads the level back to verify. No HTTP, cookie or login.
"""
import os

import actuator
import store

LEVELS = ("low", "medium", "high", "impossible")
# Modules treat anything above medium as hardened; 'medium'/'low' stay exploitable.
_NOT_A_FIX = ("low", "medium")


def _apply_enforcement(state, level):
    """Record the pinned level for the SOC view (get_defenses / dashboard). The real
    mitigation is the server-side instance.php change; this just surfaces it. 'low'
    (de-escalation) clears the record."""
    if level == "low":
        state.pop("enforced_security", None)
    else:
        state["enforced_security"] = level
    return state


def _get_level_php():
    return "echo (require (getenv('APP_DATA') ?: '/var/www/data') . '/instance.php')['level'];"


def _set_level_php(level):
    # level is validated against LEVELS (a fixed 4-value enum) before we get here,
    # so inlining it as a literal is injection-safe and avoids php -r argv ambiguity.
    return ("$f = (getenv('APP_DATA') ?: '/var/www/data') . '/instance.php'; "
            "$c = require $f; $c['level'] = '" + level + "'; "
            "file_put_contents($f, \"<?php\\nreturn \" . var_export($c, true) . \";\\n\"); "
            "echo $c['level'];")


def patch_vuln(level="impossible", target="dvwa"):
    """Raise the target app's effective security level by rewriting its live
    instance.php, switching the vulnerable lookup/netcheck modules to their hardened
    (bound-SQL / shell-escaped) code path. Returns {ok, level, requested, verified,
    [error]}; verified=True means we re-read the level from the app and it matched.
    # ponytail: Apache opcache revalidate_freq=2 -> web requests pick up the new
    # level within ~2s; the CLI read-back here is immediate and reflects the file."""
    level = (level or "").lower()
    if level not in LEVELS:
        return {"ok": False, "requested": level,
                "error": f"invalid level {level!r}; choose one of {LEVELS}"}
    try:
        cid = actuator._resolve(target)
        rc, _out, err = actuator._docker("exec", cid, "php", "-r", _set_level_php(level))
        if rc != 0:
            return {"ok": False, "requested": level,
                    "error": f"could not apply patch: {(err or '').strip() or rc}"}
        rc, back, err = actuator._docker("exec", cid, "php", "-r", _get_level_php())
        if rc != 0:
            return {"ok": False, "requested": level,
                    "error": f"patch applied but read-back failed: {(err or '').strip() or rc}"}
        new = (back or "").strip()
    except actuator.Rejected as e:
        return {"ok": False, "requested": level, "error": str(e)}
    except Exception as e:  # never raise into the actuator loop
        return {"ok": False, "requested": level, "error": type(e).__name__}
    ok = new == level
    if ok:
        try:
            with store.state_lock:
                store.save_state(_apply_enforcement(store.load_state(), level))
        except Exception:
            return {"ok": False, "requested": level, "level": new, "verified": True,
                    "error": "level changed on target but SOC-state update failed; retry"}
    return {"ok": ok, "level": new, "requested": level, "verified": ok}


def restore_lab(target="dvwa", level="medium"):
    """Undo every target-side change the blue team can make, so the lab is exploitable
    again: unfreeze a quarantined container, re-attach a cut egress network, and put the
    app back at its exploitable default level. Each step is independent and reported; one
    failing step never blocks the others. Proxy-side defenses (bans, diversions, virtual
    patches) live in shared state and are cleared by the caller. Rotated credentials are
    not reverted: the app config already matches the new secret, so the app keeps working."""
    level = (level or "").lower()
    if level not in LEVELS:
        return {"ok": False, "error": f"invalid level {level!r}; choose one of {LEVELS}"}
    steps = {}
    try:
        cid = actuator._resolve(target)
    except actuator.Rejected as e:
        return {"ok": False, "error": str(e)}
    rc, out, _ = actuator._docker("inspect", "--format", "{{.State.Paused}}", cid)
    if rc == 0 and out.strip() == "true":
        try:
            steps["quarantine"] = actuator.release_container(target)
        except actuator.Rejected as e:
            steps["quarantine"] = f"failed: {e}"
    else:
        steps["quarantine"] = "not quarantined"
    try:
        steps["egress"] = actuator.reconnect_egress(target)
    except actuator.Rejected as e:
        steps["egress"] = f"skipped: {e}"
    rc, _o, err = actuator._docker("exec", cid, "php", "-r", _set_level_php(level))
    rc2, back, _e = actuator._docker("exec", cid, "php", "-r", _get_level_php()) if rc == 0 else (rc, "", err)
    restored = (back or "").strip()
    steps["level"] = restored if rc2 == 0 and restored == level else f"failed: {(err or '').strip() or rc}"
    if restored == level:
        try:
            with store.state_lock:
                state = store.load_state()
                state.pop("enforced_security", None)
                store.save_state(state)
        except Exception:
            pass
    ok = restored == level and not str(steps["quarantine"]).startswith("failed")
    return {"ok": ok, "level": restored or None, "steps": steps}


def do_patch_vuln(level="impossible", **_):
    """Dispatch wrapper: returns a human-readable string for the tool_result."""
    r = patch_vuln(level)
    if not r["ok"]:
        if r.get("error"):
            return f"ERROR: patch_vuln failed: {r['error']}"
        return (f"ERROR: patch_vuln unconfirmed: target level read back as "
                f"{r.get('level')!r}, not '{r['requested']}' — retry or check manually.")
    note = ""
    if r["level"] in _NOT_A_FIX:
        note = (" WARNING: this level is still exploitable — use 'high' or 'impossible' "
                "to actually close the hole.")
    return (f"Target security level raised to '{r['level']}' — the vulnerable lookup/"
            f"netcheck/document-viewer modules now serve their hardened code path (bound SQL "
            f"parameter / escapeshellarg / basename-confined file read), so the exploited "
            f"SQLi/command-injection/path-traversal payloads fail while "
            f"the app keeps serving. Change takes effect on new requests within ~2s "
            f"(opcache revalidation); enforced_security='{r['level']}' recorded in shared "
            f"state for the SOC view.{note}")


PATCH_VULN_TOOL = {
    "name": "patch_vuln",
    "description": ("Virtual-patch the exploited vulnerability on the target app by raising "
                    "its server-side security level, which switches each vulnerable module "
                    "(record lookup, network diagnostics, document viewer) to its hardened "
                    "code path (parameterised SQL / shell-escaped exec / path-confined file "
                    "read) — a real fix, not a WAF band-aid or IP ban. Use after confirming "
                    "an exploit of ANY of these sinks: SQL injection, command injection, OR "
                    "path traversal / local file read. Use 'impossible' (or 'high') to close "
                    "the hole; 'low'/'medium' are the exploitable levels and will NOT mitigate."),
    "input_schema": {
        "type": "object",
        "properties": {
            "level": {"type": "string", "enum": list(LEVELS),
                      "description": "Target security level; use 'impossible' to fully patch."},
        },
        "required": ["level"],
    },
}

REGISTER = {"name": "patch_vuln", "schema": PATCH_VULN_TOOL, "fn": do_patch_vuln}


if __name__ == "__main__":
    import json
    import sys
    lvl = sys.argv[1] if len(sys.argv) > 1 else "impossible"
    tgt = sys.argv[2] if len(sys.argv) > 2 else "dvwa"
    print(f"patching target service {tgt!r} -> security '{lvl}'")
    print(json.dumps(patch_vuln(lvl, tgt), indent=2))
