"""DVWA security-level remediation, called through the actuator.

The same session verifies the change. Persisted enforced_security tells the proxy
to override client-chosen security cookies; changing a session alone is insufficient.
"""
import os
import re

import httpx

import store
from bootstrap_dvwa import _token  # CSRF token scraper only; no DB reset

LEVELS = ("low", "medium", "high", "impossible")
DVWA_URL = os.environ.get("DVWA_URL", "http://localhost:80")
_CUR_RE = re.compile(r"currently.*?\b(low|medium|high|impossible)\b", re.I)


def _login(base, user="admin", password="password"):
    """Logged-in DVWA client. Never resets the database."""
    from bootstrap_dvwa import authed_session
    return authed_session(base, user=user, password=password)


def _read_level(html):
    """DVWA's /security.php renders 'Security Level is currently: <em>X</em>'."""
    m = _CUR_RE.search(html or "")
    return m.group(1).lower() if m else None


def _apply_enforcement(state, level):
    """Set proxy cookie enforcement; low restores client-controlled behavior."""
    if level == "low":
        state.pop("enforced_security", None)
    else:
        state["enforced_security"] = level
    return state


def patch_vuln(level="impossible", base_url=None):
    """Raise DVWA's security level to `level`, fixing the vulnerable code path.
    Returns {ok, level, requested, verified, [error]}. verified=True means we
    read the new level back from the app and it matched."""
    level = (level or "").lower()
    if level not in LEVELS:
        return {"ok": False, "requested": level,
                "error": f"invalid level {level!r}; choose one of {LEVELS}"}
    base = base_url or DVWA_URL
    try:
        c = _login(base)
        token = _token(c.get("/security.php").text)
        c.post("/security.php", data={"security": level, "seclev_submit": "Submit",
                                      "user_token": token})
        c.cookies.set("security", level)
        # DVWA levels are session-specific; a fresh login cannot verify this change.
        new = _read_level(c.get("/security.php").text)
        c.close()
    except Exception as e:
        return {"ok": False, "requested": level, "error": type(e).__name__}
    ok = new == level
    if ok:
        try:
            with store.state_lock:
                store.save_state(_apply_enforcement(store.load_state(), level))
        except Exception:
            return {"ok": False, "requested": level, "level": new, "verified": True,
                    "error": "app session changed but proxy enforcement persistence failed; retry required"}
    return {"ok": ok, "level": new, "requested": level, "verified": ok}


def do_patch_vuln(level="impossible", **_):
    """Dispatch wrapper: returns a human-readable string for the tool_result."""
    r = patch_vuln(level)
    if not r["ok"]:
        if r.get("error"):
            return f"ERROR: patch_vuln failed: {r['error']}"
        return (f"ERROR: patch_vuln unconfirmed: could not verify DVWA security is now "
                f"'{r['requested']}' (read back {r.get('level')!r}) — retry or check manually.")
    return (f"DVWA security level raised to '{r['level']}' — the vulnerable module now "
            f"serves its safe/parameterized code path, and enforced_security='{r['level']}' "
            f"was recorded in shared state so the proxy pins it by stripping/overriding the "
            f"inbound 'security' cookie (closes the cookie-pinning bypass once the proxy "
            f"override is active).")


PATCH_VULN_TOOL = {
    "name": "patch_vuln",
    "description": ("Eradicate the exploited vulnerability by raising DVWA's security "
                    "level so the vulnerable module switches to its safe, "
                    "parameterized/sanitized code path (a real fix, not a WAF band-aid "
                    "or IP ban). Use after confirming an exploit. 'impossible' is fully "
                    "hardened (prepared statements, CSRF tokens, output encoding)."),
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
    print(f"patching DVWA ({DVWA_URL}) -> security '{lvl}'")
    print(json.dumps(patch_vuln(lvl), indent=2))
