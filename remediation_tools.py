"""Vuln-remediation tools for the blue agent (non-WAF eradication actions).

Unlike a WAF rule or an IP ban (which tape over the hole), these fix the hole.
First tool: patch_vuln() raises DVWA's security level so the exploited module
switches to its safe, parameterized/sanitized code path ("impossible" = DVWA's
hardened source: prepared statements, CSRF tokens, output encoding). Stronger
than a WAF rule or IP ban for clients that use the server's level.

# ponytail: DVWA picks the level per-request from the 'security' cookie, so a
# client that PINS security=low bypasses this. Full eradication needs the proxy
# to strip/override that cookie (proxy's job). This tool raises the server level
# and confirms it; it is not a universal patch on its own.

Exposed as an Anthropic tool (PATCH_VULN_TOOL) + a string-returning dispatch fn
(do_patch_vuln) matching blue_agent.py's DISPATCH/TOOLS convention, so it can be
registered there without this module importing the agent.

# ponytail: control-plane action straight to DVWA (not through the proxy, which
# could WAF/rate-limit its own fix). Non-destructive login — does NOT reset the DB.
"""
import os
import re

import httpx

from bootstrap_dvwa import _token  # reuse the anti-CSRF token scraper

LEVELS = ("low", "medium", "high", "impossible")
DVWA_URL = os.environ.get("DVWA_URL", "http://localhost:80")
_CUR_RE = re.compile(r"currently.*?\b(low|medium|high|impossible)\b", re.I)


def _login(base, user="admin", password="password"):
    """Logged-in DVWA client. Assumes the DB already exists (bootstrap ran);
    unlike bootstrap_dvwa.authed_session it does NOT reset the database."""
    c = httpx.Client(base_url=base, follow_redirects=True, timeout=20)
    r = c.get("/login.php")
    c.post("/login.php", data={"username": user, "password": password,
                               "Login": "Login", "user_token": _token(r.text)})
    return c


def _read_level(html):
    """DVWA's /security.php renders 'Security Level is currently: <em>X</em>'."""
    m = _CUR_RE.search(html or "")
    return m.group(1).lower() if m else None


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
        # Confirm on the SAME session that did the POST. DVWA's level is
        # per-session (cookie/$_SESSION), so a fresh login would read a
        # different session's default and give a false confirmation — never
        # cross-session confirm. If the read-back is unreadable we fail CLOSED
        # (verified=False -> ok=False): a false "patched" is worse than a false
        # "unconfirmed". In production patch_vuln talks directly to DVWA (no
        # proxy), so this read-back does not flake.
        new = _read_level(c.get("/security.php").text)
        c.close()
    except Exception as e:
        return {"ok": False, "requested": level, "error": str(e)}
    return {"ok": new == level, "level": new, "requested": level,
            "verified": new is not None}


def do_patch_vuln(level="impossible", **_):
    """Dispatch wrapper: returns a human-readable string for the tool_result."""
    r = patch_vuln(level)
    if not r["ok"]:
        if r.get("error"):
            return f"patch_vuln failed: {r['error']}"
        return (f"patch_vuln unconfirmed: could not verify DVWA security is now "
                f"'{r['requested']}' (read back {r.get('level')!r}) — retry or check manually.")
    return (f"DVWA security level raised to '{r['level']}' — the vulnerable module now "
            f"serves its safe/parameterized code path for sessions using the server "
            f"level. CAVEAT: DVWA reads a per-request 'security' cookie, so a client "
            f"that pins security=low still hits the vulnerable path; pair with a proxy "
            f"rule that strips/overrides the 'security' cookie for full eradication.")


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

# For blue_agent.py registration: TOOLS.append(PATCH_VULN_TOOL);
#                                 DISPATCH["patch_vuln"] = do_patch_vuln
REGISTER = {"name": "patch_vuln", "schema": PATCH_VULN_TOOL, "fn": do_patch_vuln}


if __name__ == "__main__":
    import json
    import sys
    lvl = sys.argv[1] if len(sys.argv) > 1 else "impossible"
    print(f"patching DVWA ({DVWA_URL}) -> security '{lvl}'")
    print(json.dumps(patch_vuln(lvl), indent=2))
