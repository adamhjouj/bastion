"""DVWA auth plumbing, reused by the red agent and by run.sh's health check.
Creates/resets the DB, logs in, and sets Security=Low. The #1 demo-day failure
is an uninitialised DVWA DB — this removes it."""
import re
import sys

import httpx

TOKEN_RE = re.compile(r"user_token'?\s*value=['\"]([0-9a-f]+)['\"]", re.I)


def _token(html):
    m = TOKEN_RE.search(html)
    return m.group(1) if m else ""


def authed_session(base_url, xff=None, user="admin", password="password"):
    """Return a logged-in DVWA httpx session (Security=Low). base_url can be the
    app directly or the proxy; xff sets X-Forwarded-For (the attacker's IP)."""
    headers = {"X-Forwarded-For": xff} if xff else {}
    # On a fresh DB, DVWA regenerates the session id on login, so across the
    # setup->login->security flow the jar accumulates stale/duplicate PHPSESSID
    # cookies and httpx sends the wrong one -> the session lands logged-out
    # (the #1 demo-day flake). Record every PHPSESSID the server issues, then pin
    # the jar to the last one. Harmless on a warm DB (only one is ever issued).
    issued = []

    def _grab(resp):
        for sc in resp.headers.get_list("set-cookie"):
            m = re.search(r"PHPSESSID=([^;]+)", sc)
            if m:
                issued.append(m.group(1))

    c = httpx.Client(base_url=base_url, headers=headers, follow_redirects=True,
                     timeout=20, event_hooks={"response": [_grab]})

    r = c.get("/setup.php")                                   # create/reset DB (idempotent)
    c.post("/setup.php", data={"create_db": "Create / Reset Database",
                               "user_token": _token(r.text)})
    r = c.get("/login.php")                                   # log in
    c.post("/login.php", data={"username": user, "password": password,
                               "Login": "Login", "user_token": _token(r.text)})
    r = c.get("/security.php")                                # set deployed level: medium
    c.post("/security.php", data={"security": "medium", "seclev_submit": "Submit",
                                  "user_token": _token(r.text)})

    c.cookies.clear()                                         # drop stale/duplicate PHPSESSID
    if issued:
        c.cookies.set("PHPSESSID", issued[-1])               # pin the authenticated session id
    c.cookies.set("security", "medium")                      # belt and suspenders
    return c


def verify(base_url):
    c = authed_session(base_url)
    r = c.get("/vulnerabilities/sqli/", params={"id": "1", "Submit": "Submit"})
    ok = r.status_code == 200 and ("First name" in r.text or "ID:" in r.text)
    return ok, r.status_code


if __name__ == "__main__":
    base = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:80"
    ok, code = verify(base)
    print(f"DVWA bootstrap via {base}: {'OK' if ok else 'FAILED'} (status {code})")
    sys.exit(0 if ok else 1)
