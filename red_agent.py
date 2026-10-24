"""Autonomous red-team agent — a realistic EXTERNAL attacker. It starts with NO
credentials and NO knowledge of the app: it must recon the target, gain access on
its own, discover an exploitable input, then exploit it. All traffic goes through
the proxy with a distinct attacker IP, so the blue agent sees the whole kill-chain.

Usage: python3 red_agent.py sqli    # goal: dump credential DB   (or: cmdi -> RCE)
"""
import os
import re
import sys
import time

import httpx

import llm

PROXY = os.environ.get("PROXY_URL", "http://localhost:8080")
ATTACKER_IP = os.environ.get("ATTACKER_IP", "10.13.37.7")
MODEL = llm.model_for(os.environ.get("RED_MODEL"), "claude-opus-5")
# Optional artificial pacing between requests. Default 0 — realism now comes from the
# attacker having to recon/discover (many requests over real time), not a fake delay.
REQUEST_DELAY = float(os.environ.get("RED_REQUEST_DELAY", "0"))

# An external attacker who just found the app: a bare, UNAUTHENTICATED session.
session = httpx.Client(base_url=PROXY, headers={"X-Forwarded-For": ATTACKER_IP},
                       follow_redirects=True, timeout=20)

_TOK = re.compile(r"user_token'?\s*value=['\"]([0-9a-f]+)['\"]", re.I)


def _token(html):
    m = _TOK.search(html)
    return m.group(1) if m else None


TOOLS = [
    {"name": "http_request",
     "description": "Send an HTTP request to the target web app (any path). Use it to browse "
                    "/ recon the app and to send attack payloads. Returns status + response body.",
     "input_schema": {"type": "object", "properties": {
         "method": {"type": "string"},
         "path": {"type": "string", "description": "e.g. / or /login.php or /vulnerabilities/..."},
         "params": {"type": "object", "description": "query-string params"},
         "body": {"type": "object", "description": "form body for POST"}},
         "required": ["method", "path"]}},
    {"name": "authenticate",
     "description": "Attempt to log into the app with credentials (handles the login form + "
                    "CSRF token). Use this AFTER you find a login page; you start with no "
                    "session. Try common defaults first. Returns whether access was gained.",
     "input_schema": {"type": "object", "properties": {
         "username": {"type": "string"},
         "password": {"type": "string"}},
         "required": ["username", "password"]}},
]

GOALS = {
    "sqli": ("exfiltrate the application's user credential store — every username and "
             "password hash held in its database."),
    "cmdi": ("achieve remote command execution on the server and read a sensitive system "
             "file such as /etc/passwd."),
}


def http_request(method, path, params=None, body=None):
    if REQUEST_DELAY > 0:
        time.sleep(REQUEST_DELAY)
    try:
        r = session.request(method.upper(), path, params=params or {}, data=body or None)
    except Exception as e:
        return f"ERROR: {e}"
    text = r.text if len(r.text) <= 4000 else r.text[:4000] + "\n...[truncated]"
    return f"HTTP {r.status_code}\n{text}"


def authenticate(username, password):
    """Attacker action: try to log in with guessed/default creds. Handles the CSRF token and
    the session-id regeneration quirk (pins the last PHPSESSID the server issues). Also pins
    the app's per-session security level to its deployed (medium) setting — a DVWA mechanic
    the attacker lands in, not part of the exploit. Returns success/failure."""
    issued = []

    def grab(resp):
        for sc in resp.headers.get_list("set-cookie"):
            m = re.search(r"PHPSESSID=([^;]+)", sc)
            if m:
                issued.append(m.group(1))

    session.event_hooks = {"response": [grab]}
    try:
        r = session.get("/login.php")
        session.post("/login.php", data={"username": username, "password": password,
                                         "Login": "Login", "user_token": _token(r.text)})
        r = session.get("/security.php")
        session.post("/security.php", data={"security": "medium", "seclev_submit": "Submit",
                                            "user_token": _token(r.text)})
    except Exception as e:
        session.event_hooks = {"response": []}
        return f"ERROR during login: {e}"
    session.event_hooks = {"response": []}
    session.cookies.clear()
    if issued:
        session.cookies.set("PHPSESSID", issued[-1])
    session.cookies.set("security", "medium")
    probe = session.get("/index.php")
    ok = "Logout" in probe.text or "Welcome" in probe.text
    return ("Authentication SUCCEEDED — you now have a session and the app is accessible."
            if ok else f"Authentication FAILED (HTTP {probe.status_code}) — credentials rejected.")


DISPATCH = {"http_request": http_request, "authenticate": authenticate}


def run(target):
    if target not in GOALS:
        sys.exit(f"unknown objective {target!r}; choose one of: {', '.join(GOALS)}")
    client, create_kwargs = llm.make_client()
    if client is None:
        sys.exit("set DEEPSEEK_API_KEY or ANTHROPIC_API_KEY to run the red agent")
    system = (
        "You are an autonomous red-team operator in an AUTHORIZED sandboxed lab test. You "
        "are an EXTERNAL attacker: you have NO credentials and NO prior knowledge of the "
        "target app's structure, endpoints, or vulnerabilities — discover everything "
        "yourself by interacting with it.\n\n"
        "Your goal: " + GOALS[target] + "\n\n"
        "Work like a real attacker, ONE request at a time, reading each response before the "
        "next:\n"
        "1. RECON — browse the app (start at / and /index.php); map its pages, forms, and "
        "parameters; figure out how it works and where it may be weak.\n"
        "2. ACCESS — if it needs a login, call the 'authenticate' tool to try credentials, "
        "starting with common defaults (e.g. admin/password). You are given no session.\n"
        "3. DISCOVER — find an input that looks exploitable for your goal.\n"
        "4. EXPLOIT — probe it, read responses, refine the payload, and achieve the goal.\n\n"
        "Use http_request for all browsing and attacks. If something is blocked (403), note "
        "it and reason — do not blindly hammer the same payload. When you achieve the goal, "
        "STOP and report exactly what you did, the working payload, and what you obtained.")
    messages = [{"role": "user", "content": f"Begin your assessment of the target at {PROXY}."}]
    for _ in range(40):
        resp = client.messages.create(model=MODEL, max_tokens=8000, system=system,
                                      tools=TOOLS, messages=messages, **create_kwargs)
        messages.append({"role": "assistant", "content": resp.content})
        for b in resp.content:
            if b.type == "text" and b.text.strip():
                print(f"[red] {b.text.strip()}", flush=True)
        if resp.stop_reason != "tool_use":
            break
        results = []
        for b in resp.content:
            if b.type == "tool_use":
                i = b.input
                if b.name == "authenticate":
                    print(f"[red] -> authenticate({i.get('username')}:{i.get('password')})", flush=True)
                else:
                    print(f"[red] -> {i.get('method')} {i.get('path')} "
                          f"{i.get('params') or i.get('body') or ''}", flush=True)
                fn = DISPATCH.get(b.name)
                out = fn(**i) if fn else f"unknown tool {b.name}"
                results.append({"type": "tool_result", "tool_use_id": b.id, "content": out})
        messages.append({"role": "user", "content": results})


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "sqli")
