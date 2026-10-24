"""Autonomous red-team agent — a realistic EXTERNAL attacker. It starts with NO
credentials and NO knowledge of the app: it recons the target, gains access on
its own, discovers an exploitable input, then exploits it. All traffic goes
through the proxy with a distinct attacker IP, so the blue side sees the whole
kill-chain rather than a pre-authenticated one-shot.

Usage: python3 red_agent.py sqli    # goal: dump the credential store   (or: cmdi -> RCE)
"""
import os
import re
import sys
import time

import httpx

import llm

PROXY = os.getenv("PROXY_URL", "http://localhost:8080")
ATTACKER_IP = os.getenv("ATTACKER_IP", "10.13.37.7")
MODEL = llm.model_for(os.getenv("RED_MODEL"), "claude-opus-4-5")
# Optional artificial pacing between requests. Default 0 — realism comes from the
# attacker having to recon/discover (many requests over real time), not a fake delay.
REQUEST_DELAY = float(os.getenv("RED_REQUEST_DELAY", "0"))
# DVWA stores its security level per session; the attacker's fresh session pins it to the
# app's deployed setting. A mechanic of the target, not part of the exploit.
DVWA_SECURITY = os.getenv("DVWA_SECURITY", "medium")

# An external attacker who just found the app: a bare, UNAUTHENTICATED session.
session = httpx.Client(base_url=PROXY, headers={"X-Forwarded-For": ATTACKER_IP},
                       follow_redirects=True, timeout=20)

_TOK = re.compile(r"user_token'?\s*value=['\"]([0-9a-f]+)['\"]", re.I)


def _token(html):
    match = _TOK.search(html)
    return match.group(1) if match else ""


_S = {"type": "string", "maxLength": 512}
TOOLS = [
    {"name": "http_request",
     "description": "Send one HTTP request to the target (any path) — for recon and for "
                    "attacks. Returns the status and response body.",
     "input_schema": {"type": "object", "additionalProperties": False,
                      "properties": {"method": {"type": "string", "enum": ["GET", "POST"]},
                                     "path": _S,
                                     "params": {"type": "object", "additionalProperties": {"type": "string"}},
                                     "body": {"type": "object", "additionalProperties": {"type": "string"}}},
                      "required": ["method", "path"]}},
    {"name": "authenticate",
     "description": "Attempt to log in with credentials (handles the login form + CSRF token). "
                    "Use after you find a login page; you start with no session. Try common "
                    "defaults first. Returns whether access was gained.",
     "input_schema": {"type": "object", "additionalProperties": False,
                      "properties": {"username": {"type": "string", "maxLength": 128},
                                     "password": {"type": "string", "maxLength": 128}},
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
        resp = session.request(method.upper(), path, params=params or {}, data=body or None)
    except Exception as exc:
        return f"ERROR: {exc}"
    text = resp.text if len(resp.text) <= 4000 else resp.text[:4000] + "\n…[truncated]"
    return f"HTTP {resp.status_code}\n{text}"


def authenticate(username, password):
    """Attacker action: try to log in with guessed/default creds. Handles the CSRF token and
    DVWA's session-id regeneration (pins the last PHPSESSID the server issues, which otherwise
    leaves the session logged-out on a fresh DB). Also pins the app's per-session security
    level to its deployed setting — a DVWA mechanic, not the exploit. Returns success/failure."""
    issued = []

    def grab(resp):
        for raw in resp.headers.get_list("set-cookie"):
            match = re.search(r"PHPSESSID=([^;]+)", raw)
            if match:
                issued.append(match.group(1))

    session.event_hooks = {"response": [grab]}
    try:
        page = session.get("/login.php")
        session.post("/login.php", data={"username": username, "password": password,
                                         "Login": "Login", "user_token": _token(page.text)})
        page = session.get("/security.php")
        session.post("/security.php", data={"security": DVWA_SECURITY, "seclev_submit": "Submit",
                                            "user_token": _token(page.text)})
    except Exception as exc:
        session.event_hooks = {"response": []}
        return f"ERROR during login: {exc}"
    session.event_hooks = {"response": []}
    session.cookies.clear()
    if issued:
        session.cookies.set("PHPSESSID", issued[-1])
    session.cookies.set("security", DVWA_SECURITY)
    probe = session.get("/index.php")
    ok = "Logout" in probe.text or "Welcome" in probe.text
    return ("Authentication SUCCEEDED — you now have a session and the app is accessible."
            if ok else f"Authentication FAILED (HTTP {probe.status_code}) — credentials rejected.")


DISPATCH = {"http_request": http_request, "authenticate": authenticate}


def run(target):
    client, create_kwargs = llm.make_client()
    if client is None:
        sys.exit("set DEEPSEEK_API_KEY or ANTHROPIC_API_KEY to run the red agent")
    if target not in GOALS:
        sys.exit(f"unknown target: {target!r}; choices: {sorted(GOALS)}")
    system = (
        "You are an autonomous red-team operator in an AUTHORIZED sandboxed lab test. You are "
        "an EXTERNAL attacker: you have NO credentials and NO prior knowledge of the target "
        "app's structure, endpoints, or vulnerabilities — discover everything yourself by "
        "interacting with it.\n\n"
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
        resp = client.messages.create(model=MODEL, max_tokens=4096, system=system,
                                      tools=TOOLS, messages=messages, **(create_kwargs or {}))
        messages.append({"role": "assistant", "content": resp.content})
        for block in resp.content:
            if block.type == "text" and block.text.strip():
                print(f"[red] {block.text.strip()}", flush=True)
        if resp.stop_reason != "tool_use":
            break
        results = []
        for block in resp.content:
            if block.type == "tool_use":
                i = block.input
                if block.name == "authenticate":
                    print(f"[red] -> authenticate({i.get('username')}:{i.get('password')})", flush=True)
                else:
                    print(f"[red] -> {i.get('method')} {i.get('path')}", flush=True)
                fn = DISPATCH.get(block.name)
                out = fn(**i) if fn else f"unknown tool {block.name}"
                results.append({"type": "tool_result", "tool_use_id": block.id, "content": out})
        messages.append({"role": "user", "content": results})


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "sqli")
