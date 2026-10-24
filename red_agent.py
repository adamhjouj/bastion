"""Scoped red-team agent. Authenticates to DVWA without resetting the database."""
import os
import sys

import llm
from bootstrap_dvwa import authed_session

PROXY = os.getenv("PROXY_URL", "http://localhost:8080")
ATTACKER_IP = os.getenv("ATTACKER_IP", "10.13.37.7")
MODEL = llm.model_for(os.getenv("RED_MODEL"), "claude-opus-4-5")

TOOL = [{"name": "http_request",
         "description": "Send one HTTP request to the target and return the status and response body.",
         "input_schema": {"type": "object", "additionalProperties": False,
                          "properties": {"method": {"type": "string", "enum": ["GET", "POST"]},
                                         "path": {"type": "string", "maxLength": 512},
                                         "params": {"type": "object", "additionalProperties": {"type": "string"}},
                                         "body": {"type": "object", "additionalProperties": {"type": "string"}}},
                          "required": ["method", "path"]}}]

OBJECTIVES = {
    "sqli": ("Target /vulnerabilities/sqli/ only. GET with id= and Submit=Submit. "
             "Find SQL injection in id that dumps usernames and password hashes. "
             "Iterate on responses. When you have the data, STOP and report."),
    "cmdi": ("Target /vulnerabilities/exec/ only. POST with ip= and Submit=Submit. "
             "Find command injection that reads /etc/passwd. "
             "Iterate on responses. When you have the file, STOP and report."),
}

ALLOWED_PATHS = {
    "sqli": {"/vulnerabilities/sqli/"},
    "cmdi": {"/vulnerabilities/exec/"},
}


def run(target):
    client, create_kwargs = llm.make_client()
    if client is None:
        sys.exit("set DEEPSEEK_API_KEY or ANTHROPIC_API_KEY to run the red agent")
    if target not in OBJECTIVES:
        sys.exit(f"unknown target: {target!r}; choices: {sorted(OBJECTIVES)}")
    session = authed_session(PROXY, xff=ATTACKER_IP)

    def http_request(method, path, params=None, body=None):
        allowed = ALLOWED_PATHS[target]
        if not any(path.startswith(p) for p in allowed):
            return f"TOOL ERROR: path {path!r} is outside this objective's scope"
        try:
            resp = session.request(method.upper(), path, params=params or {}, data=body)
        except Exception as exc:
            return f"ERROR: {exc}"
        text = resp.text if len(resp.text) <= 4000 else resp.text[:4000] + "\n…[truncated]"
        return f"HTTP {resp.status_code}\n{text}"

    system = (f"You are an authorized red-team operator in a sandboxed lab (DVWA). "
              f"Your scope is one endpoint and one objective. Only use http_request with the allowed path. "
              f"Objective: {OBJECTIVES[target]}")
    messages = [{"role": "user", "content": "Begin."}]
    for _ in range(25):
        resp = client.messages.create(model=MODEL, max_tokens=4096, system=system,
                                      tools=TOOL, messages=messages, **(create_kwargs or {}))
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
                print(f"[red] -> {i.get('method')} {i.get('path')}", flush=True)
                results.append({"type": "tool_result", "tool_use_id": block.id,
                                "content": http_request(i["method"], i["path"],
                                                        i.get("params"), i.get("body"))})
        messages.append({"role": "user", "content": results})


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "sqli")
