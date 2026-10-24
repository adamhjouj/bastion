"""System-1 triage: TypeSafe Jev classifies each HTTP request as malicious /
benign (+ attack type), cheaply and fast, before the heavyweight blue-team agent
reasons about a response. Raw REST (docs: https://docs.typesafe.ai/api/system-one).

Request:  POST /v1/systemone  {model, state, questions:{name:{type,instructions,criteria}}}
Response: {answers:{name:{type:"noul", noul:0..1} | {type:"choice", choice, confidence, probabilities}}}
"""
import json
import os
import sys

import httpx

URL = os.environ.get("JEV_URL", "https://api.typesafe.ai/v1/systemone")
MODEL = os.environ.get("JEV_MODEL", "jev-latest")
API_KEY = os.environ.get("TYPESAFE_API_KEY", "")
THRESHOLD = float(os.environ.get("MALICIOUS_THRESHOLD", "0.5"))

QUESTIONS = {
    "malicious": {
        "type": "noul",
        "instructions": ("Is this HTTP request an attempt to attack or exploit the web "
                         "application (SQL injection, command injection, XSS, path "
                         "traversal, etc.)? Answer true only for genuinely malicious "
                         "requests, not normal browsing, logins, or static assets."),
    },
    "attack_type": {
        "type": "choice",
        "instructions": "If this request is an attack, which type best fits?",
        "criteria": {
            "sql_injection": "Manipulating a DB query: UNION SELECT, OR 1=1, quotes/comment sequences in params",
            "command_injection": "Injecting OS shell commands: ; cat /etc/passwd, pipes, backticks, $()",
            "xss": "Injecting script/HTML: <script>, onerror=, javascript:",
            "path_traversal": "Escaping the web root: ../ sequences, reading /etc/passwd",
            "benign": "A normal, non-malicious request",
        },
    },
}


def _render(ev):
    return ("HTTP request to a web application:\n"
            f"Method: {ev.get('method', '')}\n"
            f"Path: {ev.get('path', '')}\n"
            f"Query: {ev.get('query', '')}\n"
            f"Body: {ev.get('body', '')}\n"
            f"Source IP: {ev.get('ip', '')}")


def classify_request(event, timeout=10):
    """Return {malicious, malicious_score, attack_type, type_confidence, probabilities}.
    On API error returns {error, malicious: None} so the caller can fail-safe."""
    try:
        r = httpx.post(URL,
                       headers={"Authorization": f"Bearer {API_KEY}",
                                "Content-Type": "application/json"},
                       json={"model": MODEL, "state": _render(event), "questions": QUESTIONS},
                       timeout=timeout)
        r.raise_for_status()
        return parse_answers(r.json())
    except Exception as e:
        return {"error": str(e), "malicious": None, "malicious_score": None,
                "attack_type": None, "type_confidence": None, "probabilities": {}}


def parse_answers(resp):
    ans = resp["answers"]
    noul = ans["malicious"]["noul"]
    choice = ans["attack_type"]["choice"]
    probs = ans["attack_type"].get("probabilities", {})
    malicious = noul >= THRESHOLD
    # If flagged malicious but the top choice is "benign", use the best non-benign type.
    if malicious and choice == "benign" and probs:
        nonbenign = {k: v for k, v in probs.items() if k != "benign"}
        if nonbenign:
            choice = max(nonbenign, key=nonbenign.get)
    return {"malicious": malicious, "malicious_score": noul, "attack_type": choice,
            "type_confidence": ans["attack_type"].get("confidence"), "probabilities": probs}


if __name__ == "__main__":
    # Live single-shot: python classifier.py            -> runs two built-in samples
    #                   python classifier.py '<json event>' -> classifies that event
    if not API_KEY:
        sys.exit("set TYPESAFE_API_KEY (your Jev key) first")
    if len(sys.argv) > 1:
        samples = [json.loads(sys.argv[1])]
    else:
        samples = [
            {"method": "GET", "path": "/vulnerabilities/sqli/",
             "query": "id=1' UNION SELECT user,password FROM users-- -&Submit=Submit",
             "body": "", "ip": "10.13.37.7"},
            {"method": "GET", "path": "/login.php", "query": "", "body": "", "ip": "127.0.0.1"},
        ]
    for ev in samples:
        print(f"\n{ev['method']} {ev['path']}?{ev['query']}")
        print("  ->", json.dumps(classify_request(ev), indent=2))
