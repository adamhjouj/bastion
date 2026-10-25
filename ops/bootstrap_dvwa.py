"""Non-destructive DVWA authentication; reset is an explicit operator operation."""
import argparse
import os
import re

import httpx

TOKEN_RE = re.compile(r"user_token'?\s*value=['\"]([0-9a-f]+)['\"]", re.I)


def _token(html):
    match = TOKEN_RE.search(html)
    return match.group(1) if match else ""


def authed_session(base_url, xff=None, user=None, password=None):
    headers = {"X-Forwarded-For": xff} if xff else {}
    client = httpx.Client(base_url=base_url, headers=headers, follow_redirects=True, timeout=10)
    try:
        page = client.get("/login.php")
        response = client.post("/login.php", data={"username": user or os.getenv("DVWA_USER", "admin"),
                               "password": password or os.getenv("DVWA_PASSWORD", "password"),
                               "Login": "Login", "user_token": _token(page.text)})
        if response.status_code >= 400 or "name='username'" in response.text or 'name="username"' in response.text:
            raise RuntimeError("DVWA login failed; initialize DB explicitly if needed")
        return client
    except Exception:
        client.close()
        raise


def initialize_database(base_url, confirmation):
    if confirmation != "RESET-DVWA":
        raise ValueError("explicit RESET-DVWA confirmation required")
    with httpx.Client(base_url=base_url, follow_redirects=True, timeout=20) as client:
        page = client.get("/setup.php")
        response = client.post("/setup.php", data={"create_db": "Create / Reset Database", "user_token": _token(page.text)})
        response.raise_for_status()


def verify(base_url):
    with authed_session(base_url) as client:
        response = client.get("/index.php")
        return response.status_code == 200 and "login.php" not in str(response.url), response.status_code


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("base_url")
    parser.add_argument("--reset-confirm", default="")
    args = parser.parse_args()
    if args.reset_confirm:
        initialize_database(args.base_url, args.reset_confirm)
    ok, code = verify(args.base_url)
    print(f"DVWA login check: {'OK' if ok else 'FAILED'} ({code})")
    raise SystemExit(0 if ok else 1)
