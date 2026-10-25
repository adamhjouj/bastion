"""Decoy web app. When the blue team confirms an attacker, the proxy diverts
their traffic here instead of the real app — they keep probing a convincing
fake while we remediate. Every hit is logged to data/honeypot_hits.jsonl so we
bank their TTPs (paths, payloads, tooling) for free.

# ponytail: one static fake page for every route — enough to look real and
# capture the requests. Add per-path fakes (/login POST that "fails", /admin)
# only if an attacker needs more rope to stay engaged.
"""
import asyncio
import os

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from bastion import store
from bastion.privacy import form_view

app = FastAPI()

# Any real-looking app page. No honeypot/decoy tells anywhere in here.
PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Acme Internal Portal</title>
<style>
body{font-family:Arial,Helvetica,sans-serif;background:#f4f6f8;margin:0;color:#222}
.box{max-width:340px;margin:8vh auto;background:#fff;padding:32px;border:1px solid #d9dee3;border-radius:6px}
h1{font-size:20px;margin:0 0 4px}.sub{color:#788;font-size:13px;margin:0 0 20px}
label{display:block;font-size:13px;margin:12px 0 4px}
input{width:100%;box-sizing:border-box;padding:9px;border:1px solid #cfd6dd;border-radius:4px}
button{width:100%;margin-top:18px;padding:10px;background:#1f6fd6;color:#fff;border:0;border-radius:4px;font-size:14px;cursor:pointer}
.foot{text-align:center;color:#9aa5b1;font-size:11px;margin-top:22px}
</style>
</head>
<body>
<div class="box">
<h1>Acme Internal Portal</h1>
<p class="sub">Sign in to continue to your workspace</p>
<form method="post" action="/login">
<label>Username</label>
<input type="text" name="username" autocomplete="username" autofocus>
<label>Password</label>
<input type="password" name="password" autocomplete="current-password">
<button type="submit">Sign in</button>
</form>
<p class="foot">Acme Corp &middot; v2.4.1 &middot; Authorized users only</p>
</div>
</body>
</html>
"""

METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]


def _ip(request: Request) -> str:
    # X-Forwarded-For first hop if present, else client host (matches proxy.source_ip).
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@app.api_route("/{path:path}", methods=METHODS)
async def decoy(path: str, request: Request):
    body = await request.body()
    # store.DATA read at call time so a test can monkeypatch it to a tempdir.
    ct = request.headers.get("content-type", "")
    body_text = body.decode("utf-8", "ignore")[:2000]
    if "application/x-www-form-urlencoded" in ct:
        body_text = str(form_view(body_text))
    store.append_jsonl(store.DATA / "honeypot_hits.jsonl", {
        "ts": store.now(),
        "ip": _ip(request),
        "method": request.method,
        "path": "/" + path,
        "query": request.url.query,
        "body": body_text,
        "user_agent": request.headers.get("user-agent", ""),
    })
    delay = float(os.environ.get("HONEYPOT_DELAY", "0"))
    if delay > 0:
        await asyncio.sleep(delay)  # tarpit: stall the attacker without blocking the loop
    return HTMLResponse(PAGE)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("HONEYPOT_PORT", "9000")))
