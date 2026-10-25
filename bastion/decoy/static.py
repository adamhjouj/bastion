"""Last-resort decoy page (the original static honeypot page). Served when nothing has been
learned and no LLM is available. No honeypot/decoy tells anywhere in here."""

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

# 1x1 transparent GIF for learned image routes (content-type is all we keep for binaries).
GIF_1X1 = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,"
           b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")
