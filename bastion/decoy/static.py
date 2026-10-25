"""Last-resort decoy response, built to match WHATEVER application the decoy currently fronts.

There is no hard-coded brand here. When the shape model has learned the app's identity we render
a minimal page carrying its own title; when nothing has been learned yet and no LLM is available
(cold start), we serve a brand-less, plausible holding page that reveals no contradictory identity
and no decoy tells. The warm path (learned templates / learned error page) handles everything else.
"""
import html

# A neutral internal-app sign-in shell. `{title}` is the learned title (or "Sign in" when unknown);
# `{brand}` is the learned app name as a heading (or a generic "Sign in" when unknown). The form
# posts to itself (action="") so no route name is ever invented. Palette is a plain professional
# slate — no logo, no company name, nothing that identifies it as anything in particular.
_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
body{{font:15px/1.5 system-ui,Segoe UI,Arial,sans-serif;margin:0;color:#1d2733;background:#f4f6f9}}
.box{{max-width:340px;margin:12vh auto;background:#fff;padding:30px;border:1px solid #dbe1e8;border-radius:8px}}
h1{{font-size:18px;margin:0 0 18px;font-weight:600}}
label{{display:block;font-size:13px;margin:12px 0 4px;color:#44525f}}
input{{width:100%;box-sizing:border-box;padding:9px;border:1px solid #cdd5de;border-radius:5px}}
button{{width:100%;margin-top:18px;padding:10px;background:#2b3a4a;color:#fff;border:0;border-radius:5px;font-size:14px;cursor:pointer}}
</style>
</head>
<body>
<div class="box">
<h1>{brand}</h1>
<form method="post" action="">
<label>Username</label>
<input type="text" name="username" autocomplete="username" autofocus>
<label>Password</label>
<input type="password" name="password" autocomplete="current-password">
<button type="submit">Sign in</button>
</form>
</div>
</body>
</html>
"""


def fallback_page(shape=None):
    """Minimal last-resort HTML, consistent with the learned identity when one exists.

    Uses the shape's learned title suffix (e.g. "Helios Intranet") for the title and heading so the
    page never contradicts the app the decoy is mimicking. With no learned identity it falls back to
    a generic, brand-less "Sign in" page — never a fixed company name, never a decoy tell.
    """
    suffix = ""
    try:
        if shape is not None:
            suffix = (shape.fingerprint.get("title_suffix") or "").strip()
    except Exception:
        suffix = ""
    title = suffix or "Sign in"
    brand = suffix or "Sign in"
    return _TEMPLATE.format(title=html.escape(title), brand=html.escape(brand))


# 1x1 transparent GIF for image routes the decoy has to answer without a learned asset.
GIF_1X1 = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,"
           b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")
