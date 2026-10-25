"""Static operator dashboard served under the authenticated /__ management boundary.

The single-page app is plain HTML/CSS/JS (no build step, no external origins) so it
satisfies the proxy's strict CSP (`default-src 'self'`): assets are same-origin, there
is no inline script or style, and it talks only to /__api/v1 over fetch and SSE. Auth is
inherited from the management middleware that guards every /__ path.
"""
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, RedirectResponse

router = APIRouter()
FRONTEND = Path(__file__).resolve().parent.parent / "frontend"  # repo/app root
SITE = Path(__file__).resolve().parent.parent / "site"          # standalone marketing homepage

# Servable asset types by extension. The requested path is resolved under FRONTEND and
# verified to stay inside it, so nested module/style files (e.g. pages/overview.js) are
# served while path traversal is refused.
MEDIA = {
    ".js": "text/javascript; charset=utf-8",
    ".mjs": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".png": "image/png",
    ".woff2": "font/woff2",
}


@router.get("/__dash")
def dashboard_index():
    index = FRONTEND / "index.html"
    if not index.is_file():
        raise HTTPException(404, "dashboard not built")
    return FileResponse(index, media_type="text/html; charset=utf-8")


@router.get("/__dash/{asset:path}")
def dashboard_asset(asset: str):
    media_type = MEDIA.get(Path(asset).suffix.lower())
    if media_type is None:
        raise HTTPException(404, "unknown asset")
    root = FRONTEND.resolve()
    target = (root / asset).resolve()
    if root not in target.parents:
        raise HTTPException(404, "not found")   # refuse traversal outside frontend/
    if not target.is_file():
        raise HTTPException(404, "asset not found")
    return FileResponse(target, media_type=media_type)


# --- Public marketing homepage -------------------------------------------------------------
# The standalone static site (site/) is the public front door. It is served under /__home so it
# shares the stack's single origin; the proxy middleware exempts /__home from auth and swaps the
# dashboard's strict CSP for a marketing CSP (the page uses Google Fonts + one inline bootstrap
# script). Served at /__home/ with a trailing slash so the page's relative asset references
# (site.css, assets/...) resolve under /__home/ rather than the proxy root.
SITE_MEDIA = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".webp": "image/webp", ".gif": "image/gif", ".svg": "image/svg+xml",
    ".ico": "image/x-icon", ".avif": "image/avif", ".webmanifest": "application/manifest+json",
    ".woff2": "font/woff2", ".woff": "font/woff", ".ttf": "font/ttf", ".txt": "text/plain; charset=utf-8",
}


def _site_index():
    index = SITE / "index.html"
    if not index.is_file():
        raise HTTPException(404, "marketing site not built")
    return FileResponse(index, media_type="text/html; charset=utf-8")


@router.get("/__home")
def home_redirect():
    return RedirectResponse(url="/__home/", status_code=308)  # trailing slash: relative assets


@router.get("/__home/")
def home_index():
    return _site_index()


@router.get("/__home/{asset:path}")
def home_asset(asset: str):
    if not asset:
        return _site_index()
    media_type = SITE_MEDIA.get(Path(asset).suffix.lower())
    if media_type is None:
        raise HTTPException(404, "unknown asset")
    root = SITE.resolve()
    target = (root / asset).resolve()
    if root not in target.parents:
        raise HTTPException(404, "not found")   # refuse traversal outside site/
    if not target.is_file():
        raise HTTPException(404, "asset not found")
    return FileResponse(target, media_type=media_type)
