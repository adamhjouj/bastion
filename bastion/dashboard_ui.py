"""Static operator dashboard served under the authenticated /__ management boundary.

The single-page app is plain HTML/CSS/JS (no build step, no external origins) so it
satisfies the proxy's strict CSP (`default-src 'self'`): assets are same-origin, there
is no inline script or style, and it talks only to /__api/v1 over fetch and SSE. Auth is
inherited from the management middleware that guards every /__ path.
"""
from pathlib import Path

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

router = APIRouter()
FRONTEND = Path(__file__).resolve().parent.parent / "frontend"  # repo/app root

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
