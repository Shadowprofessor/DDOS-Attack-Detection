# -*- coding: utf-8 -*-
"""
Serves the React SOC app (`dashboard/dist`) at /app and adds browser security headers.

* `/app` and `/app/<path>`: a real file inside dist is served; anything else gets index.html
  (SPA fallback). Paths are resolved and must stay inside dist (no traversal). `/api/*` is
  never touched.
* Security headers on /app* and /api*: strict CSP (no inline script/style), nosniff,
  no-referrer, Permissions-Policy, frame denial; HSTS in production/staging.
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse

DIST_DIR = Path(os.environ.get("DDOS_DASHBOARD_DIST") or
                Path(__file__).resolve().parent.parent.parent / "dashboard" / "dist")

CSP = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
       "font-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; "
       "base-uri 'none'; form-action 'self'")

BASE_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
}

NOT_BUILT = ("<!doctype html><title>SOC app not built</title>"
             "<p>Run <code>cd dashboard &amp;&amp; npm ci &amp;&amp; npm run build</code>.</p>")


def _is_prod() -> bool:
    return os.environ.get("DDOS_ENV", "").lower() in ("production", "prod", "staging")


def _serve(rel: str):
    dist = DIST_DIR.resolve()
    index = dist / "index.html"
    if not index.is_file():
        return HTMLResponse(NOT_BUILT, status_code=503)
    if rel:
        target = (dist / rel).resolve()
        if dist in target.parents and target.is_file():
            # hashed assets are immutable; index.html is not cached
            cache = "public, max-age=31536000, immutable" if "assets" in target.parts else "no-cache"
            return FileResponse(target, headers={"Cache-Control": cache})
        if "." in Path(rel).name:  # looks like a missing asset, not a client route
            raise HTTPException(status_code=404, detail="Not found.")
    return FileResponse(index, media_type="text/html", headers={"Cache-Control": "no-cache"})


def install(app: FastAPI) -> None:
    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path == "/app" or path.startswith("/app/") or path.startswith("/api/"):
            for k, v in BASE_HEADERS.items():
                response.headers.setdefault(k, v)
            response.headers["Content-Security-Policy"] = CSP
            if _is_prod():
                response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        return response

    @app.get("/app", include_in_schema=False)
    async def spa_root():
        return _serve("")

    @app.get("/app/{rel:path}", include_in_schema=False)
    async def spa(rel: str):
        return _serve(rel)
