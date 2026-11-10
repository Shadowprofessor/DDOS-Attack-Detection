# -*- coding: utf-8 -*-
"""
Serves the React SOC app (`dashboard/dist`) at /app and adds browser security headers.

* `/app` and `/app/<path>`: a file is served only if it is in the server-built index of dist
  (no path is built from the URL, so no traversal); anything else gets index.html (SPA
  fallback). `/api/*` is never touched.
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


_index_cache: dict = {"key": None, "files": {}}


def _dist_files(dist: Path, index: Path) -> dict:
    """Map of 'relative/posix/path' -> file, built by walking dist ourselves (rebuilt per build).

    Requests are looked up in this map, so no filesystem path is ever built from the URL."""
    key = (str(dist), index.stat().st_mtime_ns)
    if _index_cache["key"] != key:
        files = {}
        for p in dist.rglob("*"):
            if p.is_file() and not p.is_symlink():
                files[p.relative_to(dist).as_posix()] = p
        _index_cache.update(key=key, files=files)
    return _index_cache["files"]


def _serve(rel: str):
    dist = DIST_DIR.resolve()
    index = dist / "index.html"
    if not index.is_file():
        return HTMLResponse(NOT_BUILT, status_code=503)
    if rel:
        target = _dist_files(dist, index).get(rel)
        if target is not None:
            # hashed assets are immutable; index.html is not cached
            cache = "public, max-age=31536000, immutable" if rel.startswith("assets/") else "no-cache"
            return FileResponse(target, headers={"Cache-Control": cache})
        if "." in rel.rsplit("/", 1)[-1]:  # looks like a missing asset, not a client route
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
