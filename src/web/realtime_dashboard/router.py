# -*- coding: utf-8 -*-
"""
FastAPI Router for Real-time Dashboard and WebSocket Telemetry Stream.
"""
import os
from fastapi import APIRouter, WebSocket
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from src.web.realtime_dashboard.broadcaster import get_broadcaster
from src.mitigation.manager import get_manager

router = APIRouter()

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


@router.websocket("/ws/dashboard")
async def websocket_dashboard_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint streaming live flows, alert bursts, and pending actions.
    Enforces first-message authentication.
    """
    # Import current active keys from scoring_service
    from src.api.scoring_service import API_KEYS, ADMIN_KEYS

    valid_keys = set(API_KEYS) | set(ADMIN_KEYS)
    broadcaster = get_broadcaster()

    def get_pending_actions_list():
        mgr = get_manager()
        return list(mgr.get_pending().values())

    await broadcaster.handle_connection(
        websocket=websocket,
        valid_keys=valid_keys,
        get_pending_fn=get_pending_actions_list,
        auth_timeout=5.0,
    )


@router.get("/dashboard", response_class=HTMLResponse)
async def serve_dashboard_html():
    """Serve the real-time SOC dashboard HTML interface."""
    index_path = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path, media_type="text/html")
    return HTMLResponse("<h1>Real-Time Dashboard UI Not Found</h1>", status_code=404)
