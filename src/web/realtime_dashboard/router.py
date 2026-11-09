# -*- coding: utf-8 -*-
"""
FastAPI Router for Real-time Dashboard and WebSocket Telemetry Stream.
"""
import os
from fastapi import APIRouter, WebSocket, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from src.web.realtime_dashboard.broadcaster import get_broadcaster
from src.mitigation.manager import get_manager

router = APIRouter()

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


async def _require_api_key(request: Request):
    """Auth for the dashboard JSON/LLM endpoints. Lazy import avoids a circular import
    with scoring_service (which includes this router at module load)."""
    from src.api.scoring_service import _get_valid_api_keys, _get_valid_admin_keys
    key = request.headers.get("X-API-Key") or request.headers.get("X-Admin-Key")
    if not key or key not in (_get_valid_api_keys() | _get_valid_admin_keys()):
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return key


@router.websocket("/ws/dashboard")
async def websocket_dashboard_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint streaming live flows, alert bursts, and pending actions.
    Enforces first-message authentication.
    """
    # Import current active keys from scoring_service
    from src.api.scoring_service import _get_valid_api_keys, _get_valid_admin_keys

    valid_keys = _get_valid_api_keys() | _get_valid_admin_keys()
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


@router.get("/api/session-detection-summary", dependencies=[Depends(_require_api_key)])
async def get_session_detection_summary():
    """Return honest happened vs. detected summary from the persistent attack counter store."""
    from src.mitigation.attack_counters import get_attack_counters
    return get_attack_counters().get_summary()


@router.get("/api/campaigns", dependencies=[Depends(_require_api_key)])
async def get_campaigns():
    """Return active and concluded attack campaigns with bot breakdown and timeline."""
    try:
        from src.api.scoring_service import _CAMPAIGN_CORRELATOR
        active = _CAMPAIGN_CORRELATOR.get_active_campaigns()
        concluded = _CAMPAIGN_CORRELATOR.get_concluded_campaigns()
    except Exception:
        active = []
        concluded = []
    return {
        "active_campaigns": active,
        "concluded_campaigns": concluded,
    }


@router.post("/api/chat", dependencies=[Depends(_require_api_key)])
async def chat_with_soc_assistant(request: Request):
    """
    Read-only advisory chat endpoint.
    Answers operator questions grounded in live telemetry via Nemotron 3 Ultra.
    ZERO execution authority — cannot approve or execute mitigation actions.
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    message = body.get("message", "")
    from src.agent.soc_chat_assistant import get_soc_chat_assistant
    assistant = get_soc_chat_assistant()
    return assistant.answer_query(message)


