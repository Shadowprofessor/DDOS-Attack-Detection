# -*- coding: utf-8 -*-
"""
FastAPI Router for Real-time Dashboard and WebSocket Telemetry Stream.
"""
import os
from fastapi import APIRouter, WebSocket, Request, Depends, HTTPException

from src.web.realtime_dashboard.broadcaster import get_broadcaster
from src.mitigation.manager import get_manager

router = APIRouter()



async def _require_api_key(request: Request):
    """Auth for the dashboard JSON/LLM endpoints. Lazy import avoids a circular import
    with scoring_service (which includes this router at module load)."""
    from src.api.scoring_service import _get_valid_api_keys, _get_valid_admin_keys
    from src.api.rbac import key_from_request
    key = key_from_request(request)  # header key, or SOC web-app session (+CSRF on POST)
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

    from src.api.rbac import ws_session_key

    await broadcaster.handle_connection(
        websocket=websocket,
        valid_keys=valid_keys,
        get_pending_fn=get_pending_actions_list,
        auth_timeout=5.0,
        preauth_key=ws_session_key(websocket),  # SOC app: same-origin session cookie
    )


@router.get("/dashboard", include_in_schema=False)
@router.get("/legacy", include_in_schema=False)
async def legacy_dashboard_redirect():
    """The legacy dashboard was removed in v5.0.0; its URLs redirect permanently to the SOC app."""
    from fastapi.responses import RedirectResponse
    return RedirectResponse("/app/", status_code=308)


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


# v4.7.0 bug hunt: each chat message may be an LLM call; unlimited chat = unbounded cost / DoS.
_CHAT_RATE_PER_MIN = int(os.environ.get("DDOS_CHAT_RATE_PER_MIN", "20"))
_chat_limiter = None


def _get_chat_limiter():
    global _chat_limiter
    if _chat_limiter is None:
        from src.api.analyst_router import _KeyRateLimiter
        _chat_limiter = _KeyRateLimiter(_CHAT_RATE_PER_MIN)
    return _chat_limiter


@router.post("/api/chat")
async def chat_with_soc_assistant(request: Request, key: str = Depends(_require_api_key)):
    """
    Read-only advisory chat endpoint.
    Answers operator questions grounded in live telemetry via Nemotron 3 Ultra.
    ZERO execution authority — cannot approve or execute mitigation actions.
    """
    import hashlib
    if not _get_chat_limiter().allow(hashlib.sha256(key.encode("utf-8")).hexdigest()):
        raise HTTPException(status_code=429, detail="Chat rate limit exceeded; retry later.")
    try:
        body = await request.json()
    except Exception:
        body = {}
    message = str(body.get("message", ""))[:2000] if isinstance(body, dict) else ""
    from src.agent.soc_chat_assistant import get_soc_chat_assistant
    assistant = get_soc_chat_assistant()
    return assistant.answer_query(message)


