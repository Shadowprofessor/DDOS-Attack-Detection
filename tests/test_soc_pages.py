# -*- coding: utf-8 -*-
"""v4.5.0: session auth for chat / analyst config / legacy stream, /api/system, /legacy deprecation."""
import json

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import src.api.scoring_service as api_module
from src.api.scoring_service import app
from src.api.session_router import login_limiter
from src.ir.runtime import IRRuntime, set_ir_runtime
from src.mitigation.manager import PendingActionManager
from src.web.session import COOKIE_NAME, get_session_store

ANALYST_KEY = "pages-analyst-key1"


@pytest.fixture
def c(tmp_path, monkeypatch):
    monkeypatch.setenv("DDOS_IR_SCHEDULER", "off")
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    storage = str(tmp_path / "actions.json")
    monkeypatch.setenv("DDOS_PENDING_ACTIONS_PATH", storage)
    orig = set(api_module.API_KEYS)
    api_module.API_KEYS.add(ANALYST_KEY)
    mgr = PendingActionManager.get_instance(storage)
    mgr.clear()
    set_ir_runtime(IRRuntime({}, database_url=f"sqlite:///{(tmp_path / 'ir.db').as_posix()}", manager_factory=lambda: mgr))
    get_session_store().clear()
    login_limiter.clear()
    try:
        with TestClient(app, base_url="https://testserver") as client:
            yield client
    finally:
        set_ir_runtime(None)
        get_session_store().clear()
        api_module.API_KEYS = orig


def _login(c):
    r = c.post("/api/session/login", json={"api_key": ANALYST_KEY})
    return r.json()["csrf_token"], r.cookies[COOKIE_NAME]


def test_chat_via_session_requires_csrf_and_stays_read_only(c):
    csrf, _ = _login(c)
    assert c.post("/api/chat", json={"message": "summary?"}).status_code == 403
    r = c.post("/api/chat", json={"message": "What is the current session detection summary?"},
               headers={"X-CSRF-Token": csrf})
    assert r.status_code == 200 and r.json()["authority"] == "READ_ONLY_ADVISORY"


def test_analyst_config_via_session(c):
    _login(c)
    r = c.get("/api/analyst/config")
    assert r.status_code == 200 and "api_key_present" in r.json() and "api_key" not in r.json()


def test_system_info_has_no_secrets(c):
    assert c.get("/api/system").status_code == 401
    _login(c)
    body = c.get("/api/system").json()
    assert body["version"].count(".") == 2 and body["role"] == "analyst"
    assert {"loaded", "artifacts"} <= set(body["models"])
    assert "rollback_ttl_s" in body["incident_response"]
    text = json.dumps(body)
    assert ANALYST_KEY not in text and "nvapi-" not in text and '"api_key":' not in text
    for a in body["models"]["artifacts"]:
        assert "/" not in a["name"] and "\\" not in a["name"]


def test_legacy_urls_redirect_permanently(c):
    for path in ("/dashboard", "/legacy"):
        r = c.get(path, follow_redirects=False)
        assert r.status_code == 308 and r.headers["location"] == "/app/"


def test_legacy_stream_accepts_same_origin_session_cookie(c):
    _, sid = _login(c)
    with c.websocket_connect("/ws/dashboard", headers={"cookie": f"{COOKIE_NAME}={sid}",
                                                       "origin": "https://testserver"}) as ws:
        assert ws.receive_json()["type"] == "auth_ok"


def test_legacy_stream_rejects_cross_origin_cookie(c):
    _, sid = _login(c)
    with c.websocket_connect("/ws/dashboard", headers={"cookie": f"{COOKIE_NAME}={sid}",
                                                       "origin": "https://evil.example"}) as ws:
        with pytest.raises(WebSocketDisconnect) as ei:
            ws.receive_text()  # falls back to first-message auth -> none sent -> 1008
        assert ei.value.code == 1008
