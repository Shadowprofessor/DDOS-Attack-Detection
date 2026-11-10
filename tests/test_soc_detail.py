# -*- coding: utf-8 -*-
"""v4.3.1: session-based approve/reject (+CSRF), approvals feed, on-demand analysis, WS cookie auth."""
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import src.api.scoring_service as api_module
from src.api.scoring_service import app
from src.api.session_router import login_limiter
from src.ir.runtime import IRRuntime, set_ir_runtime
from src.mitigation.manager import PendingActionManager
from src.web.session import COOKIE_NAME, get_session_store

ANALYST_KEY = "detail-analyst-key"
ADMIN_KEY = "detail-admin-key-1"
AGG = {"incident_id": "agg-detail", "window_start": 1.0, "pps": 250000.0, "unique_src_ips": 900,
       "top_src_ips": [{"key": "10.10.0.21", "share": 0.1}], "dst_ips": ["10.0.0.4"],
       "protocol_mix": {"tcp": 0.98}, "tcp_flag_ratios": {"syn": 0.93},
       "ml": {"label": "Syn", "confidence": 0.97}}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DDOS_IR_SCHEDULER", "off")
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    storage = str(tmp_path / "actions.json")
    monkeypatch.setenv("DDOS_PENDING_ACTIONS_PATH", storage)
    orig_api, orig_admin = set(api_module.API_KEYS), set(api_module.ADMIN_KEYS)
    api_module.API_KEYS.add(ANALYST_KEY)
    api_module.ADMIN_KEYS.add(ADMIN_KEY)
    mgr = PendingActionManager.get_instance(storage)
    mgr.clear()
    rt = IRRuntime({}, database_url=f"sqlite:///{(tmp_path / 'ir.db').as_posix()}", manager_factory=lambda: mgr)
    set_ir_runtime(rt)
    get_session_store().clear()
    login_limiter.clear()
    try:
        with TestClient(app, base_url="https://testserver") as c:
            yield c, rt, mgr
    finally:
        set_ir_runtime(None)
        get_session_store().clear()
        api_module.API_KEYS, api_module.ADMIN_KEYS = orig_api, orig_admin


def _login(c, key):
    r = c.post("/api/session/login", json={"api_key": key})
    assert r.status_code == 200
    return r.json()["csrf_token"], r.cookies[COOKIE_NAME]


def _incident_with_pending(c, rt, mgr):
    iid = c.post("/api/incidents", headers={"X-API-Key": ANALYST_KEY},
                 json={"title": "SYN flood", "severity": 5, "aggregate": AGG}).json()["id"]
    r = c.post(f"/api/incidents/{iid}/playbook/syn_flood/step/rate_limit_top_source",
               headers={"X-API-Key": ANALYST_KEY}, json={})
    return iid, r.json()["result"]["action_id"]


class TestSessionApprovals:
    def test_admin_session_approves_with_csrf_only(self, env):
        c, rt, mgr = env
        _, aid = _incident_with_pending(c, rt, mgr)
        csrf, _ = _login(c, ADMIN_KEY)
        assert c.post(f"/actions/approve/{aid}").status_code == 403  # no CSRF
        assert mgr.get_action(aid)["status"] == "PENDING"
        r = c.post(f"/actions/approve/{aid}", headers={"X-CSRF-Token": csrf})
        assert r.status_code == 200 and mgr.get_action(aid)["status"] == "EXECUTED"

    def test_analyst_session_cannot_approve_or_reject(self, env):
        c, rt, mgr = env
        _, aid = _incident_with_pending(c, rt, mgr)
        csrf, _ = _login(c, ANALYST_KEY)
        assert c.post(f"/actions/approve/{aid}", headers={"X-CSRF-Token": csrf}).status_code == 403
        assert c.post(f"/actions/reject/{aid}", headers={"X-CSRF-Token": csrf}, json={"reason": "x"}).status_code == 403
        assert mgr.get_action(aid)["status"] == "PENDING"

    def test_admin_session_rejects(self, env):
        c, rt, mgr = env
        _, aid = _incident_with_pending(c, rt, mgr)
        csrf, _ = _login(c, ADMIN_KEY)
        r = c.post(f"/actions/reject/{aid}", headers={"X-CSRF-Token": csrf}, json={"reason": "false positive"})
        assert r.status_code == 200 and mgr.get_action(aid)["status"] == "REJECTED"

    def test_pending_list_via_session(self, env):
        c, rt, mgr = env
        _incident_with_pending(c, rt, mgr)
        _login(c, ANALYST_KEY)
        assert c.get("/actions/pending").json()["count"] == 1

    def test_no_credentials_still_401(self, env):
        c, rt, mgr = env
        _, aid = _incident_with_pending(c, rt, mgr)
        assert c.post(f"/actions/approve/{aid}").status_code == 401


class TestApprovalsFeed:
    def test_pending_then_active_with_countdown(self, env):
        c, rt, mgr = env
        iid, aid = _incident_with_pending(c, rt, mgr)
        csrf, _ = _login(c, ADMIN_KEY)
        feed = c.get("/api/approvals").json()
        p = feed["pending"][0]
        assert p["action_id"] == aid and p["incident_id"] == iid
        assert p["blast_radius"] == "low" and p["reversible"] is True and p["rollback_ttl_s"] == 600
        c.post(f"/actions/approve/{aid}", headers={"X-CSRF-Token": csrf})
        rt.rollback.tick()
        feed = c.get("/api/approvals").json()
        assert feed["pending"] == []
        act = feed["active"][0]
        assert act["action_id"] == aid and act["rollback_state"] == "scheduled"
        assert 0 < act["seconds_until_rollback"] <= 600

    def test_requires_auth(self, env):
        c, _, _ = env
        assert c.get("/api/approvals").status_code == 401


class TestAnalyze:
    def test_rule_fallback_stored_on_incident(self, env):
        c, rt, mgr = env
        iid, _ = _incident_with_pending(c, rt, mgr)
        r = c.post(f"/api/incidents/{iid}/analyze", headers={"X-API-Key": ANALYST_KEY})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["analysis"]["source"] == "rules"
        assert body["analysis"]["analysis"]["attack_type"] == "TCP SYN flood"
        assert any(e["kind"] == "analysis" for e in body["events"])
        assert body["severity"] == 5  # analyst never changes the human-set severity
        assert mgr.get_pending() and len(mgr.get_pending()) == 1  # nothing new proposed

    def test_no_aggregate_is_409(self, env):
        c, _, _ = env
        iid = c.post("/api/incidents", headers={"X-API-Key": ANALYST_KEY},
                     json={"title": "manual report", "severity": 2}).json()["id"]
        assert c.post(f"/api/incidents/{iid}/analyze", headers={"X-API-Key": ANALYST_KEY}).status_code == 409


class TestWsCookieAuth:
    def test_same_origin_cookie_accepted(self, env):
        c, _, _ = env
        _, sid = _login(c, ANALYST_KEY)
        with c.websocket_connect("/ws/incidents", headers={"cookie": f"{COOKIE_NAME}={sid}",
                                                           "origin": "https://testserver"}) as ws:
            assert ws.receive_json() == {"type": "auth_ok", "role": "analyst"}

    @pytest.mark.parametrize("origin", ["https://evil.example", None])
    def test_cross_or_missing_origin_rejected(self, env, origin):
        c, _, _ = env
        _, sid = _login(c, ANALYST_KEY)
        h = {"cookie": f"{COOKIE_NAME}={sid}"}
        if origin:
            h["origin"] = origin
        with c.websocket_connect("/ws/incidents", headers=h) as ws:
            with pytest.raises(WebSocketDisconnect) as ei:
                ws.receive_text()  # no first-message auth sent -> times out -> 1008
            assert ei.value.code == 1008
