# -*- coding: utf-8 -*-
"""v4.2.0 IR API: RBAC matrix, validation, export/CERT-In/replay/rollback endpoints, /ws/incidents."""
import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import src.api.scoring_service as api_module
from src.api.scoring_service import app
from src.ir.runtime import IRRuntime, set_ir_runtime
from src.mitigation.manager import PendingActionManager

ANALYST = {"X-API-Key": "ir-analyst-key"}
ADMIN = {"X-Admin-Key": "ir-admin-key"}
AGG = {"incident_id": "agg-api", "window_start": 1.0, "pps": 250000.0,
       "top_src_ips": [{"key": "10.10.0.21", "share": 0.1}], "dst_ips": ["10.0.0.4"],
       "protocol_mix": {"tcp": 0.98}, "tcp_flag_ratios": {"syn": 0.93}}


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DDOS_IR_SCHEDULER", "off")
    storage = str(tmp_path / "actions.json")
    monkeypatch.setenv("DDOS_PENDING_ACTIONS_PATH", storage)
    orig_api, orig_admin = set(api_module.API_KEYS), set(api_module.ADMIN_KEYS)
    api_module.API_KEYS.add("ir-analyst-key")
    api_module.ADMIN_KEYS.add("ir-admin-key")
    mgr = PendingActionManager.get_instance(storage)
    mgr.clear()
    rt = IRRuntime({}, database_url=f"sqlite:///{(tmp_path / 'ir.db').as_posix()}", manager_factory=lambda: mgr)
    set_ir_runtime(rt)
    try:
        with TestClient(app) as client:
            yield client, rt, mgr
    finally:
        set_ir_runtime(None)
        api_module.API_KEYS, api_module.ADMIN_KEYS = orig_api, orig_admin


def _create(client, severity=5):
    r = client.post("/api/incidents", headers=ANALYST,
                    json={"title": "SYN flood", "severity": severity, "aggregate": AGG})
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _linked_executed_action(client, rt, mgr, iid):
    aid = mgr.propose("BLOCK", "10.10.0.21", "10.0.0.4", "t")
    assert client.post(f"/api/incidents/{iid}/actions", headers=ANALYST, json={"action_id": aid}).status_code == 201
    mgr.approve(aid, approver="test_admin")
    rt.rollback.tick()
    return aid


class TestRBACMatrix:
    """Every endpoint x {no key, bad key, analyst, admin} -> expected status."""

    def test_matrix(self, env):
        client, rt, mgr = env
        iid = _create(client)
        aid = _linked_executed_action(client, rt, mgr, iid)
        aid2 = mgr.propose("BLOCK", "10.10.0.22", "10.0.0.4", "t")
        cases = [
            # method, path, body, analyst_expected, admin_expected
            ("GET", "/api/incidents", None, 200, 200),
            ("POST", "/api/incidents", {"title": "x flood", "severity": 2}, 201, 201),
            ("GET", f"/api/incidents/{iid}", None, 200, 200),
            ("POST", f"/api/incidents/{iid}/notes", {"text": "hi"}, 201, 201),
            ("POST", f"/api/incidents/{iid}/transition", {"to": "triage"}, 200, 409),
            ("POST", f"/api/incidents/{iid}/actions", {"action_id": aid2}, 201, 201),
            ("POST", f"/api/incidents/{iid}/playbook/syn_flood/step/confirm_syn_ratio", {}, 200, 200),
            ("POST", f"/api/incidents/{iid}/playbook/syn_flood/step/record_root_cause", {}, 403, 200),
            ("GET", f"/api/incidents/{iid}/export?format=md", None, 200, 200),
            ("GET", f"/api/incidents/{iid}/export?format=pdf", None, 200, 200),
            ("GET", f"/api/incidents/{iid}/cert-in/draft", None, 403, 200),
            ("POST", f"/api/incidents/{iid}/cert-in/reported", {"reference": "ACK-1"}, 403, 200),
            ("GET", "/api/playbooks", None, 200, 200),
            ("GET", "/api/replay/scenarios", None, 200, 200),
            ("POST", "/api/replay", {"scenario": "syn_flood", "speed": 10000}, 201, 201),
            ("GET", f"/api/actions/{aid}/rollback", None, 200, 200),
            ("POST", f"/api/actions/{aid}/extend", {"reason": "still ongoing", "seconds": 60}, 403, 200),
            # last: closes the incident (analyst may not; admin may, from triage)
            ("POST", f"/api/incidents/{iid}/transition", {"to": "false_positive"}, 403, 200),
        ]
        for method, path, body, exp_analyst, exp_admin in cases:
            kw = {"json": body} if body is not None else {}
            assert client.request(method, path, **kw).status_code == 401, (method, path, "no key")
            assert client.request(method, path, headers={"X-API-Key": "nope"}, **kw).status_code == 401, path
            ra = client.request(method, path, headers=ANALYST, **kw)
            assert ra.status_code == exp_analyst, (method, path, "analyst", ra.text)
            rd = client.request(method, path, headers=ADMIN, **kw)
            assert rd.status_code == exp_admin, (method, path, "admin", rd.text)


class TestValidationAndErrors:
    @pytest.mark.parametrize("body", [
        {"title": "x", "severity": 3},
        {"title": "valid title", "severity": 9},
        {"title": "valid title", "severity": 3, "evil_extra": 1},
        {"title": "valid title", "severity": 3, "aggregate": {"incident_id": "bad id!", "window_start": 1}},
    ])
    def test_invalid_create_is_422_without_trace(self, env, body):
        client, _, _ = env
        r = client.post("/api/incidents", headers=ANALYST, json=body)
        assert r.status_code == 422
        assert "Traceback" not in r.text and 'File "' not in r.text

    def test_bad_path_id_422_and_unknown_404(self, env):
        client, _, _ = env
        assert client.get("/api/incidents/bad%20id!", headers=ANALYST).status_code == 422
        r = client.get("/api/incidents/INC-20000101-0000", headers=ANALYST)
        assert r.status_code == 404 and "not found" in r.json()["detail"]

    def test_illegal_transition_409_and_contain_needs_justification(self, env):
        client, _, _ = env
        iid = _create(client)
        assert client.post(f"/api/incidents/{iid}/transition", headers=ADMIN, json={"to": "closed"}).status_code == 409
        for to in ("triage", "investigating"):
            assert client.post(f"/api/incidents/{iid}/transition", headers=ANALYST, json={"to": to}).status_code == 200
        assert client.post(f"/api/incidents/{iid}/transition", headers=ADMIN, json={"to": "contained"}).status_code == 400
        r = client.post(f"/api/incidents/{iid}/transition", headers=ADMIN,
                        json={"to": "contained", "justification": "upstream provider null-routed the source"})
        assert r.status_code == 200 and r.json()["status"] == "contained"

    def test_replay_needs_exactly_one_source(self, env):
        client, _, _ = env
        assert client.post("/api/replay", headers=ANALYST, json={}).status_code == 422
        assert client.post("/api/replay", headers=ANALYST,
                           json={"scenario": "syn_flood", "aggregate": AGG}).status_code == 422
        assert client.post("/api/replay", headers=ANALYST, json={"scenario": "nope"}).status_code == 404

    def test_replay_endpoint_proposes_nothing_real(self, env):
        client, _, mgr = env
        r = client.post("/api/replay", headers=ANALYST, json={"scenario": "syn_flood", "speed": 10000})
        assert r.status_code == 201 and r.json()["incident"]["is_replay"] is True
        assert mgr.get_action_log() == []

    def test_playbook_step_proposes_pending_only_and_approval_still_needs_admin(self, env):
        client, _, mgr = env
        iid = _create(client)
        r = client.post(f"/api/incidents/{iid}/playbook/syn_flood/step/rate_limit_top_source", headers=ANALYST, json={})
        aid = r.json()["result"]["action_id"]
        assert mgr.get_action(aid)["status"] == "PENDING"
        assert client.post(f"/actions/approve/{aid}", headers=ANALYST).status_code == 403
        assert mgr.get_action(aid)["status"] == "PENDING"

    def test_export_headers_and_actor_has_no_key_material(self, env):
        client, _, _ = env
        iid = _create(client)
        r = client.get(f"/api/incidents/{iid}/export?format=pdf", headers=ANALYST)
        assert r.headers["content-type"] == "application/pdf" and r.content.startswith(b"%PDF")
        assert f'filename="{iid}.pdf"' in r.headers["content-disposition"]
        md = client.get(f"/api/incidents/{iid}/export", headers=ANALYST).text
        assert "ir-analyst-key"[:8] not in md and "analyst:" in md

    def test_cert_in_draft_409_below_threshold(self, env):
        client, _, _ = env
        iid = _create(client, severity=2)
        assert client.get(f"/api/incidents/{iid}/cert-in/draft", headers=ADMIN).status_code == 409

    def test_metrics_expose_ir_series(self, env):
        client, _, _ = env
        _create(client)
        body = client.get("/metrics").text
        for name in ("ddos_incidents{state=\"new\"}", "ddos_incident_mttd_seconds_bucket",
                     "ddos_incident_mttc_seconds_count", "ddos_rollbacks_total", "ddos_cert_in_seconds_remaining"):
            assert name in body, name


class TestIncidentsWebSocket:
    def test_rejects_unauthenticated(self, env):
        client, _, _ = env
        with client.websocket_connect("/ws/incidents") as ws:
            ws.send_text('{"type": "auth", "key": "wrong"}')
            with pytest.raises(WebSocketDisconnect) as ei:
                ws.receive_text()
            assert ei.value.code == 1008

    def test_authenticated_receives_events_and_inbound_is_ignored(self, env):
        client, rt, _ = env
        with client.websocket_connect("/ws/incidents") as ws:
            ws.send_text('{"type": "auth", "key": "ir-analyst-key"}')
            assert ws.receive_json() == {"type": "auth_ok", "role": "analyst"}
            ws.send_text('{"type": "transition", "to": "closed"}')  # must be ignored
            iid = _create(client)
            ev = ws.receive_json()
            assert ev["type"] == "incident.created" and ev["incident"]["id"] == iid
        assert rt.service.get(iid)["status"] == "new"
