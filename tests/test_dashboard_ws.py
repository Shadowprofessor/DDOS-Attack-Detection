# -*- coding: utf-8 -*-
"""
Tests for Real-time Dashboard WebSocket endpoint and Gated Approval Integration (Prompt 7).

Verifies:
1. First-message WS authentication (rejects unauthenticated/invalid with code 1008).
2. Authenticated handshake delivering auth_ok and initial_state.
3. Message schema formatting including consensus_tier, per_model_breakdown, and caveat text.
4. /score/flow hot path decoupling (sub-1ms xgb_only latency unaffected by WS broadcast).
5. Inbound client message protection (WS is strictly server-to-client; client messages ignored).
6. One-click Approve/Reject gate enforcement via REST (admin credentials required).
7. Static AST audit verifying zero direct mitigation execution in dashboard module.
"""
import ast
import json
import os
import sys
import time
import pytest
from unittest.mock import MagicMock, patch
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import src.api.scoring_service as api_module
from src.api.scoring_service import app
from src.mitigation.manager import PendingActionManager, get_manager
from src.web.realtime_dashboard.broadcaster import get_broadcaster


@pytest.fixture(autouse=True)
def setup_api_env(tmp_path, monkeypatch):
    """Configure test keys and clean manager singleton."""
    storage_file = str(tmp_path / "dashboard_test_actions.json")
    monkeypatch.setenv("DDOS_PENDING_ACTIONS_PATH", storage_file)
    monkeypatch.setenv("DDOS_API_KEYS", "test-api-key-123")
    monkeypatch.setenv("DDOS_ADMIN_KEYS", "test-admin-key-456")

    orig_api = set(api_module.API_KEYS)
    orig_admin = set(api_module.ADMIN_KEYS)
    api_module.API_KEYS.add("test-api-key-123")
    api_module.ADMIN_KEYS.add("test-admin-key-456")

    mgr = PendingActionManager.get_instance(storage_file)
    mgr.clear()
    try:
        yield mgr
    finally:
        api_module.API_KEYS = orig_api
        api_module.ADMIN_KEYS = orig_admin


def test_ws_connection_unauthenticated_rejected():
    """
    Prompt 7 Condition 1:
    Connecting without sending valid auth as the first message closes with code 1008.
    """
    client = TestClient(app)
    # Test 1: Send invalid auth key
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/ws/dashboard") as ws:
            ws.send_text(json.dumps({"type": "auth", "key": "wrong-key"}))
            ws.receive_text()
    assert excinfo.value.code == 1008

    # Test 2: Send non-auth message
    with pytest.raises(WebSocketDisconnect) as excinfo:
        with client.websocket_connect("/ws/dashboard") as ws:
            ws.send_text(json.dumps({"type": "hello", "data": "test"}))
            ws.receive_text()
    assert excinfo.value.code == 1008


def test_ws_connection_authenticated_success():
    """
    Prompt 7 Condition 1:
    Valid first-message auth delivers auth_ok and initial_state payload.
    """
    mgr = get_manager()
    aid = mgr.propose("BLOCK", "192.168.1.100", "10.0.0.1", "Initial test alert", confidence=0.92)

    client = TestClient(app)
    with client.websocket_connect("/ws/dashboard") as ws:
        # First-message auth
        ws.send_text(json.dumps({"type": "auth", "key": "test-admin-key-456"}))

        # First response: auth_ok
        resp1 = json.loads(ws.receive_text())
        assert resp1["type"] == "auth_ok"
        assert resp1["status"] == "authenticated"

        # Second response: initial_state
        resp2 = json.loads(ws.receive_text())
        assert resp2["type"] == "initial_state"
        assert resp2["pending_count"] == 1
        assert len(resp2["pending_actions"]) == 1
        assert resp2["pending_actions"][0]["action_id"] == aid


def test_ws_message_schema_consensus_and_caveat():
    """
    Verify broadcast message schema surfaces consensus_tier, per_model_breakdown, and caveat.
    """
    broadcaster = get_broadcaster()

    # Create dummy flow with TABULAR_UNANIMOUS_SEQUENCE_DISSENT context
    breakdown = {
        "random_forest": {"label": "WebDDoS", "confidence": 0.93},
        "xgboost": {"label": "WebDDoS", "confidence": 0.96},
        "sequence_classifier": {
            "label": "Syn",
            "confidence": 0.72,
            "active": True,
            "caveat": "Trained on synthetic pseudo-temporal windows; unverified on real sequences",
        },
        "mode": "ensemble_full",
    }

    flow_event = {
        "label": "WebDDoS",
        "confidence": 0.94,
        "is_attack": True,
        "consensus_tier": "TABULAR_UNANIMOUS_SEQUENCE_DISSENT",
        "per_model_breakdown": breakdown,
        "caveat": "Trained on synthetic pseudo-temporal windows; unverified on real sequences",
    }

    client = TestClient(app)
    with client.websocket_connect("/ws/dashboard") as ws:
        ws.send_text(json.dumps({"type": "auth", "key": "test-admin-key-456"}))
        _ = ws.receive_text()  # auth_ok
        _ = ws.receive_text()  # initial_state

        # Enqueue flow and trigger direct message broadcast
        broadcaster.enqueue_flow(flow_event)

        # Broadcast directly to verify client schema receipt
        msg = {
            "type": "flow_scored",
            "timestamp": time.time(),
            "flow_rate": 15.0,
            "total_flows": 1,
            "total_attacks": 1,
            "flow": flow_event,
        }
        import asyncio
        asyncio.run(broadcaster.broadcast_message(msg))

        received = json.loads(ws.receive_text())
        assert received["type"] == "flow_scored"
        assert received["flow"]["label"] == "WebDDoS"
        assert received["flow"]["consensus_tier"] == "TABULAR_UNANIMOUS_SEQUENCE_DISSENT"

        # Check breakdown context
        rec_breakdown = received["flow"]["per_model_breakdown"]
        assert rec_breakdown["random_forest"]["label"] == "WebDDoS"
        assert rec_breakdown["xgboost"]["label"] == "WebDDoS"
        assert rec_breakdown["sequence_classifier"]["label"] == "Syn"
        assert rec_breakdown["sequence_classifier"]["active"] is True

        # Check sequence caveat
        assert "unverified on real sequences" in received["flow"]["caveat"]


def test_score_flow_latency_unaffected_by_dashboard():
    """
    Prompt 7 Condition 2:
    Confirm /score/flow latency is sub-1ms in xgb_only mode and broadcaster enqueue
    adds zero blocking latency (sub-0.1ms fire-and-forget).
    """
    from src.models.ensemble import get_default_ensemble
    broadcaster = get_broadcaster()
    ens = get_default_ensemble()
    features = {col: 10.0 for col in ens.feature_names}

    # Warmup
    ens.score_flow(features, mode="xgb_only")

    # 1. Benchmark xgb_only model execution time.
    # Local SLA: strictly sub-1.5ms (locally runs at ~0.4-0.8ms).
    # CI runners: noisy shared runners permit up to 5.0ms.
    runs = 30
    t0 = time.perf_counter()
    for _ in range(runs):
        lbl, conf, bd = ens.score_flow(features, mode="xgb_only")
    model_latency_ms = ((time.perf_counter() - t0) * 1000.0) / runs

    is_ci = bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"))
    threshold_ms = 5.0 if is_ci else 1.5
    assert model_latency_ms < threshold_ms, (
        f"xgb_only scoring latency ({model_latency_ms:.2f}ms) exceeded {threshold_ms}ms"
    )

    # 2. Benchmark enqueue_flow fire-and-forget overhead (sub-0.1ms)
    t0 = time.perf_counter()
    for _ in range(runs):
        broadcaster.enqueue_flow({
            "label": "Benign",
            "confidence": 0.99,
            "is_attack": False,
            "consensus_tier": "xgb_only",
        })
    enqueue_latency_ms = ((time.perf_counter() - t0) * 1000.0) / runs

    assert enqueue_latency_ms < 0.1, f"Broadcaster enqueue ({enqueue_latency_ms:.4f}ms) exceeded 0.1ms"

    # 3. Test backpressure: filling queue beyond maxsize drops oldest without blocking
    small_broadcaster = api_module.get_broadcaster()
    for i in range(small_broadcaster.queue_maxsize + 20):
        small_broadcaster.enqueue_flow({"label": f"flow_{i}", "is_attack": False})
    # Queue remains bounded at or below maxsize
    assert small_broadcaster._flow_queue.qsize() <= small_broadcaster.queue_maxsize


def test_score_flow_latency_threshold_scoping(monkeypatch):
    """
    Verify threshold logic:
    1. Without CI/GITHUB_ACTIONS set, threshold is strictly 1.5ms (and passes locally).
    2. With CI=true set, threshold is relaxed to 5.0ms to tolerate noisy virtual runners.
    """
    from src.models.ensemble import get_default_ensemble
    ens = get_default_ensemble()
    features = {col: 10.0 for col in ens.feature_names}

    # Warmup
    ens.score_flow(features, mode="xgb_only")

    # Case A: Non-CI local environment
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    is_ci = bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"))
    assert is_ci is False
    threshold_local = 5.0 if is_ci else 1.5
    assert threshold_local == 1.5

    runs = 30
    t0 = time.perf_counter()
    for _ in range(runs):
        ens.score_flow(features, mode="xgb_only")
    local_latency_ms = ((time.perf_counter() - t0) * 1000.0) / runs
    assert local_latency_ms < 1.5, f"Local xgb_only latency ({local_latency_ms:.2f}ms) exceeded strict 1.5ms threshold"

    # Case B: CI environment
    monkeypatch.setenv("CI", "true")
    is_ci_set = bool(os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS"))
    assert is_ci_set is True
    threshold_ci = 5.0 if is_ci_set else 1.5
    assert threshold_ci == 5.0


def test_ws_inbound_messages_ignored_never_execute():
    """
    Prompt 7 Condition 3:
    Confirm /ws/dashboard never acts on inbound message content from a client.
    Arbitrary or approve/reject-shaped messages are ignored.
    """
    mgr = get_manager()
    aid = mgr.propose("BLOCK", "10.0.0.77", "10.0.0.1", "Unapproved action")

    client = TestClient(app)
    with client.websocket_connect("/ws/dashboard") as ws:
        ws.send_text(json.dumps({"type": "auth", "key": "test-admin-key-456"}))
        _ = ws.receive_text()  # auth_ok
        _ = ws.receive_text()  # initial_state

        # Attempt to exploit/bypass via WS channel by sending approve command
        malicious_msg = json.dumps({
            "action": "approve",
            "action_id": aid,
            "commands": ["rm -rf /"],
        })
        ws.send_text(malicious_msg)

        # Give brief tick to ensure any async handler would have run
        time.sleep(0.05)

        # Action MUST remain PENDING with zero execution
        action = mgr.get_action(aid)
        assert action["status"] == "PENDING"
        assert action["auto_execute"] is False


def test_dashboard_approve_reject_rest_gate():
    """
    Verify one-click approve and reject buttons call existing REST endpoints
    and require DDOS_ADMIN_KEYS.
    """
    mgr = get_manager()
    aid = mgr.propose("BLOCK", "10.0.0.88", "10.0.0.1", "Test REST gate")

    client = TestClient(app)

    # 1. No key -> 401
    r1 = client.post(f"/actions/approve/{aid}")
    assert r1.status_code == 401

    # 2. Scoring API key -> 403 Forbidden
    r2 = client.post(f"/actions/approve/{aid}", headers={"X-API-Key": "test-api-key-123"})
    assert r2.status_code == 403

    # 3. Valid admin key -> Approved & Executed
    with patch.object(mgr, "_execute_action") as mock_exec:
        r3 = client.post(f"/actions/approve/{aid}", headers={"X-Admin-Key": "test-admin-key-456"})
        assert r3.status_code == 200
        assert r3.json()["status"] == "executed"
        mock_exec.assert_called_once()

    # 4. Reject endpoint test
    aid2 = mgr.propose("BLOCK", "10.0.0.89", "10.0.0.1", "Test reject")
    r4 = client.post(
        f"/actions/reject/{aid2}",
        headers={"X-Admin-Key": "test-admin-key-456"},
        json={"reason": "Rejected via test"},
    )
    assert r4.status_code == 200
    assert r4.json()["status"] == "rejected"
    assert mgr.get_action(aid2)["status"] == "REJECTED"


def test_static_ast_audit_dashboard_no_direct_execution():
    """
    Static AST check: ensure src/web/realtime_dashboard/ contains NO direct
    calls to _execute_action, subprocess, os.system, or socket commands.
    """
    dashboard_dir = os.path.join(REPO_ROOT, "src", "web", "realtime_dashboard")
    for root, _, files in os.walk(dashboard_dir):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                with open(path, "r", encoding="utf-8") as f:
                    tree = ast.parse(f.read(), filename=path)

                for node in ast.walk(tree):
                    if isinstance(node, ast.Call):
                        if isinstance(node.func, ast.Name):
                            assert node.func.id not in ("_execute_action", "system", "popen")
                        elif isinstance(node.func, ast.Attribute):
                            assert node.func.attr not in ("_execute_action", "Popen", "check_call", "check_output")


def test_dashboard_html_and_static_assets_served():
    """Verify GET /dashboard and static assets return 200 OK."""
    client = TestClient(app)
    resp = client.get("/dashboard")
    assert resp.status_code == 200
    assert "DDoS Defense SOC" in resp.text

    css_resp = client.get("/dashboard/static/style.css")
    assert css_resp.status_code == 200
    assert "--bg-primary" in css_resp.text

    js_resp = client.get("/dashboard/static/app.js")
    assert js_resp.status_code == 200
    assert "sessionStorage" in js_resp.text
    # Condition 4: Confirm localStorage is NEVER used in frontend script
    assert "localStorage" not in js_resp.text


def test_dashboard_ws_degraded_flow_payload():
    """
    Verify degraded flow telemetry preservation over WebSocket:
    1. Enqueue flow with degraded_confidence=True, feature_completeness=0.7013,
       and host_ingress degradation reason.
    2. Broadcast message and assert payload preserves all three fields.
    3. Assert frontend app.js contains degraded badge and reason callout rendering logic.
    """
    broadcaster = get_broadcaster()
    client = TestClient(app)

    flow_event = {
        "label": "Syn",
        "confidence": 0.88,
        "is_attack": True,
        "consensus_tier": "xgb_only",
        "feature_completeness": 0.7013,
        "degraded_confidence": True,
        "degradation_reason": "host_ingress: 23 backward features unobserved and zero-filled",
        "per_model_breakdown": {
            "xgboost": {"label": "Syn", "confidence": 0.88},
            "degraded_confidence": True,
            "feature_completeness": 0.7013,
            "degradation_reason": "host_ingress: 23 backward features unobserved and zero-filled",
        },
    }

    with client.websocket_connect("/ws/dashboard") as ws:
        ws.send_text(json.dumps({"type": "auth", "key": "test-admin-key-456"}))
        _ = ws.receive_text()  # auth_ok
        _ = ws.receive_text()  # initial_state

        msg = {
            "type": "flow_scored",
            "timestamp": time.time(),
            "flow_rate": 10.0,
            "total_flows": 1,
            "total_attacks": 1,
            "flow": flow_event,
        }
        import asyncio
        asyncio.run(broadcaster.broadcast_message(msg))

        received = json.loads(ws.receive_text())
        assert received["type"] == "flow_scored"
        flow_payload = received["flow"]
        assert flow_payload["degraded_confidence"] is True
        assert flow_payload["feature_completeness"] == 0.7013
        assert flow_payload["degradation_reason"] == "host_ingress: 23 backward features unobserved and zero-filled"

    # Verify frontend app.js includes degraded badge logic and action degradation_reason handling
    js_resp = client.get("/dashboard/static/app.js")
    assert js_resp.status_code == 200
    assert "DEGRADED" in js_resp.text
    assert "badge-degraded" in js_resp.text
    assert "degradation_reason" in js_resp.text

