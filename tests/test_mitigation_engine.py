# -*- coding: utf-8 -*-
"""
Tests for Layer 0 Mitigation Engine & Endpoints Wiring:
- PendingActionManager persistence and lifecycle
- CLI (list, show, approve, reject, log)
- API endpoints (/actions/pending, /actions/approve/{id}, /actions/reject/{id})
- Credential tiering (DDOS_ADMIN_KEYS vs DDOS_API_KEYS)
- Zero-divergence between API and CLI
"""
import os
import sys
import json
import pytest
from unittest.mock import MagicMock
from fastapi.testclient import TestClient

# Ensure repo root is on sys.path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from src.mitigation.manager import PendingActionManager
from src.mitigation import cli
import src.api.scoring_service as api_module
from src.api.scoring_service import app


@pytest.fixture
def temp_manager(tmp_path):
    """Provide an isolated PendingActionManager using a temporary file."""
    storage_file = str(tmp_path / "test_pending_actions.json")
    mgr = PendingActionManager(storage_file)
    mgr.clear()
    return mgr


@pytest.fixture
def client_with_keys(tmp_path, monkeypatch):
    """Provide a TestClient with configured API and Admin keys, using an isolated manager storage."""
    storage_file = str(tmp_path / "api_pending_actions.json")
    monkeypatch.setenv("DDOS_PENDING_ACTIONS_PATH", storage_file)
    monkeypatch.setenv("DDOS_API_KEYS", "scoring-key-123")
    monkeypatch.setenv("DDOS_ADMIN_KEYS", "admin-key-999")

    # Re-initialize keys in api_module
    api_module.API_KEYS = {"scoring-key-123"}
    api_module.ADMIN_KEYS = {"admin-key-999"}

    # Point manager singleton to this isolated path
    mgr = PendingActionManager.get_instance(storage_file)
    mgr.clear()

    # Create test client
    with TestClient(app) as test_client:
        yield test_client, mgr, storage_file


class TestPendingActionManager:
    """Unit tests for PendingActionManager."""

    def test_propose_persists_to_disk(self, temp_manager):
        aid = temp_manager.propose(
            action_type="BLOCK_ATTACKER",
            attacker_ip="192.168.1.50",
            victim_ip="10.0.0.1",
            reason="SYN Flood detected",
            confidence=0.98,
            commands=["iptables -I INPUT -s 192.168.1.50 -j DROP"],
            source="test_runner",
        )
        assert aid is not None
        assert os.path.exists(temp_manager.storage_path)

        # Check disk contents
        with open(temp_manager.storage_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert len(data["action_log"]) == 1
            action = data["action_log"][0]
            assert action["action_id"] == aid
            assert action["status"] == "PENDING"
            assert action["auto_execute"] is False
            assert action["attacker_ip"] == "192.168.1.50"

    def test_approve_lifecycle(self, temp_manager):
        aid = temp_manager.propose(
            action_type="BLOCK_ATTACKER",
            attacker_ip="192.168.1.60",
            victim_ip="10.0.0.2",
            reason="UDP Flood",
            commands=["iptables -I INPUT -s 192.168.1.60 -j DROP"],
        )

        success, msg, action = temp_manager.approve(aid, approver="alice_admin")
        assert success is True
        assert action["status"] == "EXECUTED"
        assert action["approver"] == "alice_admin"
        assert action["approved_at"] is not None

        # Verify disk reflects EXECUTED state
        reloaded = temp_manager.get_action(aid)
        assert reloaded["status"] == "EXECUTED"
        assert aid not in temp_manager.get_pending()

    def test_reject_lifecycle(self, temp_manager):
        aid = temp_manager.propose(
            action_type="DOCKER_BLOCK",
            attacker_ip="192.168.1.70",
            victim_ip="10.0.0.3",
            reason="Probe scan",
        )

        success, msg, action = temp_manager.reject(aid, reason="False alarm", rejecter="bob_admin")
        assert success is True
        assert action["status"] == "REJECTED"
        assert action["rejecter"] == "bob_admin"
        assert action["rejection_reason"] == "False alarm"
        assert action["rejected_at"] is not None

        reloaded = temp_manager.get_action(aid)
        assert reloaded["status"] == "REJECTED"
        assert aid not in temp_manager.get_pending()

    def test_double_approve_fails(self, temp_manager):
        aid = temp_manager.propose(
            action_type="BLOCK_ATTACKER",
            attacker_ip="192.168.1.80",
            victim_ip="10.0.0.1",
            reason="Test",
        )
        s1, _, _ = temp_manager.approve(aid)
        assert s1 is True
        s2, msg, _ = temp_manager.approve(aid)
        assert s2 is False
        assert "already EXECUTED" in msg

    def test_reject_after_approve_fails(self, temp_manager):
        aid = temp_manager.propose(
            action_type="BLOCK_ATTACKER",
            attacker_ip="192.168.1.90",
            victim_ip="10.0.0.1",
            reason="Test",
        )
        temp_manager.approve(aid)
        s, msg, _ = temp_manager.reject(aid)
        assert s is False
        assert "already EXECUTED" in msg


class TestMitigationAPIEndpoints:
    """Tests for FastAPI endpoints and credential tiering."""

    def test_pending_endpoint_requires_auth(self, client_with_keys):
        client, mgr, _ = client_with_keys
        # No header
        resp = client.get("/actions/pending")
        assert resp.status_code == 401

        # Invalid key
        resp = client.get("/actions/pending", headers={"X-API-Key": "invalid-key"})
        assert resp.status_code == 401

    def test_pending_endpoint_accepts_scoring_or_admin_key(self, client_with_keys):
        client, mgr, _ = client_with_keys
        aid = mgr.propose("BLOCK", "10.0.0.5", "10.0.0.1", "Flood")

        # Accessible with scoring key
        resp1 = client.get("/actions/pending", headers={"X-API-Key": "scoring-key-123"})
        assert resp1.status_code == 200
        assert resp1.json()["count"] == 1
        assert resp1.json()["pending_actions"][0]["action_id"] == aid

        # Accessible with admin key
        resp2 = client.get("/actions/pending", headers={"X-Admin-Key": "admin-key-999"})
        assert resp2.status_code == 200
        assert resp2.json()["count"] == 1

    def test_approve_endpoint_rejects_scoring_key_with_403(self, client_with_keys):
        """CRITICAL: A scoring API key must NOT be able to approve/execute mitigations."""
        client, mgr, _ = client_with_keys
        aid = mgr.propose("BLOCK", "10.0.0.6", "10.0.0.1", "Flood")

        # Attempt approval using standard scoring key
        resp = client.post(f"/actions/approve/{aid}", headers={"X-API-Key": "scoring-key-123"})
        assert resp.status_code == 403
        assert "Insufficient privileges" in resp.json()["detail"]

        # Verify action remained PENDING and was not executed
        action = mgr.get_action(aid)
        assert action["status"] == "PENDING"

    def test_reject_endpoint_rejects_scoring_key_with_403(self, client_with_keys):
        """CRITICAL: A scoring API key must NOT be able to reject mitigations."""
        client, mgr, _ = client_with_keys
        aid = mgr.propose("BLOCK", "10.0.0.7", "10.0.0.1", "Flood")

        resp = client.post(f"/actions/reject/{aid}", headers={"X-API-Key": "scoring-key-123"})
        assert resp.status_code == 403
        assert "Insufficient privileges" in resp.json()["detail"]

        action = mgr.get_action(aid)
        assert action["status"] == "PENDING"

    def test_approve_endpoint_succeeds_with_admin_key(self, client_with_keys):
        client, mgr, _ = client_with_keys
        aid = mgr.propose("BLOCK", "10.0.0.8", "10.0.0.1", "Flood")

        resp = client.post(f"/actions/approve/{aid}", headers={"X-Admin-Key": "admin-key-999"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "executed"
        assert data["action_id"] == aid
        assert data["action"]["status"] == "EXECUTED"

        # Action is no longer in pending list
        action = mgr.get_action(aid)
        assert action["status"] == "EXECUTED"

    def test_reject_endpoint_succeeds_with_admin_key(self, client_with_keys):
        client, mgr, _ = client_with_keys
        aid = mgr.propose("BLOCK", "10.0.0.9", "10.0.0.1", "Flood")

        resp = client.post(
            f"/actions/reject/{aid}",
            headers={"X-Admin-Key": "admin-key-999"},
            json={"reason": "Operator verified harmless test traffic"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "rejected"
        assert data["action"]["status"] == "REJECTED"
        assert data["action"]["rejection_reason"] == "Operator verified harmless test traffic"

    def test_approve_nonexistent_returns_404(self, client_with_keys):
        client, _, _ = client_with_keys
        resp = client.post("/actions/approve/nonexistent-id", headers={"X-Admin-Key": "admin-key-999"})
        assert resp.status_code == 404

    def test_approve_already_executed_returns_400(self, client_with_keys):
        client, mgr, _ = client_with_keys
        aid = mgr.propose("BLOCK", "10.0.0.10", "10.0.0.1", "Flood")
        client.post(f"/actions/approve/{aid}", headers={"X-Admin-Key": "admin-key-999"})

        # Try to approve again
        resp = client.post(f"/actions/approve/{aid}", headers={"X-Admin-Key": "admin-key-999"})
        assert resp.status_code == 400


class TestMitigationCLIAndZeroDivergence:
    """Tests for CLI commands and zero-divergence with the API."""

    def test_cli_list_and_show(self, tmp_path, capsys):
        storage_file = str(tmp_path / "cli_pending.json")
        mgr = PendingActionManager.get_instance(storage_file)
        mgr.clear()

        aid = mgr.propose("BLOCK_ATTACKER", "192.168.1.111", "10.0.0.1", "ICMP Flood", confidence=0.99)

        # CLI list
        ret = cli.main(["--config", storage_file, "list"])
        assert ret == 0
        captured = capsys.readouterr().out
        assert aid in captured
        assert "192.168.1.111" in captured

        # CLI show
        ret2 = cli.main(["--config", storage_file, "show", aid])
        assert ret2 == 0
        captured2 = capsys.readouterr().out
        assert "ICMP Flood" in captured2
        assert "PENDING" in captured2

    def test_cli_approve(self, tmp_path):
        storage_file = str(tmp_path / "cli_approve.json")
        mgr = PendingActionManager.get_instance(storage_file)
        mgr.clear()

        aid = mgr.propose("BLOCK_ATTACKER", "192.168.1.112", "10.0.0.1", "Attack")
        ret = cli.main(["--config", storage_file, "approve", aid])
        assert ret == 0

        action = mgr.get_action(aid)
        assert action["status"] == "EXECUTED"

    def test_cli_reject(self, tmp_path):
        storage_file = str(tmp_path / "cli_reject.json")
        mgr = PendingActionManager.get_instance(storage_file)
        mgr.clear()

        aid = mgr.propose("BLOCK_ATTACKER", "192.168.1.113", "10.0.0.1", "Attack")
        ret = cli.main(["--config", storage_file, "reject", aid, "--reason", "Not malicious"])
        assert ret == 0

        action = mgr.get_action(aid)
        assert action["status"] == "REJECTED"
        assert action["rejection_reason"] == "Not malicious"

    def test_zero_divergence_between_api_and_cli(self, client_with_keys, capsys):
        """Action proposed via manager is approved via CLI, and API immediately sees the change."""
        client, mgr, storage_file = client_with_keys

        # 1. Propose action
        aid = mgr.propose("BLOCK_ATTACKER", "192.168.1.200", "10.0.0.4", "Zero Divergence Test")

        # 2. Check API sees it in pending
        resp = client.get("/actions/pending", headers={"X-API-Key": "scoring-key-123"})
        assert any(a["action_id"] == aid for a in resp.json()["pending_actions"])

        # 3. Approve via CLI using the same storage file
        ret = cli.main(["--config", storage_file, "--user", "secops_cli", "approve", aid])
        assert ret == 0

        # 4. Check API immediately sees it is NO LONGER pending
        resp_after = client.get("/actions/pending", headers={"X-API-Key": "scoring-key-123"})
        assert not any(a["action_id"] == aid for a in resp_after.json()["pending_actions"])

        # 5. Check API approve endpoint returns 400 because CLI already executed it
        resp_double = client.post(f"/actions/approve/{aid}", headers={"X-Admin-Key": "admin-key-999"})
        assert resp_double.status_code == 400
        assert "already EXECUTED" in resp_double.json()["detail"]
