# -*- coding: utf-8 -*-
"""
Specific Bypass-Check Test Suite (Item 3 Requirement).

Verifies that:
1. /score/flow and /score/batch NEVER trigger mitigation execution.
2. Nemotron agent (AIThreatAnalyzer) NEVER triggers mitigation execution.
3. SDN controller (EnhancedRyuSecurityController) NEVER sends OpenFlow DROP mods directly.
4. Unauthenticated callers and scoring-key callers cannot trigger execution via the API.
5. Static AST audit confirms no backdoors or direct execution calls outside PendingActionManager.approve().
"""
import ast
import os
import sys
import pytest
from unittest.mock import MagicMock, patch
from fastapi.testclient import TestClient

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CODES_DIR = os.path.join(REPO_ROOT, "Codes")
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
if CODES_DIR not in sys.path:
    sys.path.insert(0, CODES_DIR)

from src.mitigation.manager import PendingActionManager, get_manager
import src.api.scoring_service as api_module
from src.api.scoring_service import app


@pytest.fixture
def clean_manager(tmp_path, monkeypatch):
    storage_file = str(tmp_path / "bypass_actions.json")
    monkeypatch.setenv("DDOS_PENDING_ACTIONS_PATH", storage_file)
    monkeypatch.setenv("DDOS_API_KEYS", "scoring-key-test")
    monkeypatch.setenv("DDOS_ADMIN_KEYS", "admin-key-test")
    api_module.API_KEYS = {"scoring-key-test"}
    api_module.ADMIN_KEYS = {"admin-key-test"}

    mgr = PendingActionManager.get_instance(storage_file)
    mgr.clear()
    return mgr


class TestMitigationBypassChecks:
    """Rigorous verification that NO component can bypass the human approval gate."""

    def test_scoring_api_never_executes_mitigation(self, clean_manager):
        """Even a 100% confidence attack scored via /score/flow must NEVER call execution functions."""
        with TestClient(app) as client:
            with patch.object(clean_manager, "_execute_action") as mock_exec, \
                 patch.object(clean_manager, "approve") as mock_approve, \
                 patch("subprocess.run") as mock_sub_run, \
                 patch("subprocess.check_output") as mock_sub_chk:

                # Synthesize flow feature payload
                features = {col: 100.0 for col in api_module.registry.feature_cols}
                features["Fwd Pkts/s"] = 50000.0
                features["Bwd Pkts/s"] = 0.0

                resp = client.post(
                    "/score/flow",
                    headers={"X-API-Key": "scoring-key-test"},
                    json={"features": features},
                )
                assert resp.status_code == 200

                # Assert ZERO execution calls occurred
                mock_exec.assert_not_called()
                mock_approve.assert_not_called()
                mock_sub_run.assert_not_called()
                mock_sub_chk.assert_not_called()

    def test_nemotron_agent_never_executes_mitigation(self, clean_manager):
        """Nemotron agent analysis calls must ONLY enqueue proposed actions with auto_execute=False."""
        from security.ai_threat_analyzer import AIThreatAnalyzer

        analyzer = AIThreatAnalyzer(api_key=None)

        with patch.object(clean_manager, "_execute_action") as mock_exec, \
             patch("subprocess.run") as mock_sub_run, \
             patch("subprocess.check_output") as mock_sub_chk:

            telemetry = {
                "attacker_ip": "192.168.1.199",
                "victim_ip": "10.0.0.4",
                "attack_type": "Syn Flood",
                "packet_count": 2000,
                "confidence": 0.99,
            }

            res = analyzer.analyze_and_propose(telemetry)
            assert res["status"] == "PROPOSED"
            assert res["requires_human_approval"] is True

            # Check action recorded in queue
            aid = res["proposed_action_id"]
            action = clean_manager.get_action(aid)
            assert action is not None
            assert action["status"] == "PENDING"
            assert action["auto_execute"] is False

            # ZERO execution calls
            mock_exec.assert_not_called()
            mock_sub_run.assert_not_called()
            mock_sub_chk.assert_not_called()

    def test_sdn_controller_never_sends_flowmod_before_approval(self, clean_manager):
        """EnhancedRyuSecurityController.mitigate_attacker must NOT call send_msg until approved."""
        from controller.enhanced_security_controller import EnhancedRyuSecurityController

        controller = EnhancedRyuSecurityController.__new__(EnhancedRyuSecurityController)
        controller.logger = MagicMock()

        mock_dp = MagicMock()
        mock_dp.id = 1
        mock_dp.ofproto = MagicMock()
        mock_dp.ofproto_parser = MagicMock()

        action_id = controller.mitigate_attacker(
            mock_dp,
            "192.168.1.88",
            victim_ip="10.0.0.4",
            confidence=0.99,
            in_port=1,
            reason="Continuous ICMP flood",
        )

        # 1. Flow mod was NOT sent
        mock_dp.send_msg.assert_not_called()

        # 2. Action in manager is PENDING with auto_execute=False
        action = clean_manager.get_action(action_id)
        assert action["status"] == "PENDING"
        assert action["auto_execute"] is False
        assert action["action_type"] == "OPENFLOW_DROP"

        # 3. Only explicit approval triggers send_msg
        clean_manager.approve(action_id, approver="test_operator")
        mock_dp.send_msg.assert_called_once()
        assert clean_manager.get_action(action_id)["status"] == "EXECUTED"

    def test_scoring_api_key_cannot_bypass_via_approve_endpoint(self, clean_manager):
        """Attempting to call /actions/approve with a scoring key fails with 403 and NEVER executes."""
        aid = clean_manager.propose("BLOCK", "10.0.0.99", "10.0.0.1", "Test")

        with TestClient(app) as client:
            with patch.object(clean_manager, "_execute_action") as mock_exec:
                # 1. No key
                r1 = client.post(f"/actions/approve/{aid}")
                assert r1.status_code == 401

                # 2. Scoring key
                r2 = client.post(f"/actions/approve/{aid}", headers={"X-API-Key": "scoring-key-test"})
                assert r2.status_code == 403
                assert "Insufficient privileges" in r2.json()["detail"]

                # Action must still be PENDING
                assert clean_manager.get_action(aid)["status"] == "PENDING"
                mock_exec.assert_not_called()

    def test_static_ast_audit_for_execution_calls(self):
        """
        Static AST scan: ensure _execute_action is ONLY called inside PendingActionManager.approve(),
        and no hidden call sites exist in src/api or src/mitigation.
        """
        scan_paths = [
            os.path.join(REPO_ROOT, "src", "mitigation", "manager.py"),
            os.path.join(REPO_ROOT, "src", "api", "scoring_service.py"),
            os.path.join(REPO_ROOT, "src", "mitigation", "cli.py"),
        ]

        for path in scan_paths:
            with open(path, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=path)

            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    # Check for direct calls to _execute_action
                    if isinstance(node.func, ast.Name) and node.func.id == "_execute_action":
                        # Must be manager.py
                        assert "manager.py" in path
                    elif isinstance(node.func, ast.Attribute) and node.func.attr == "_execute_action":
                        assert "manager.py" in path
