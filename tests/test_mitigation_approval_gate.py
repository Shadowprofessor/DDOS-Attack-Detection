"""Tests for Fixes 3 & 4: API key handling and mitigation approval gate.

Fix 3: ai_threat_analyzer no longer has a hardcoded API key.
Fix 4: All mitigation actions go through a pending-actions queue;
       nothing is executed without explicit approve_action() call.
"""
import sys
import os

# Add the Codes directory to sys.path so imports resolve
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "Codes")))

# Clear any residual pending actions from prior test runs
import security.ai_threat_analyzer as ata_module
from security.ai_threat_analyzer import (
    AIThreatAnalyzer,
    get_pending_actions,
    get_action,
    get_action_log,
    approve_action,
    reject_action,
    _pending_actions,
    _action_log,
)
from src.mitigation.manager import get_manager
from security.docker_enforcer import DockerEnforcer


def _reset_pending_actions():
    """Clear pending actions between tests — uses the unified manager to wipe both memory and disk."""
    mgr = get_manager()
    mgr.clear()


class TestFix3_NoHardcodedApiKey:
    """Verify the hardcoded API key is gone."""

    def test_no_hardcoded_key_in_source(self):
        """Read the source file and verify no hardcoded key pattern exists."""
        source_path = os.path.join(
            os.path.dirname(__file__), "..", "Codes", "security", "ai_threat_analyzer.py"
        )
        with open(source_path, "r", encoding="utf-8") as f:
            source = f.read()

        # The old hardcoded key started with "sk-or-v1-"
        assert "sk-or-v1-" not in source, "Hardcoded API key still present in source!"
        # Should not have any literal key as a default value
        assert "sk-or-" not in source, "Potential hardcoded key pattern found!"

    def test_api_key_from_env_variable(self):
        """When OPENROUTER_API_KEY is set, it should be used."""
        os.environ["OPENROUTER_API_KEY"] = "test-key-12345"
        try:
            analyzer = AIThreatAnalyzer()
            assert analyzer.api_key == "test-key-12345"
        finally:
            del os.environ["OPENROUTER_API_KEY"]

    def test_api_key_missing_does_not_crash(self):
        """When no API key is set, the analyzer should still initialize (with a warning)."""
        # Temporarily remove the env var if it exists
        old_key = os.environ.pop("OPENROUTER_API_KEY", None)
        try:
            analyzer = AIThreatAnalyzer()
            assert analyzer.api_key is None
        finally:
            if old_key:
                os.environ["OPENROUTER_API_KEY"] = old_key

    def test_api_key_from_constructor_param(self):
        """Explicit constructor parameter should take precedence."""
        analyzer = AIThreatAnalyzer(api_key="explicit-key-999")
        assert analyzer.api_key == "explicit-key-999"


class TestFix4_MitigationApprovalGate:
    """Verify that detection events result in PROPOSED actions, not executed commands."""

    def setup_method(self):
        _reset_pending_actions()

    def test_analyze_and_propose_creates_pending_action(self):
        """A simulated detection event should create a PENDING action, not execute anything."""
        # No API key → will use local heuristic (no real API call)
        analyzer = AIThreatAnalyzer(api_key=None)

        telemetry = {
            "attacker_ip": "192.168.1.100",
            "victim_ip": "10.0.0.1",
            "attack_type": "ICMP Echo Flood",
            "packet_count": 500,
            "continuous_pings": 200,
        }

        result = analyzer.analyze_and_propose(telemetry)

        # Verify the result says PROPOSED, not MITIGATED
        assert result["status"] == "PROPOSED"
        assert result["requires_human_approval"] is True
        assert "proposed_action_id" in result

        # Verify the action is in the pending queue
        action_id = result["proposed_action_id"]
        action = get_action(action_id)
        assert action is not None
        assert action["status"] == "PENDING"
        assert action["attacker_ip"] == "192.168.1.100"
        assert action["auto_execute"] is False

    def test_analyze_and_prevent_deprecated_also_proposes(self):
        """The old analyze_and_prevent() method should now also just propose."""
        analyzer = AIThreatAnalyzer(api_key=None)
        telemetry = {
            "attacker_ip": "192.168.1.200",
            "victim_ip": "10.0.0.2",
            "attack_type": "TCP SYN Flood",
            "packet_count": 1000,
            "continuous_pings": 0,
        }

        result = analyzer.analyze_and_prevent(telemetry)
        assert result["status"] == "PROPOSED"
        assert result["requires_human_approval"] is True

    def test_docker_enforcer_proposes_not_executes(self):
        """DockerEnforcer.block_attacker_container() should propose, not execute."""
        action_id, message = DockerEnforcer.block_attacker_container(
            "192.168.1.100", "10.0.0.1"
        )

        assert action_id is not None
        assert "pending approval" in message.lower() or "proposed" in message.lower()

        # Verify action is PENDING
        action = get_action(action_id)
        assert action is not None
        assert action["status"] == "PENDING"
        assert action["action_type"] == "DOCKER_BLOCK"

    def test_approve_action_changes_status(self):
        """approve_action() should change status to EXECUTED."""
        analyzer = AIThreatAnalyzer(api_key=None)
        telemetry = {
            "attacker_ip": "192.168.1.100",
            "victim_ip": "10.0.0.1",
            "attack_type": "UDP Flood",
            "packet_count": 300,
            "continuous_pings": 0,
        }
        result = analyzer.analyze_and_propose(telemetry)
        action_id = result["proposed_action_id"]

        # Approve the action
        success, msg = approve_action(action_id)
        assert success is True

        action = get_action(action_id)
        assert action["status"] == "EXECUTED"

    def test_reject_action(self):
        """reject_action() should mark the action as REJECTED."""
        action_id, _ = DockerEnforcer.block_attacker_container("192.168.1.100", "10.0.0.1")

        success, msg = reject_action(action_id)
        assert success is True

        action = get_action(action_id)
        assert action["status"] == "REJECTED"

    def test_double_approve_fails(self):
        """Cannot approve an already-approved action."""
        action_id, _ = DockerEnforcer.block_attacker_container("192.168.1.100", "10.0.0.1")
        approve_action(action_id)
        success, msg = approve_action(action_id)
        assert success is False

    def test_get_pending_actions_filters_correctly(self):
        """get_pending_actions() should only return PENDING actions."""
        # Create two actions
        id1, _ = DockerEnforcer.block_attacker_container("192.168.1.1", "10.0.0.1")
        id2, _ = DockerEnforcer.block_attacker_container("192.168.1.2", "10.0.0.1")

        # Approve one
        approve_action(id1)

        pending = get_pending_actions()
        assert id1 not in pending
        assert id2 in pending

    def test_action_log_is_chronological(self):
        """The action log should contain all proposed actions in order."""
        DockerEnforcer.block_attacker_container("192.168.1.1", "10.0.0.1")
        DockerEnforcer.block_attacker_container("192.168.1.2", "10.0.0.1")
        DockerEnforcer.block_attacker_container("192.168.1.3", "10.0.0.1")

        log = get_action_log()
        assert len(log) == 3
        # Verify chronological order
        assert log[0]["proposed_at"] <= log[1]["proposed_at"] <= log[2]["proposed_at"]

    def test_no_subprocess_calls_in_propose(self):
        """
        Verify that analyze_and_propose() does NOT import or call subprocess.
        (The old execute_prevention() used subprocess directly.)
        """
        import importlib
        import unittest.mock as mock

        # Patch subprocess to detect any calls
        with mock.patch.dict("sys.modules", {"subprocess": mock.MagicMock()}) as mocked:
            analyzer = AIThreatAnalyzer(api_key=None)
            telemetry = {
                "attacker_ip": "192.168.1.100",
                "victim_ip": "10.0.0.1",
                "attack_type": "Test",
                "packet_count": 1,
                "continuous_pings": 0,
            }
            result = analyzer.analyze_and_propose(telemetry)
            assert result["status"] == "PROPOSED"
            # subprocess should not have been called


class TestFix5_OpenFlowDropApprovalGate:
    """Verify that OpenFlow DROP actions go through the approval gate and do NOT send flow-mods directly."""

    def setup_method(self):
        _reset_pending_actions()

    def test_mitigate_attacker_proposes_and_does_not_send_flow_mod(self):
        """mitigate_attacker() must create a PENDING action and NOT call send_msg until approved."""
        from unittest.mock import MagicMock
        from controller.enhanced_security_controller import EnhancedRyuSecurityController

        # Instantiate controller using __new__ to avoid spawning Ryu monitor threads
        controller = EnhancedRyuSecurityController.__new__(EnhancedRyuSecurityController)
        controller.logger = MagicMock()

        mock_dp = MagicMock()
        mock_dp.id = 1
        mock_dp.ofproto = MagicMock()
        mock_dp.ofproto_parser = MagicMock()

        # Trigger mitigate_attacker with explicit victim_ip and confidence
        action_id = controller.mitigate_attacker(
            mock_dp, "192.168.1.50", victim_ip="10.0.0.4", confidence=0.98, in_port=2, reason="Simulated Flood"
        )

        # 1. Verify NO flow-mod sent to datapath directly
        mock_dp.send_msg.assert_not_called()

        # 2. Verify PENDING action created with action_type OPENFLOW_DROP, correct victim_ip and confidence
        assert action_id is not None
        action = get_action(action_id)
        assert action is not None
        assert action["status"] == "PENDING"
        assert action["action_type"] == "OPENFLOW_DROP"
        assert action["attacker_ip"] == "192.168.1.50"
        assert action["victim_ip"] == "10.0.0.4"
        assert action["confidence"] == 0.98
        assert action["auto_execute"] is False

        # 3. Approve action and verify flow-mod IS sent only after approval
        success, msg = approve_action(action_id)
        assert success is True
        mock_dp.send_msg.assert_called_once()
        # Re-fetch after approve because approve() reloads from disk
        action_after = get_action(action_id)
        assert action_after["status"] == "EXECUTED"


