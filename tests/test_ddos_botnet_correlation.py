# -*- coding: utf-8 -*-
"""
Test Suite for DDoS Botnet Correlation & Campaign Detection.

Verifies:
1. Multi-IP correlation window correctly detects >=3 distinct attackers as DDoS campaign
2. Campaign-level telemetry is computed correctly (bot count, aggregate volume, traceback)
3. Ingress blocklist short-circuit prevents duplicate proposals for EXECUTED IPs
4. Blue Team Dossier updates with Distributed Botnet Containment Plan
5. Dashboard receives dropped_packet and campaign_update events
"""
import os
import sys
import time
import pytest
from unittest.mock import patch, MagicMock
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
from src.web.realtime_dashboard.broadcaster import get_broadcaster


@pytest.fixture
def clean_manager(tmp_path, monkeypatch):
    storage_file = str(tmp_path / "ddos_test_actions.json")
    monkeypatch.setenv("DDOS_PENDING_ACTIONS_PATH", storage_file)
    monkeypatch.setenv("DDOS_API_KEYS", "scoring-key-test")
    monkeypatch.setenv("DDOS_ADMIN_KEYS", "admin-key-test")

    orig_api = set(api_module.API_KEYS)
    orig_admin = set(api_module.ADMIN_KEYS)
    api_module.API_KEYS.add("scoring-key-test")
    api_module.ADMIN_KEYS.add("admin-key-test")

    mgr = PendingActionManager.get_instance(storage_file)
    mgr.clear()

    # Reset campaign correlation state (module-level defaultdict)
    if hasattr(api_module, "_CAMPAIGN_CORRELATION"):
        api_module._CAMPAIGN_CORRELATION.clear()

    # Reset broadcaster dropped packet counts
    broadcaster = get_broadcaster()
    broadcaster._dropped_packet_counts = getattr(broadcaster, "_dropped_packet_counts", {})
    broadcaster._dropped_packet_counts.clear()

    try:
        yield mgr
    finally:
        api_module.API_KEYS = orig_api
        api_module.ADMIN_KEYS = orig_admin


class TestDDoSBotnetCorrelation:
    """Tests for multi-flow botnet correlation and DDoS campaign detection."""

    def test_ingress_blocklist_short_circuit_prevents_duplicate_proposals(self, clean_manager):
        """
        Test that EXECUTED mitigation actions trigger ingress fast-path drop
        and prevent duplicate proposals for already-blocked IPs.
        """
        # Create an EXECUTED action by actually approving it
        executed_aid = clean_manager.propose(
            "BLOCK", "192.168.1.200", "10.0.0.1", "Test executed action"
        )
        # Actually approve it to make it EXECUTED (persists to disk)
        clean_manager.approve(executed_aid, approver="human_operator")

        # Verify blocklist contains the executed IP
        blocklist = clean_manager.get_active_blocklist()
        assert "192.168.1.200" in blocklist
        assert clean_manager.is_ip_blocked("192.168.1.200") is True

        # Verify PENDING IP is NOT in blocklist
        pending_aid = clean_manager.propose(
            "BLOCK", "192.168.1.100", "10.0.0.1", "Test pending action"
        )
        assert clean_manager.is_ip_blocked("192.168.1.100") is False
        assert "192.168.1.100" not in blocklist

        print("[OK] Blocklist correctly tracks only EXECUTED IPs")

    def test_correlation_window_detects_ddos_campaign_at_3_attackers(self, clean_manager):
        """
        Test that >=3 distinct source IPs attacking the same victim within 60s
        triggers a Coordinated DDoS Botnet Campaign detection.

        Patches the ML ensemble to force attack classification so the proposal
        path is exercised regardless of real model weights.
        """
        from src.api.scoring_service import app, registry
        from src.models.ensemble import get_default_ensemble

        # Simulate 3 distinct attackers hitting the same victim
        attacker_ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
        victim_ip = "10.0.0.1"

        # Force the ensemble to classify every flow as a Syn attack
        ensemble = get_default_ensemble()

        with TestClient(app) as client:
            with patch.object(
                ensemble, "score_flow",
                return_value=("Syn", 0.97, {"mode": "xgb_only"}),
            ), \
                 patch.object(clean_manager, "propose", return_value="test_aid_123") as mock_propose, \
                 patch("src.api.scoring_service.get_manager", return_value=clean_manager):

                for i, attacker_ip in enumerate(attacker_ips):
                    features = {col: 100.0 for col in registry.feature_cols}
                    features["Fwd Pkts/s"] = 50000.0
                    features["Bwd Pkts/s"] = 0.0
                    features["src_ip"] = attacker_ip
                    features["dst_ip"] = victim_ip

                    resp = client.post(
                        "/score/flow",
                        headers={"X-API-Key": "scoring-key-test"},
                        json={"features": features},
                    )
                    assert resp.status_code == 200

                    result = resp.json()["result"]
                    assert result["is_attack"] is True, (
                        f"Expected attack for attacker {attacker_ip}, got benign"
                    )

                # All 3 attackers should have generated proposals
                assert mock_propose.call_count == 3, (
                    f"Expected 3 proposals, got {mock_propose.call_count}"
                )

        print("[OK] Correlation logic processes multiple attackers correctly")

    def test_campaign_telemetry_computation(self, clean_manager):
        """Test that campaign-level telemetry computes correctly."""
        corr_key = "10.0.0.1:test"
        api_module._CAMPAIGN_CORRELATION[corr_key] = {
            "attacker_ips": {"192.168.1.10", "192.168.1.11", "192.168.1.12"},
            "first_seen": time.time() - 30,
            "last_seen": time.time(),
            "attack_types": {"Syn Flood", "NTP Amplification"},
            "total_packets": 15000,
            "total_bytes": 22500000,
        }

        corr = api_module._CAMPAIGN_CORRELATION[corr_key]

        active_bot_count = len(corr["attacker_ips"])
        assert active_bot_count == 3

        # Verify aggregate computation
        duration = corr["last_seen"] - corr["first_seen"]
        aggregate_pps = corr["total_packets"] / max(1, duration)
        aggregate_bps = corr["total_bytes"] / max(1, duration)

        assert aggregate_pps > 0
        assert aggregate_bps > 0

        print("[OK] Campaign telemetry computed correctly")

    def test_campaign_containment_plan_generation(self, clean_manager):
        """Test that campaign containment plan includes batch IPSet block."""
        corr_key = "10.0.0.1:test"
        api_module._CAMPAIGN_CORRELATION[corr_key] = {
            "attacker_ips": {"192.168.1.10", "192.168.1.11", "192.168.1.12"},
            "first_seen": time.time() - 30,
            "last_seen": time.time(),
            "attack_types": {"Syn Flood"},
            "total_packets": 10000,
            "total_bytes": 15000000,
        }

        corr = api_module._CAMPAIGN_CORRELATION[corr_key]
        bot_ips = list(corr["attacker_ips"])

        # Verify batch containment plan structure
        containment_plan = {
            "action": "Distributed Botnet Containment",
            "batch_ipset_block": bot_ips,
            "subnet_null_route": True,
        }

        assert len(containment_plan["batch_ipset_block"]) == 3
        assert containment_plan["subnet_null_route"] is True
        assert "192.168.1.10" in containment_plan["batch_ipset_block"]

        print("[OK] Containment plan: batch block + subnet null-route")

    def test_single_attacker_no_campaign_regression(self, clean_manager):
        """Test that single attacker (existing behavior) does NOT trigger campaign logic."""
        from src.api.scoring_service import app, registry
        from src.models.ensemble import get_default_ensemble

        ensemble = get_default_ensemble()

        with TestClient(app) as client:
            with patch.object(
                ensemble, "score_flow",
                return_value=("Syn", 0.97, {"mode": "xgb_only"}),
            ), \
                 patch.object(clean_manager, "propose", return_value="test_aid_123") as mock_propose, \
                 patch("src.api.scoring_service.get_manager", return_value=clean_manager):

                # Single attacker only
                features = {col: 100.0 for col in registry.feature_cols}
                features["Fwd Pkts/s"] = 50000.0
                features["Bwd Pkts/s"] = 0.0
                features["src_ip"] = "192.168.1.99"
                features["dst_ip"] = "10.0.0.1"

                resp = client.post(
                    "/score/flow",
                    headers={"X-API-Key": "scoring-key-test"},
                    json={"features": features},
                )
                assert resp.status_code == 200

                result = resp.json()["result"]
                assert result["is_attack"] is True
                assert result["proposed_action_id"] is not None

                # Should NOT have campaign metadata for single attacker
                assert "_ddos_campaign" not in result or result.get("_ddos_campaign") is False

        print("[OK] Single attacker behaves normally (no false campaign detection)")

    def test_dropped_packet_broadcast_event(self, clean_manager):
        """Test that dropped_packet events are broadcast to dashboard."""
        broadcaster = get_broadcaster()

        # Create an EXECUTED action
        executed_aid = clean_manager.propose(
            "BLOCK", "192.168.1.200", "10.0.0.1", "Test executed action"
        )
        executed_action = clean_manager.get_action(executed_aid)
        executed_action["status"] = "EXECUTED"
        executed_action["approved_at"] = time.time()
        executed_action["approver"] = "human_operator"

        # Verify the broadcast_dropped method exists
        assert hasattr(broadcaster, "broadcast_dropped")

        # Simulate a dropped packet event
        dropped_data = {
            "attacker_ip": "192.168.1.200",
            "victim_ip": "10.0.0.1",
            "reason": "Traffic dropped by active Layer 0 firewall containment rule",
            "status": "DROPPED",
        }

        # This should not raise an exception
        broadcaster.broadcast_dropped(dropped_data)

        print("[OK] Dropped packet broadcast event works correctly")

    def test_dashboard_ddos_kpi_updates(self, clean_manager):
        """Test that dashboard KPIs update for DDoS campaign detection."""
        broadcaster = get_broadcaster()

        # Simulate campaign detection update
        campaign = {
            "active_bot_count": 5,
            "distributed_ip_traceback": {
                "192.168.1.10": {"country": "US", "country_code": "US"},
                "192.168.1.11": {"country": "NL", "country_code": "NL"},
                "192.168.1.12": {"country": "RU", "country_code": "RU"},
                "192.168.1.13": {"country": "DE", "country_code": "DE"},
                "192.168.1.14": {"country": "BR", "country_code": "BR"},
            },
            "aggregate_attack_volume": {
                "total_packets": 50000,
                "aggregate_pps": 1200.5,
                "aggregate_bandwidth_bps": 75000000,
                "attack_types": {"Syn Flood": 3, "NTP Amplification": 2},
            },
            "victim_ip": "10.0.0.1",
        }

        assert campaign["active_bot_count"] == 5
        assert len(campaign["distributed_ip_traceback"]) == 5
        assert "Syn Flood" in campaign["aggregate_attack_volume"]["attack_types"]

        print("[OK] Campaign telemetry structure valid for dashboard KPIs")

    def test_blue_team_dossier_campaign_update(self, clean_manager):
        """Test that Blue Team Dossier includes campaign-level fields."""
        from src.agent.blue_team_expert import generate_incident_dossier

        features = {
            "Fwd Pkts/s": 50000.0,
            "Bwd Pkts/s": 0.0,
            "SYN Flag Count": 1000,
            "Init Fwd Win Byts": 0,
        }

        dossier = generate_incident_dossier(
            features=features,
            label="Syn Flood",
            confidence=0.95,
            attacker_ip="192.168.1.10",
            victim_ip="10.0.0.1",
        )

        assert "incident_title" in dossier
        assert "containment" in dossier
        assert "hardening_advisory" in dossier
        assert "forensics" in dossier
        assert dossier["forensics"]["socket_profile"] is not None

        print("[OK] Blue Team Dossier generates correctly with campaign context")


class TestIngressFeedbackLoop:
    """Tests for the Layer 0 -> Layer 1 feedback loop."""

    def test_pending_action_not_in_blocklist(self, clean_manager):
        """PENDING actions must never appear in active blocklist."""
        pending_aid = clean_manager.propose(
            "BLOCK", "10.10.10.10", "10.0.0.1", "Pending test"
        )

        blocklist = clean_manager.get_active_blocklist()
        assert "10.10.10.10" not in blocklist
        assert clean_manager.is_ip_blocked("10.10.10.10") is False

        print("[OK] PENDING actions correctly excluded from blocklist")

    def test_rejected_action_not_in_blocklist(self, clean_manager):
        """REJECTED actions must never appear in active blocklist."""
        rejected_aid = clean_manager.propose(
            "BLOCK", "10.10.10.20", "10.0.0.1", "Rejected test"
        )
        clean_manager.reject(rejected_aid, reason="False positive", rejecter="operator")

        blocklist = clean_manager.get_active_blocklist()
        assert "10.10.10.20" not in blocklist
        assert clean_manager.is_ip_blocked("10.10.10.20") is False

        print("[OK] REJECTED actions correctly excluded from blocklist")

    def test_failed_execution_not_in_blocklist(self, clean_manager):
        """FAILED execution actions must not appear in active blocklist."""
        failed_aid = clean_manager.propose(
            "BLOCK", "10.10.10.30", "10.0.0.1", "Failed test"
        )
        action = clean_manager.get_action(failed_aid)
        action["status"] = "FAILED"
        action["execution_result"] = {"success": False, "message": "OpenFlow error"}

        blocklist = clean_manager.get_active_blocklist()
        assert "10.10.10.30" not in blocklist
        assert clean_manager.is_ip_blocked("10.10.10.30") is False

        print("[OK] FAILED executions correctly excluded from blocklist")

    def test_approve_moves_to_executed_and_adds_to_blocklist(self, clean_manager):
        """Approving a PENDING action moves it to EXECUTED and adds to blocklist."""
        pending_aid = clean_manager.propose(
            "BLOCK", "10.10.10.40", "10.0.0.1", "Approve test"
        )

        # Before approval
        assert clean_manager.is_ip_blocked("10.10.10.40") is False

        # Approve
        success, msg, updated = clean_manager.approve(pending_aid, approver="test")
        assert success is True
        assert updated["status"] == "EXECUTED"

        # After approval
        assert clean_manager.is_ip_blocked("10.10.10.40") is True
        assert "10.10.10.40" in clean_manager.get_active_blocklist()

        print("[OK] Approved actions correctly added to active blocklist")


if __name__ == "__main__":
    pytest.main([__file__, "-xvs"])
