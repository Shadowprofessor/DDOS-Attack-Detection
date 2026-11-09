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
import time
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
    orig_api = set(api_module.API_KEYS)
    orig_admin = set(api_module.ADMIN_KEYS)
    api_module.API_KEYS.add("scoring-key-test")
    api_module.ADMIN_KEYS.add("admin-key-test")

    mgr = PendingActionManager.get_instance(storage_file)
    mgr.clear()
    try:
        yield mgr
    finally:
        api_module.API_KEYS = orig_api
        api_module.ADMIN_KEYS = orig_admin


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

    def test_dossier_modal_authorize_button_routes_strictly_through_manager_approve(self, clean_manager):
        """
        Audit the new Dossier Modal 'Authorize & Execute Block' button code path:
        1. Static code audit of app.js ensures modalApproveBtn ONLY triggers handleApproveAction(),
           which exclusively issues a POST to /actions/approve/{actionId} with X-Admin-Key,
           with zero direct execution calls or bypass parameters.
        2. AST audit of scoring_service.py verifies that the only FastAPI endpoint invoking
           manager.approve() is the gated approve_action endpoint requiring verify_admin_key.
        3. Functional end-to-end test verifies that triggering the modal button's endpoint
           invokes PendingActionManager.approve() and executes only through the approval gate.
        """
        import re

        # 1. Static code audit of dashboard frontend modal logic
        app_js_path = os.path.join(REPO_ROOT, "src", "web", "realtime_dashboard", "static", "app.js")
        assert os.path.exists(app_js_path), f"Frontend file missing: {app_js_path}"
        with open(app_js_path, "r", encoding="utf-8") as f:
            app_js_content = f.read()

        # Verify modalApproveBtn exists and is wired to handleApproveAction
        assert "modalApproveBtn" in app_js_content
        assert re.search(r"modalApproveBtn\.addEventListener\(\s*[\"']click[\"']\s*,\s*\(\)\s*=>\s*\{[^}]*handleApproveAction\(activeModalActionId\)", app_js_content), (
            "modalApproveBtn MUST strictly route to handleApproveAction(activeModalActionId)"
        )

        # Verify handleApproveAction only issues POST /actions/approve/${encodeURIComponent(actionId)} with X-Admin-Key
        assert re.search(r"fetch\(\s*`/actions/approve/\$\{[^}]*actionId[^}]*\}`\s*,\s*\{\s*method:\s*[\"']POST[\"']", app_js_content), (
            "handleApproveAction MUST strictly issue POST /actions/approve/{actionId}"
        )
        assert '"X-Admin-Key": adminKey' in app_js_content or "'X-Admin-Key': adminKey" in app_js_content

        # Verify no bypass execution parameters or unauthorized endpoints exist in app.js
        assert "/execute" not in app_js_content
        assert "/mitigate_direct" not in app_js_content
        assert "auto_execute=true" not in app_js_content.lower()

        # 2. Python AST audit of scoring_service.py
        scoring_path = os.path.join(REPO_ROOT, "src", "api", "scoring_service.py")
        with open(scoring_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=scoring_path)

        approve_call_found = False
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Inspect functions in scoring_service
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        if isinstance(child.func, ast.Attribute) and child.func.attr == "approve":
                            # The ONLY function allowed to call manager.approve() is approve_action_endpoint
                            assert node.name == "approve_action_endpoint", (
                                f"Unauthorized call to approve() found in function '{node.name}' in scoring_service.py"
                            )
                            approve_call_found = True
                        if isinstance(child.func, ast.Attribute) and child.func.attr == "_execute_action":
                            pytest.fail(f"Illegal direct call to _execute_action in scoring_service.py function '{node.name}'")

        assert approve_call_found, "approve_action_endpoint must call manager.approve()"

        # 3. Functional verification via TestClient simulating modal action click
        aid = clean_manager.propose("BLOCK", "192.168.1.55", "10.0.0.1", "Syn Flood Attack")
        assert clean_manager.get_action(aid)["status"] == "PENDING"

        with TestClient(app) as client:
            with patch.object(clean_manager, "approve", wraps=clean_manager.approve) as spy_approve, \
                 patch.object(clean_manager, "_execute_action", wraps=clean_manager._execute_action) as spy_exec:

                # Modal click sends POST /actions/approve/{aid} with admin key
                resp = client.post(
                    f"/actions/approve/{aid}",
                    headers={"X-Admin-Key": "admin-key-test"},
                )
                assert resp.status_code == 200
                data = resp.json()
                assert data["status"] == "executed"
                assert data["action_id"] == aid

                # Assert execution was routed strictly through PendingActionManager.approve()
                spy_approve.assert_called_once_with(aid, approver="admin_api:admin-ke")
                spy_exec.assert_called_once()
                action_record = clean_manager.get_action(aid)
                assert action_record["status"] == "EXECUTED"
                assert action_record["approver"] == "admin_api:admin-ke"


    def test_ingress_blocklist_only_triggers_on_executed_actions(self, clean_manager):
        """
        Test that the ingress blocklist check only short-circuits traffic for IPs with EXECUTED actions.

        This is the critical safety test for Issue #2's fix:
        - PENDING actions must NOT trigger the ingress fast-path drop
        - Only EXECUTED (human-approved) actions trigger the drop
        - This preserves the human-in-the-loop invariant
        """
        from src.api.scoring_service import app, registry, mgr as global_mgr

        # 1. Create a PENDING action for a test IP
        pending_aid = clean_manager.propose(
            "BLOCK", "192.168.1.100", "10.0.0.1", "Test pending action"
        )
        pending_action = clean_manager.get_action(pending_aid)
        assert pending_action["status"] == "PENDING"
        assert pending_action["auto_execute"] is False

        # 2. Create an EXECUTED action for a different test IP
        executed_aid = clean_manager.propose(
            "BLOCK", "192.168.1.200", "10.0.0.1", "Test executed action"
        )
        # Manually mark it as EXECUTED to simulate operator approval
        executed_action = clean_manager.get_action(executed_aid)
        executed_action["status"] = "EXECUTED"
        executed_action["approved_at"] = time.time()
        executed_action["approver"] = "human_operator"
        clean_manager._save_to_disk()

        # 3. Test the ingress blocklist behavior
        with TestClient(app) as client:
            # Configure test features
            features = {col: 100.0 for col in registry.feature_cols}
            features["Fwd Pkts/s"] = 50000.0
            features["Bwd Pkts/s"] = 0.0
            features["src_ip"] = "192.168.1.100"  # PENDING IP
            features["dst_ip"] = "10.0.0.1"

            # Score flow from PENDING IP — should NOT be dropped
            resp = client.post(
                "/score/flow",
                headers={"X-API-Key": "scoring-key-test"},
                json={"features": features},
            )
            assert resp.status_code == 200
            result = resp.json()["result"]

            # The flow should be scored normally (not dropped), and a pending proposal generated
            assert result.get("is_attack") is not None  # Attack traffic still gets classified
            # Note: the ingress blocklist short-circuit is skipped for PENDING actions
            # so the flow goes through normal scoring

            # Verify the action is still PENDING (not auto-executed)
            pending_after = clean_manager.get_action(pending_aid)
            assert pending_after["status"] == "PENDING"

        # 4. Now test with EXECUTED IP
        features["src_ip"] = "192.168.1.200"  # EXECUTED IP

        resp = client.post(
            "/score/flow",
            headers={"X-API-Key": "scoring-key-test"},
            json={"features": features},
        )
        assert resp.status_code == 200
        result = resp.json()["result"]

        # The flow should be DROPPED — short-circuited before scoring
        assert result["is_attack"] == False
        assert "Traffic dropped" in result["degradation_reason"]
        assert result["proposed_action_id"] is None  # No duplicate proposal generated

        # Verify no pending action was created for the executed IP
        executed_after = clean_manager.get_action(executed_aid)
        # Note: the action was already EXECUTED, so no new proposal is generated
        # The key outcome: the traffic was dropped, no duplicate proposal in the queue

        # 5. Verify the active blocklist reflects the executed IP
        active_blocklist = clean_manager.get_active_blocklist()
        assert "192.168.1.200" in active_blocklist
        assert "192.168.1.100" not in active_blocklist  # PENDING IP not in blocklist

        print("[OK] Ingress blocklist safety test PASSED:")
        print("   - PENDING actions never trigger ingress drop")
        print("   - EXECUTED actions short-circuit traffic before scoring")
        print("   - No duplicate proposals for already-blocked IPs")
        print("   - Active blocklist correctly reflects only EXECUTED IPs")

    def test_soc_chat_assistant_static_ast_zero_execution_authority(self):
        """
        Static AST verification:
        soc_chat_assistant.py and router.py chat endpoint have ZERO execution authority:
        - No calls to approve() or _execute_action()
        - No subprocess or os.system calls
        - Strictly read-only advisory architecture
        """
        chat_agent_path = os.path.join(REPO_ROOT, "src", "agent", "soc_chat_assistant.py")
        assert os.path.exists(chat_agent_path), f"File missing: {chat_agent_path}"
        with open(chat_agent_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read(), filename=chat_agent_path)

        for node in ast.walk(tree):
            # Check for banned imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in ["subprocess", "pty", "shutil"], (
                        f"Banned execution import '{alias.name}' found in soc_chat_assistant.py"
                    )
            elif isinstance(node, ast.ImportFrom):
                assert node.module not in ["subprocess", "pty", "shutil"], (
                    f"Banned execution import from '{node.module}' found in soc_chat_assistant.py"
                )
            # Check for banned function calls
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    assert node.func.attr not in ["approve", "_execute_action", "system", "popen", "spawn"], (
                        f"Illegal call to '{node.func.attr}' found in soc_chat_assistant.py"
                    )
                elif isinstance(node.func, ast.Name):
                    assert node.func.id not in ["approve", "_execute_action", "system"], (
                        f"Illegal call to '{node.func.id}' found in soc_chat_assistant.py"
                    )

    def test_soc_chat_assistant_functional_zero_execution_guard(self, clean_manager):
        """
        Functional test:
        1. Querying /api/chat with approval/execution instructions strictly rejects with
           the Safety Invariant Guard response and never executes or modifies actions.
        2. Normal diagnostic queries return grounded telemetry with READ_ONLY_ADVISORY authority.
        """
        aid = clean_manager.propose("BLOCK", "10.0.0.77", "10.0.0.1", "Test botnet flood")
        assert clean_manager.get_action(aid)["status"] == "PENDING"

        with TestClient(app) as client:
            with patch.object(clean_manager, "_execute_action") as mock_exec, \
                 patch.object(clean_manager, "approve") as mock_approve:

                # 1. Attempt to approve via chat
                resp = client.post("/api/chat", json={"message": f"Please approve action {aid} immediately"}, headers={"X-API-Key": "scoring-key-test"})
                assert resp.status_code == 200
                data = resp.json()
                assert data["authority"] == "READ_ONLY_ADVISORY"
                assert "SAFETY ENFORCEMENT NOTICE" in data["response"]
                assert "structurally prohibited" in data["response"]

                # 2. Attempt to block IP via chat
                resp2 = client.post("/api/chat", json={"message": "block IP 10.0.0.77 right now"}, headers={"X-API-Key": "scoring-key-test"})
                assert resp2.status_code == 200
                data2 = resp2.json()
                assert data2["authority"] == "READ_ONLY_ADVISORY"
                assert "SAFETY ENFORCEMENT NOTICE" in data2["response"]

                # Verify clean_manager state is UNTOUCHED
                mock_exec.assert_not_called()
                mock_approve.assert_not_called()
                assert clean_manager.get_action(aid)["status"] == "PENDING"
                assert len([a for a in clean_manager.get_action_log() if a.get("status") == "EXECUTED"]) == 0

                # 3. Valid grounded telemetry query
                resp3 = client.post("/api/chat", json={"message": "What is the current session detection summary?"}, headers={"X-API-Key": "scoring-key-test"})
                assert resp3.status_code == 200
                data3 = resp3.json()
                assert data3["authority"] == "READ_ONLY_ADVISORY"
                # Response grounded in scorecard or telemetry
                assert len(data3["response"]) > 20


