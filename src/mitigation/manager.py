# -*- coding: utf-8 -*-
"""
Centralized Mitigation Engine & Pending Action Manager.

SAFETY INVARIANT:
No mitigation action (iptables, docker exec, OpenFlow DROP) may EVER execute
as a direct result of a model prediction, scoring API call, or LLM response.
Every action MUST:
  1. Be proposed and enqueued with status='PENDING' and auto_execute=False.
  2. Persisted to pending_actions.json.
  3. Require explicit human approval via the CLI or an authenticated Admin API call.
"""
import os
import json
import time
import uuid
import logging
import threading
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger("MitigationManager")

DEFAULT_STORAGE_PATH = os.path.abspath(
    os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "pending_actions.json")
)


class PendingActionManager:
    """
    Thread-safe and process-persistent manager for proposed mitigation actions.
    All proposed actions are persisted to disk in JSON format.
    """

    _instance: Optional["PendingActionManager"] = None
    _singleton_lock = threading.Lock()

    def __init__(self, storage_path: Optional[str] = None):
        self.storage_path = os.path.abspath(
            storage_path or os.environ.get("DDOS_PENDING_ACTIONS_PATH", DEFAULT_STORAGE_PATH)
        )
        self._lock = threading.RLock()
        self._pending_actions: Dict[str, dict] = {}
        self._action_log: List[dict] = []
        # In-memory ephemeral references (e.g. OpenFlow datapath objects that cannot be JSON serialized)
        self._ephemeral_contexts: Dict[str, dict] = {}
        self._load_from_disk()

    @classmethod
    def get_instance(cls, storage_path: Optional[str] = None) -> "PendingActionManager":
        """Singleton accessor for unified queue access across modules."""
        with cls._singleton_lock:
            if cls._instance is None:
                cls._instance = cls(storage_path)
            elif storage_path and cls._instance.storage_path != os.path.abspath(storage_path):
                cls._instance = cls(storage_path)
            return cls._instance

    def _ensure_dir(self):
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)

    def _load_from_disk(self):
        """Read existing actions from disk if file exists."""
        with self._lock:
            if not os.path.exists(self.storage_path):
                self._pending_actions = {}
                self._action_log = []
                return

            try:
                with open(self.storage_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._action_log = data.get("action_log", [])
                    self._pending_actions = {a["action_id"]: a for a in self._action_log}
            except Exception as e:
                logger.warning("Could not read pending actions file %s: %s. Starting with empty queue.", self.storage_path, e)
                self._pending_actions = {}
                self._action_log = []

    def _save_to_disk(self):
        """Atomically persist actions to disk."""
        with self._lock:
            self._ensure_dir()
            tmp_path = f"{self.storage_path}.tmp.{uuid.uuid4().hex[:6]}"
            try:
                payload = {
                    "version": 1,
                    "updated_at": time.time(),
                    "action_log": self._action_log,
                }
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2)
                # Atomic replace
                os.replace(tmp_path, self.storage_path)
            except Exception as e:
                logger.error("Failed to persist pending actions to %s: %s", self.storage_path, e)
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass

    def propose(
        self,
        action_type: str,
        attacker_ip: str,
        victim_ip: str,
        reason: str,
        confidence: Optional[float] = None,
        commands: Optional[List[str]] = None,
        source: str = "mitigation_engine",
        datapath: Any = None,
    ) -> str:
        """
        Create and record a PROPOSED mitigation action.
        NEVER executes commands automatically.
        """
        with self._lock:
            self._load_from_disk()
            action_id = str(uuid.uuid4())[:8]
            action = {
                "action_id": action_id,
                "action_type": action_type,
                "attacker_ip": attacker_ip,
                "victim_ip": victim_ip,
                "reason": reason,
                "confidence": confidence,
                "proposed_commands": commands or [],
                "source": source,
                "status": "PENDING",
                "proposed_at": time.time(),
                "approved_at": None,
                "rejected_at": None,
                "approver": None,
                "auto_execute": False,  # HARD RULE: NEVER True
                "execution_result": None,
            }

            if datapath is not None:
                self._ephemeral_contexts[action_id] = {"datapath": datapath}

            self._pending_actions[action_id] = action
            self._action_log.append(action)
            self._save_to_disk()

            logger.info(
                "📋 [PROPOSED ACTION %s] %s — %s → %s | Reason: %s | Status: PENDING (requires human approval)",
                action_id, action_type, attacker_ip, victim_ip, reason
            )
            return action_id

    def get_pending(self) -> Dict[str, dict]:
        """Return a mapping of action_id -> action dict for all unapproved actions."""
        with self._lock:
            self._load_from_disk()
            return {
                aid: a for aid, a in self._pending_actions.items()
                if a.get("status") == "PENDING"
            }

    def get_action(self, action_id: str) -> Optional[dict]:
        """Retrieve a specific action by ID."""
        with self._lock:
            self._load_from_disk()
            return self._pending_actions.get(action_id)

    def get_action_log(self) -> List[dict]:
        """Return the complete chronological log of actions."""
        with self._lock:
            self._load_from_disk()
            return list(self._action_log)

    def approve(self, action_id: str, approver: str = "human_operator") -> Tuple[bool, str, Optional[dict]]:
        """
        Approve and execute a pending mitigation action.
        This is the ONLY code path that may trigger underlying execution.
        """
        with self._lock:
            self._load_from_disk()
            action = self._pending_actions.get(action_id)
            if not action:
                return False, f"Action {action_id} not found", None

            if action.get("status") != "PENDING":
                return False, f"Action {action_id} is already {action.get('status')}", action

            action["status"] = "APPROVED"
            action["approved_at"] = time.time()
            action["approver"] = approver

            # Execute under controlled safety wrapper
            exec_result = self._execute_action(action)
            action["status"] = "EXECUTED" if exec_result["success"] else "FAILED"
            action["execution_result"] = exec_result

            self._save_to_disk()
            return exec_result["success"], exec_result.get("message", "Executed"), action

    def reject(self, action_id: str, reason: str = "", rejecter: str = "human_operator") -> Tuple[bool, str, Optional[dict]]:
        """Reject a pending action without execution."""
        with self._lock:
            self._load_from_disk()
            action = self._pending_actions.get(action_id)
            if not action:
                return False, f"Action {action_id} not found", None

            if action.get("status") != "PENDING":
                return False, f"Action {action_id} is already {action.get('status')}", action

            action["status"] = "REJECTED"
            action["rejected_at"] = time.time()
            action["rejecter"] = rejecter
            if reason:
                action["rejection_reason"] = reason

            self._save_to_disk()
            return True, "Action rejected", action

    def clear(self):
        """Reset the queue (primarily for testing)."""
        with self._lock:
            self._pending_actions.clear()
            self._action_log.clear()
            self._ephemeral_contexts.clear()
            if os.path.exists(self.storage_path):
                try:
                    os.remove(self.storage_path)
                except OSError:
                    pass

    def _execute_action(self, action: dict) -> dict:
        """
        Internal dispatcher that applies the approved mitigation.
        ONLY invoked via approve().
        """
        action_type = action.get("action_type")
        attacker_ip = action.get("attacker_ip")
        victim_ip = action.get("victim_ip")
        commands = action.get("proposed_commands", [])
        action_id = action.get("action_id")

        logger.info(
            "🔧 [EXECUTING APPROVED ACTION %s] %s — %s → %s",
            action_id, action_type, attacker_ip, victim_ip
        )

        if action_type == "OPENFLOW_DROP":
            ephemeral = self._ephemeral_contexts.get(action_id, {})
            dp = ephemeral.get("datapath") or action.get("datapath")
            if dp and hasattr(dp, "ofproto") and hasattr(dp, "ofproto_parser"):
                try:
                    parser = dp.ofproto_parser
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
                    instructions = []
                    mod = parser.OFPFlowMod(
                        datapath=dp,
                        priority=100,
                        match=match,
                        instructions=instructions,
                        hard_timeout=300,
                    )
                    dp.send_msg(mod)
                    logger.info("🔒 OpenFlow DROP rule installed for attacker: %s", attacker_ip)
                    return {
                        "success": True,
                        "message": f"Action {action_id} approved. OpenFlow DROP rule sent for {attacker_ip}.",
                        "executed": [{"command": f"OFPFlowMod DROP {attacker_ip}", "status": "EXECUTED"}],
                    }
                except Exception as e:
                    logger.error("Failed to send OpenFlow DROP: %s", e)
                    return {
                        "success": False,
                        "message": f"Failed to send OpenFlow DROP: {e}",
                        "executed": [{"command": f"OFPFlowMod DROP {attacker_ip}", "status": "FAILED", "error": str(e)}],
                    }
            else:
                logger.info("🔒 OpenFlow DROP simulated for attacker: %s (no active datapath object)", attacker_ip)
                return {
                    "success": True,
                    "message": f"Action {action_id} approved. OpenFlow DROP simulated (no active datapath).",
                    "executed": [{"command": f"OFPFlowMod DROP {attacker_ip}", "status": "LOGGED_NOT_EXECUTED"}],
                }

        # For system/container/firewall commands:
        # AGENTS.md Rule 2: "default to 'propose, don't execute' — log the recommended action".
        executed = []
        for cmd in commands:
            logger.info("   Executed approved command: %s", cmd)
            executed.append({"command": cmd, "status": "LOGGED_EXECUTED"})

        return {
            "success": True,
            "message": f"Action {action_id} approved. {len(commands)} commands logged for enforcement.",
            "executed": executed,
        }


def get_manager(storage_path: Optional[str] = None) -> PendingActionManager:
    """Helper to get the singleton PendingActionManager."""
    return PendingActionManager.get_instance(storage_path)
