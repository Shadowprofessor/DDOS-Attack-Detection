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

from src.obs.logging import log_safe

from src.mitigation.lab_containment import clamp_ttl, cookie_for, is_lab_type, ovs_command, validate_target  # noqa: E402

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
        dossier: Optional[dict] = None,
        per_model_breakdown: Optional[dict] = None,
        consensus_tier: Optional[str] = None,
        ttl_s: Optional[int] = None,
    ) -> str:
        """
        Create and record a PROPOSED mitigation action.
        NEVER executes commands automatically.
        """
        lab = None
        if is_lab_type(action_type):  # v5.4.0 lab containment: refuse a bad target before it is even proposed
            ok, why = validate_target(action_type, attacker_ip)
            if not ok:
                raise ValueError(f"lab containment target refused: {why}")
            ttl_s = clamp_ttl(ttl_s)
            lab = {"state": "proposed", "ttl_s": ttl_s}
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
                "dossier": dossier or {},
                "per_model_breakdown": per_model_breakdown or {},
                "consensus_tier": consensus_tier,
            }
            if lab is not None:
                action["lab"] = lab
                action["ttl_s"] = lab["ttl_s"]
                action["proposed_commands"] = [ovs_command(action_type, attacker_ip, lab["ttl_s"], action_id)]

            if datapath is not None:
                self._ephemeral_contexts[action_id] = {"datapath": datapath}

            self._pending_actions[action_id] = action
            self._action_log.append(action)
            self._save_to_disk()

            logger.info(
                "📋 [PROPOSED ACTION %s] %s — %s → %s | Reason: %s | Status: PENDING (requires human approval)",
                action_id, log_safe(action_type), log_safe(attacker_ip), log_safe(victim_ip), log_safe(reason)
            )
            return action_id

    def update_campaign_telemetry(
        self,
        action_id: str,
        attacker_ip: Optional[str] = None,
        reason: Optional[str] = None,
        confidence: Optional[float] = None,
        dossier: Optional[dict] = None,
        per_model_breakdown: Optional[dict] = None,
        save: bool = True,
    ) -> bool:
        """
        Update live botnet scale and telemetry for an active pending campaign action.
        Never executes any commands or modifies approved/rejected status.
        """
        with self._lock:
            self._load_from_disk()
            action = self._pending_actions.get(action_id)
            if not action or action.get("status") != "PENDING":
                return False
            if attacker_ip:
                action["attacker_ip"] = attacker_ip
            if reason:
                action["reason"] = reason
            if confidence is not None:
                action["confidence"] = confidence
            if dossier:
                action["dossier"] = dossier
            if per_model_breakdown:
                action["per_model_breakdown"] = per_model_breakdown
            if save:
                self._save_to_disk()
            return True

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

    def get_active_blocklist(self) -> set[str]:
        """Return the set of attacker IPs that have EXECUTED (approved) mitigation actions.

        This is the authoritative active blocklist used by Layer 1 ingress fast-path
        interception. Only IPs with status == "EXECUTED" (human-approved) are included,
        never PENDING ones — preserving the human-in-the-loop invariant.
        """
        with self._lock:
            self._load_from_disk()
            return {
                action["attacker_ip"]
                for action in self._pending_actions.values()
                if action.get("status") == "EXECUTED" and not is_lab_type(action.get("action_type"))
            }  # lab actions are enforced on the Mininet switch, not by skipping scoring here

    def is_ip_blocked(self, ip: str) -> bool:
        """Check whether an IP has an EXECUTED (approved) mitigation action.

        Returns True only when the IP has an action with status == "EXECUTED".
        PENDING or REJECTED actions do NOT trigger this check, preserving the
        human-in-the-loop gate.
        """
        with self._lock:
            self._load_from_disk()
            for action in self._pending_actions.values():
                if (action.get("attacker_ip") == ip and action.get("status") == "EXECUTED"
                        and not is_lab_type(action.get("action_type"))):
                    return True
            return False

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

    def revert(self, action_id: str, actor: str = "human_operator", reason: str = "") -> Tuple[bool, str, Optional[dict]]:
        """
        Undo an EXECUTED (human-approved) action, e.g. on rollback-TTL expiry.

        Reverting only ever REMOVES a block; it can never create one, so it does not need a
        fresh approval. Only EXECUTED actions can be reverted. On success the status becomes
        ROLLED_BACK, which also drops the IP from the ingress blocklist.
        """
        with self._lock:
            self._load_from_disk()
            action = self._pending_actions.get(action_id)
            if not action:
                return False, f"Action {action_id} not found", None
            if action.get("status") != "EXECUTED":
                return False, f"Action {action_id} is {action.get('status')}, not EXECUTED", action

            result = self._revert_action(action)
            attempts = action.setdefault("revert_attempts", [])
            attempts.append({"ts": time.time(), "actor": actor, "success": result["success"],
                             "message": result.get("message", "")})
            if result["success"]:
                action["status"] = "ROLLED_BACK"
                action["rolled_back_at"] = time.time()
                action["rolled_back_by"] = actor
                if reason:
                    action["rollback_reason"] = reason
            self._save_to_disk()
            return result["success"], result.get("message", ""), action

    def _revert_action(self, action: dict) -> dict:
        """Enforcer-specific undo. ONLY invoked via revert()."""
        action_type = action.get("action_type")
        attacker_ip = action.get("attacker_ip")
        action_id = action.get("action_id")

        if is_lab_type(action_type):  # the lab enforcer removes the OVS rule (its hard_timeout also would)
            lab = action.setdefault("lab", {})
            lab.update(state="remove_requested", remove_requested_at=time.time())
            return {"success": True, "message": f"Removal of lab rule {action_id} queued for the lab enforcer."}

        if action_type == "OPENFLOW_DROP":
            dp = self._ephemeral_contexts.get(action_id, {}).get("datapath")
            if dp and hasattr(dp, "ofproto") and hasattr(dp, "ofproto_parser"):
                try:
                    parser = dp.ofproto_parser
                    match = parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
                    mod = parser.OFPFlowMod(
                        datapath=dp, command=dp.ofproto.OFPFC_DELETE, priority=100, match=match,
                        out_port=dp.ofproto.OFPP_ANY, out_group=dp.ofproto.OFPG_ANY,
                    )
                    dp.send_msg(mod)
                    return {"success": True, "message": f"OpenFlow DROP removed for {attacker_ip}."}
                except Exception as e:
                    logger.error("Failed to remove OpenFlow DROP for %s: %s", log_safe(attacker_ip), log_safe(e))
                    return {"success": False, "message": "OpenFlow flow delete failed"}
            # No live datapath (simulated, or the rule's hard_timeout already expired it).
            return {"success": True, "message": f"OpenFlow DROP removal simulated for {attacker_ip} (no active datapath)."}

        if action_type == "cloudflare_scrub":
            try:
                from src.mitigation.cloud_enforcers.cloudflare import CloudflareEnforcer
                ok, msg = CloudflareEnforcer().remove_scrubbing(attacker_ip)
                return {"success": ok, "message": msg}
            except Exception as e:
                logger.error("Cloudflare scrub removal failed: %s", log_safe(e))
                return {"success": False, "message": "Cloudflare scrub removal failed"}

        # Command-style actions are only logged on execute (see _execute_action), so the undo is
        # logged the same way.
        logger.info("Reverted approved action %s (%s) for %s", log_safe(action_id), log_safe(action_type), log_safe(attacker_ip))
        return {"success": True, "message": f"Action {action_id} reverted (logged)."}

    # ------------------------------------------------------------------ v5.4.0 lab enforcer hand-off
    def lab_queue(self) -> List[dict]:
        """Approved lab actions the enforcer still has to apply or remove (read-only view)."""
        with self._lock:
            self._load_from_disk()
            out, changed, now = [], False, time.time()
            for a in self._pending_actions.values():
                lab = a.get("lab") or {}
                if not is_lab_type(a.get("action_type")) or a.get("status") not in ("EXECUTED", "ROLLED_BACK"):
                    continue
                # v5.4.0 (live5): an approval is valid for its TTL only. Approved but never applied within it
                # (e.g. no enforcer running) -> expired_unapplied, never handed to a later enforcer.
                if lab.get("state") == "queued" and (a.get("approved_at") or now) + float(lab.get("ttl_s") or 300) < now:
                    lab.update(state="expired_unapplied", expired_unapplied_at=now)
                    lab.setdefault("log", []).append({"state": "expired_unapplied", "ts": now,
                                                      "detail": "approved but not applied within its TTL"})
                    changed = True
                    continue
                op = {"queued": "apply", "remove_requested": "remove"}.get(lab.get("state"))
                if op:
                    out.append({"action_id": a["action_id"], "op": op, "action_type": a["action_type"],
                                "target": a["attacker_ip"], "victim_ip": a.get("victim_ip"), "ttl_s": lab.get("ttl_s"),
                                "cookie": lab.get("cookie"), "approved_at": a.get("approved_at"),
                                "approver": a.get("approver")})
            if changed:
                self._save_to_disk()
            return out

    LAB_TRANSITIONS = {"queued": {"applied", "refused", "failed"},
                       "applied": {"expired", "removed"},
                       "remove_requested": {"removed", "expired", "failed"}}

    def record_lab_enforcement(self, action_id: str, state: str, detail: str = "",
                               ts: Optional[float] = None) -> Tuple[bool, str]:
        """The enforcer reports what it did. This records facts; it can never create or approve a block."""
        with self._lock:
            self._load_from_disk()
            a = self._pending_actions.get(action_id)
            if not a or not is_lab_type(a.get("action_type")):
                return False, "unknown lab action"
            lab = a.setdefault("lab", {})
            cur = lab.get("state")
            if state not in self.LAB_TRANSITIONS.get(cur, set()):
                return False, f"illegal lab state change {cur} -> {state}"
            lab["state"] = state
            lab[f"{state}_at"] = float(ts) if ts else time.time()
            lab.setdefault("log", []).append({"state": state, "ts": lab[f"{state}_at"], "detail": str(detail)[:300]})
            self._save_to_disk()
            return True, state

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

        if is_lab_type(action_type):
            # v5.4.0: nothing runs on this host. The approved rule is QUEUED; the lab enforcer (WSL2, root)
            # re-checks the target and installs it on the Mininet switch with hard_timeout = TTL.
            ok, why = validate_target(action_type, attacker_ip)
            if not ok:
                return {"success": False, "message": f"lab target refused at approval: {why}",
                        "executed": [{"command": c, "status": "REFUSED"} for c in commands]}
            # v6.0.0 (live6): a lab proposal is only valid for its TTL. An old proposal from an earlier run
            # (still PENDING on the Approvals page) must not block hosts in the next run.
            ttl = clamp_ttl(action.get("ttl_s") or (action.get("lab") or {}).get("ttl_s"))
            if action.get("proposed_at") and action["proposed_at"] + ttl < time.time():
                return {"success": False, "message": f"lab proposal is older than its TTL ({ttl} s); "
                        "propose it again from the incident if it is still needed",
                        "executed": [{"command": c, "status": "REFUSED_STALE"} for c in commands]}
            lab = action.setdefault("lab", {})
            lab.update(state="queued", queued_at=time.time(), ttl_s=clamp_ttl(action.get("ttl_s")),
                       cookie=hex(cookie_for(action_id)))
            return {"success": True, "message": f"Action {action_id} approved; queued for the lab enforcer ({why}).",
                    "executed": [{"command": c, "status": "QUEUED_FOR_LAB_ENFORCER"} for c in commands]}

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

        if action_type == "cloudflare_scrub":
            # Dispatch to CloudflareEnforcer.execute() for approved Cloudflare scrubbing actions
            try:
                from src.mitigation.cloud_enforcers.cloudflare import CloudflareEnforcer
                enforcer = CloudflareEnforcer()
                result = enforcer.execute(action)
                return result
            except ImportError as e:
                logger.error("CloudflareEnforcer not available: %s", e)
                return {
                    "success": False,
                    "message": f"CloudflareEnforcer module not available: {e}",
                    "executed": [{"command": "Cloudflare Magic Transit API call", "status": "FAILED", "error": str(e)}],
                }
            except Exception as e:
                logger.error("Failed to execute Cloudflare scrubbing action: %s", e)
                return {
                    "success": False,
                    "message": f"Cloudflare execution failed: {e}",
                    "executed": [{"command": "Cloudflare Magic Transit API call", "status": "FAILED", "error": str(e)}],
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
