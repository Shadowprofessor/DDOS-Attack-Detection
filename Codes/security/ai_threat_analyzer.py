# -*- coding: utf-8 -*-
"""
OpenRouter Nemotron AI Threat Analyzer & Agent Orchestration Layer.

Uses multi-turn reasoning and structured output to analyze DDoS attack telemetry
from BOTH the Ryu/SDN controller and the FastAPI scoring service.

SAFETY: This module NEVER executes mitigation commands directly. All proposed
actions are written to the unified pending-actions store and require explicit
human approval via approve_action() before execution.
"""
import os
import sys
import json
import time
import uuid
import logging
import threading
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger("AIThreatAnalyzer")

# Ensure repository root is in sys.path
_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from src.mitigation.manager import get_manager, PendingActionManager

_manager = get_manager()
_pending_actions_lock = _manager._lock
_pending_actions = _manager._pending_actions
_action_log = _manager._action_log


def _safe_print(text):
    try:
        sys.stdout.write(str(text) + "\n")
        sys.stdout.flush()
    except Exception:
        pass


def get_pending_actions() -> Dict[str, dict]:
    """Return all pending (unapproved) actions from the unified manager."""
    return get_manager().get_pending()


def get_action(action_id: str) -> Optional[dict]:
    """Return a single action by ID from the unified manager."""
    return get_manager().get_action(action_id)


def get_action_log() -> List[dict]:
    """Return the full chronological action log from the unified manager."""
    return get_manager().get_action_log()


def approve_action(action_id: str) -> Tuple[bool, str]:
    """
    Approve and execute a pending mitigation action.
    Routes through PendingActionManager.
    """
    success, msg, _ = get_manager().approve(action_id, approver="human_operator")
    return success, msg


def reject_action(action_id: str) -> Tuple[bool, str]:
    """Reject a pending action (do not execute) via PendingActionManager."""
    success, msg, _ = get_manager().reject(action_id, reason="", rejecter="human_operator")
    return success, msg


def _propose_action(action_type: str, attacker_ip: str, victim_ip: str, reason: str,
                    confidence: Optional[float] = None, commands: Optional[list] = None,
                    source: str = "ai_threat_analyzer", datapath=None) -> str:
    """
    Write a proposed mitigation action to the SINGLE unified pending-actions store.
    Does NOT execute anything — only logs the proposal.
    """
    return get_manager().propose(
        action_type=action_type,
        attacker_ip=attacker_ip,
        victim_ip=victim_ip,
        reason=reason,
        confidence=confidence,
        commands=commands,
        source=source,
        datapath=datapath,
    )


def _execute_approved_action(action: dict) -> dict:
    """Execute a previously-approved action. ONLY called from approve_action()."""
    return get_manager()._execute_action(action)




class AIThreatAnalyzer:
    """
    OpenRouter Nemotron AI Threat Analyzer & Agent Orchestration Layer.

    Supports dual alert ingestion (Ryu SDN controller & FastAPI scoring API),
    thread-safe alert batching with auto-flush triggers and payload chunking,
    OpenRouter Nemotron 3 Ultra reasoning, and graceful degraded mode fallback.

    NOTE ON DEGRADED MODE:
    The heuristic fallback provides safe, deterministic, template-based mitigation
    proposals that match Nemotron's proposed ACTION in common cases, but does NOT
    match its reasoning depth, multi-step threat explanation, or ability to handle
    novel or ambiguous attack vectors. Degraded mode is a safe fallback ensuring
    continuous system availability and 100% action queueing, not an equivalent
    reasoning mode.
    """

    MAX_BUFFER_SIZE = 100      # Auto-flush trigger threshold
    MAX_LLM_BATCH_SIZE = 20    # Max alerts per single Nemotron API payload

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None,
                 confidence_threshold: float = 0.7, chunk_delay: float = 0.1):
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
        if not self.api_key:
            logger.warning(
                "[DEGRADED MODE ACTIVE] OPENROUTER_API_KEY not set. "
                "Nemotron LLM analysis will use rule-based fallback."
            )
        self.model = model or os.environ.get("OPENROUTER_MODEL", "nvidia/nemotron-3-ultra-550b-a55b:free")
        self.api_url = "https://openrouter.ai/api/v1/chat/completions"
        self.confidence_threshold = confidence_threshold
        self.chunk_delay = chunk_delay
        self._alert_buffer: List[dict] = []
        self._buffer_lock = threading.Lock()

    def normalize_alert(self, raw_alert: dict) -> dict:
        """Normalize alert telemetry from SDN controller or Scoring API into a canonical dict."""
        attacker_ip = raw_alert.get("attacker_ip") or raw_alert.get("src_ip") or "Unknown"
        victim_ip = raw_alert.get("victim_ip") or raw_alert.get("dst_ip") or "Unknown"
        attack_type = raw_alert.get("attack_type") or raw_alert.get("attack_family") or "Generic DDoS"

        conf = raw_alert.get("confidence")
        if conf is None:
            conf = raw_alert.get("attack_family_confidence", 1.0)
        try:
            conf_float = float(conf) if conf is not None else 1.0
        except (ValueError, TypeError):
            conf_float = 1.0

        source = raw_alert.get("source", "unknown_source")

        return {
            "attacker_ip": str(attacker_ip),
            "victim_ip": str(victim_ip),
            "attack_type": str(attack_type),
            "confidence": conf_float,
            "packet_count": raw_alert.get("packet_count", 0),
            "continuous_pings": raw_alert.get("continuous_pings", 0),
            "source": str(source),
            "raw_alert": raw_alert,
        }

    def ingest_alert(self, alert_data: dict) -> bool:
        """
        Ingest an alert from either source (SDN controller or Scoring API).
        Buffers high-confidence alerts (confidence >= confidence_threshold).
        Auto-flushes when buffer hits MAX_BUFFER_SIZE (100).
        """
        norm = self.normalize_alert(alert_data)
        if norm["confidence"] < self.confidence_threshold:
            logger.info(
                "Alert dropped below confidence threshold (%.2f < %.2f) for %s",
                norm["confidence"], self.confidence_threshold, norm["attacker_ip"]
            )
            return False

        should_flush = False
        with self._buffer_lock:
            self._alert_buffer.append(norm)
            if len(self._alert_buffer) >= self.MAX_BUFFER_SIZE:
                should_flush = True

        logger.info(
            "Ingested high-confidence alert [%s]: %s -> %s (conf: %.2f)",
            norm["source"], norm["attacker_ip"], norm["victim_ip"], norm["confidence"]
        )

        if should_flush:
            logger.info("Buffer limit reached (%d alerts). Triggering auto-flush.", self.MAX_BUFFER_SIZE)
            self.flush_and_analyze()

        return True

    def flush_and_analyze(self) -> List[dict]:
        """Process all buffered high-confidence alerts, chunking into MAX_LLM_BATCH_SIZE batches."""
        with self._buffer_lock:
            if not self._alert_buffer:
                return []
            batch = list(self._alert_buffer)
            self._alert_buffer.clear()

        results = []
        # Chunk large buffers to prevent oversized API payloads
        for i in range(0, len(batch), self.MAX_LLM_BATCH_SIZE):
            chunk = batch[i:i + self.MAX_LLM_BATCH_SIZE]
            results.extend(self.analyze_batch_and_propose(chunk))

        return results

    def _call_nemotron_api(self, prompt: str) -> Tuple[Optional[dict], str]:
        """
        Call Nemotron 3 Ultra via OpenRouter and parse structured JSON response.
        Distinguishes between invalid model errors vs temporary network errors.
        Returns (parsed_dict, raw_text).
        """
        if not self.api_key:
            logger.warning("[DEGRADED MODE ACTIVE] OPENROUTER_API_KEY missing. Skipping API call.")
            return None, "Degraded mode (no API key set)"

        try:
            import requests

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
            system_instruction = (
                "You are an expert DDoS threat analyst. Analyze the provided attack telemetry "
                "and return ONLY valid JSON with keys: \"explanation\", \"attack_type_guess\", "
                "\"severity\", \"proposed_action\", \"requires_human_approval\". "
                "The value of \"requires_human_approval\" MUST ALWAYS be true."
            )
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_instruction},
                    {"role": "user", "content": prompt}
                ],
                "reasoning": {"enabled": True},
            }

            resp = requests.post(self.api_url, headers=headers, data=json.dumps(payload), timeout=15)
            if resp.status_code in (400, 404) and ("model" in resp.text.lower() or "not found" in resp.text.lower()):
                logger.error(
                    "❌ [INVALID MODEL CONFIGURATION ERROR] Model '%s' does not exist or is invalid on OpenRouter. "
                    "HTTP %d: %s",
                    self.model, resp.status_code, resp.text[:200]
                )
                return None, f"Invalid model error HTTP {resp.status_code}"

            if resp.status_code != 200:
                logger.warning(
                    "[DEGRADED MODE ACTIVE] OpenRouter Nemotron API temporarily unreachable. HTTP %d: %s. Using heuristic fallback.",
                    resp.status_code, resp.text[:200]
                )
                return None, f"HTTP error {resp.status_code}"

            data = resp.json()
            if "choices" in data and len(data["choices"]) > 0:
                content = data["choices"][0]["message"].get("content", "")
                try:
                    clean_content = content.strip()
                    if "```" in clean_content:
                        parts = clean_content.split("```")
                        for part in parts:
                            part_clean = part.strip()
                            if part_clean.startswith("json"):
                                part_clean = part_clean[4:].strip()
                            if part_clean.startswith("{") and part_clean.endswith("}"):
                                clean_content = part_clean
                                break

                    parsed = json.loads(clean_content)
                    if isinstance(parsed, dict):
                        return parsed, content
                except Exception as parse_err:
                    logger.warning(
                        "[DEGRADED MODE ACTIVE] Could not parse JSON from Nemotron response (%s). Content snippet: %s",
                        parse_err, content[:100]
                    )
                    return None, content

            return None, "Empty choice response from API"

        except Exception as e:
            logger.warning(
                "[DEGRADED MODE ACTIVE] Nemotron API call failed or timed out: %s. Using heuristic fallback.",
                e
            )
            return None, f"Exception: {e}"

    def analyze_batch_and_propose(self, alert_batch: List[dict]) -> List[dict]:
        """Analyze a list of normalized alerts in batched LLM calls (up to MAX_LLM_BATCH_SIZE alerts per call)."""
        results = []
        if not alert_batch:
            return results

        # Chunk into sub-batches of max MAX_LLM_BATCH_SIZE (20)
        for i in range(0, len(alert_batch), self.MAX_LLM_BATCH_SIZE):
            if i > 0 and self.chunk_delay > 0:
                time.sleep(self.chunk_delay)

            chunk = alert_batch[i:i + self.MAX_LLM_BATCH_SIZE]

            alert_summaries = []
            for idx, alert in enumerate(chunk, 1):
                alert_summaries.append(
                    f"[{idx}] Source: {alert['source']} | Attacker: {alert['attacker_ip']} -> Victim: {alert['victim_ip']} | "
                    f"Vector: {alert['attack_type']} | Confidence: {alert['confidence']:.2f}"
                )
            prompt = (
                f"Batch Telemetry ({len(chunk)} high-confidence alerts):\n" + "\n".join(alert_summaries) + "\n"
                "Formulate mitigation proposals for these attack flows."
            )

            parsed_json, raw_text = self._call_nemotron_api(prompt)

            for alert in chunk:
                attacker_ip = alert["attacker_ip"]
                victim_ip = alert["victim_ip"]
                attack_type = alert["attack_type"]
                conf = alert["confidence"]

                if parsed_json:
                    explanation = str(parsed_json.get("explanation", raw_text))
                    attack_type_guess = str(parsed_json.get("attack_type_guess", attack_type))
                    severity = str(parsed_json.get("severity", "HIGH"))
                    proposed_act = str(parsed_json.get("proposed_action", f"Block IP {attacker_ip}"))
                else:
                    # Degraded / heuristic mode fallback
                    explanation = (
                        f"Degraded mode (heuristic fallback): High-confidence DDoS attack ({attack_type}) "
                        f"detected from {attacker_ip} targeting {victim_ip} (confidence: {conf:.2f})."
                    )
                    attack_type_guess = attack_type
                    severity = "HIGH" if conf > 0.85 else "MEDIUM"
                    proposed_act = f"Block attacker IP {attacker_ip} via iptables and SDN drop."

                proposed_commands = [
                    f"iptables -I INPUT -s {attacker_ip} -j DROP",
                    f"docker exec <container_id> iptables -A OUTPUT -d {victim_ip} -j DROP",
                ]

                action_id = _propose_action(
                    action_type="BLOCK_ATTACKER",
                    attacker_ip=attacker_ip,
                    victim_ip=victim_ip,
                    reason=f"Nemotron Analysis: {explanation}",
                    confidence=conf,
                    commands=proposed_commands,
                    source=f"ai_threat_analyzer ({alert['source']})",
                )

                # HARD RULE: requires_human_approval MUST ALWAYS BE TRUE.
                res_dict = {
                    "attacker_ip": attacker_ip,
                    "victim_ip": victim_ip,
                    "attack_type_guess": attack_type_guess,
                    "explanation": explanation,
                    "severity": severity,
                    "proposed_action": proposed_act,
                    "proposed_action_id": action_id,
                    "requires_human_approval": True,  # Hardcoded True
                    "status": "PROPOSED",
                }
                results.append(res_dict)

        return results

    def analyze_and_propose(self, attack_telemetry, container_info=None):
        """
        Analyze a single attack telemetry item and PROPOSE (not execute) mitigation.
        Delegates to batch pipeline for unified logic.
        """
        norm = self.normalize_alert(attack_telemetry)
        batch_res = self.analyze_batch_and_propose([norm])
        if batch_res:
            res = batch_res[0]
            res["ai_analysis"] = res["explanation"]
            return res
        return {
            "attacker_ip": norm["attacker_ip"],
            "victim_ip": norm["victim_ip"],
            "ai_analysis": "Low confidence alert skipped.",
            "proposed_action_id": None,
            "requires_human_approval": True,
            "status": "SKIPPED",
        }

    def analyze_and_prevent(self, attack_telemetry, container_info=None):
        """
        DEPRECATED: Use analyze_and_propose() instead.
        Delegates to analyze_and_propose() — does NOT execute any prevention commands.
        """
        logger.warning(
            "analyze_and_prevent() is deprecated — mitigation actions are now "
            "propose-only. Use analyze_and_propose() and approve_action()."
        )
        return self.analyze_and_propose(attack_telemetry, container_info)
