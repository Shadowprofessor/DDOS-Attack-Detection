# -*- coding: utf-8 -*-
"""
OpenRouter Nemotron AI Threat Analyzer & Agent Orchestration Layer.

Uses multi-turn reasoning and structured output to analyze DDoS attack telemetry
from BOTH the Ryu/SDN controller and the FastAPI scoring service.

Ensemble Context Integration:
Incorporates per_model_breakdown (RF, XGBoost, SequenceClassifier) into alert triage
prompts to provide calibrated multi-model consensus context to the LLM agent.

SAFETY INVARIANT: This module NEVER executes mitigation commands directly. All proposed
actions are written to the unified pending-actions store (PendingActionManager) and
require explicit human approval via approve_action() before execution.
"""
import os
import sys
import json
import time
import logging
import threading
from typing import List, Dict, Optional, Tuple, Any

logger = logging.getLogger("NemotronAgent")

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


def _propose_action(
    action_type: str,
    attacker_ip: str,
    victim_ip: str,
    reason: str,
    confidence: Optional[float] = None,
    commands: Optional[list] = None,
    source: str = "nemotron_agent",
    datapath=None,
) -> str:
    """
    Write a proposed mitigation action to the SINGLE unified pending-actions store.
    Does NOT execute anything — only logs the proposal with auto_execute=False.
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


def summarize_ensemble_consensus(breakdown: Optional[dict]) -> dict:
    """
    Categorize model agreement across the ensemble's per_model_breakdown.

    Respects the Prompt 5d weight cap where tabular models (RF+XGB) carry 85%
    of decision weight and SequenceClassifier carries at most 15% (unverified).

    Taxonomy:
      - NO_BREAKDOWN: Telemetry lacks per-model breakdown (legacy or SDN source).
      - SINGLE_MODEL: Only 1 model active (e.g. xgb_only live default).
      - TABULAR_UNANIMOUS: RF and XGB agree (SequenceClassifier inactive).
      - FULL_UNANIMOUS: RF, XGB, and SequenceClassifier all agree (3/3 models).
      - TABULAR_UNANIMOUS_SEQUENCE_DISSENT: RF+XGB agree on attack, SequenceClassifier dissents.
          Respects weight cap: does NOT downgrade to SPLIT or MAJORITY.
      - TABULAR_SPLIT: RF and XGB disagree on attack vector (SequenceClassifier inactive).
      - TABULAR_SPLIT_SEQUENCE_TIEBREAK: RF and XGB disagree, SequenceClassifier aligns with one.
      - FULL_SPLIT: All 3 models predict divergent classes.
    """
    if not breakdown or not isinstance(breakdown, dict):
        return {
            "status": "NO_BREAKDOWN",
            "summary": "No ensemble breakdown provided (single-source alert telemetry).",
            "details": {},
            "active_models": [],
        }

    rf_entry = breakdown.get("random_forest")
    xgb_entry = breakdown.get("xgboost")
    seq_entry = breakdown.get("sequence_classifier")

    rf_active = bool(rf_entry and isinstance(rf_entry, dict) and "label" in rf_entry)
    xgb_active = bool(xgb_entry and isinstance(xgb_entry, dict) and "label" in xgb_entry)
    seq_active = bool(
        seq_entry
        and isinstance(seq_entry, dict)
        and seq_entry.get("active") is True
        and "label" in seq_entry
    )

    active_models = []
    if rf_active:
        active_models.append("random_forest")
    if xgb_active:
        active_models.append("xgboost")
    if seq_active:
        active_models.append("sequence_classifier")

    # 1. Single-model active case (e.g. xgb_only live path)
    if len(active_models) <= 1:
        single_name = active_models[0] if active_models else "unknown"
        if single_name == "xgboost":
            lbl = xgb_entry.get("label", "Unknown")
            conf = float(xgb_entry.get("confidence", 0.0))
        elif single_name == "random_forest":
            lbl = rf_entry.get("label", "Unknown")
            conf = float(rf_entry.get("confidence", 0.0))
        elif single_name == "sequence_classifier":
            lbl = seq_entry.get("label", "Unknown")
            conf = float(seq_entry.get("confidence", 0.0))
        else:
            lbl = "Unknown"
            conf = 0.0

        return {
            "status": "SINGLE_MODEL",
            "summary": f"Single model active ({single_name}): {lbl} (conf: {conf:.2f}).",
            "active_models": active_models,
            "details": {
                "active_model": single_name,
                "label": lbl,
                "confidence": conf,
            },
        }

    rf_label = rf_entry.get("label") if rf_active else None
    xgb_label = xgb_entry.get("label") if xgb_active else None
    rf_conf = float(rf_entry.get("confidence", 0.0)) if rf_active else 0.0
    xgb_conf = float(xgb_entry.get("confidence", 0.0)) if xgb_active else 0.0

    tabular_both = rf_active and xgb_active
    tabular_agree = tabular_both and (rf_label == xgb_label)

    # 2. Tabular-only active (sequence classifier inactive)
    if tabular_both and not seq_active:
        if tabular_agree:
            return {
                "status": "TABULAR_UNANIMOUS",
                "summary": f"Tabular models agree: {rf_label} (RF={rf_conf:.2f}, XGB={xgb_conf:.2f}).",
                "active_models": active_models,
                "details": {
                    "rf": {"label": rf_label, "confidence": rf_conf},
                    "xgb": {"label": xgb_label, "confidence": xgb_conf},
                },
            }
        else:
            return {
                "status": "TABULAR_SPLIT",
                "summary": f"Tabular models split: RF={rf_label} ({rf_conf:.2f}) vs XGB={xgb_label} ({xgb_conf:.2f}).",
                "active_models": active_models,
                "details": {
                    "rf": {"label": rf_label, "confidence": rf_conf},
                    "xgb": {"label": xgb_label, "confidence": xgb_conf},
                },
            }

    # 3. All 3 models active (RF + XGB + SequenceClassifier)
    seq_label = seq_entry.get("label")
    seq_conf = float(seq_entry.get("confidence", 0.0))
    caveat = seq_entry.get(
        "caveat",
        "Trained on synthetic pseudo-temporal windows; unverified on real packet sequences",
    )

    details = {
        "rf": {"label": rf_label, "confidence": rf_conf},
        "xgb": {"label": xgb_label, "confidence": xgb_conf},
        "sequence": {"label": seq_label, "confidence": seq_conf, "caveat": caveat},
    }

    if tabular_agree:
        if seq_label == rf_label:
            return {
                "status": "FULL_UNANIMOUS",
                "summary": (
                    f"Full unanimous consensus across all 3 models on {rf_label} "
                    f"(RF={rf_conf:.2f}, XGB={xgb_conf:.2f}, LSTM={seq_conf:.2f})."
                ),
                "active_models": active_models,
                "details": details,
            }
        else:
            # Condition 1: Respect weight cap (RF+XGB carry 85%).
            # Do NOT downgrade to SPLIT or MAJORITY.
            return {
                "status": "TABULAR_UNANIMOUS_SEQUENCE_DISSENT",
                "summary": (
                    f"Tabular unanimous on {rf_label} (RF={rf_conf:.2f}, XGB={xgb_conf:.2f}) "
                    f"with Sequence Classifier dissenting on {seq_label} ({seq_conf:.2f}). "
                    f"Note: Tabular models carry 85% decision weight; sequence model is unverified."
                ),
                "active_models": active_models,
                "details": details,
            }

    # Tabular models disagree
    if seq_label in (rf_label, xgb_label):
        aligned_with = "RF" if seq_label == rf_label else "XGB"
        return {
            "status": "TABULAR_SPLIT_SEQUENCE_TIEBREAK",
            "summary": (
                f"Tabular models split (RF={rf_label}, XGB={xgb_label}); "
                f"Sequence Classifier aligns with {aligned_with} on {seq_label} ({seq_conf:.2f})."
            ),
            "active_models": active_models,
            "details": details,
        }

    return {
        "status": "FULL_SPLIT",
        "summary": (
            f"Complete split across all 3 models: "
            f"RF={rf_label} ({rf_conf:.2f}), XGB={xgb_label} ({xgb_conf:.2f}), LSTM={seq_label} ({seq_conf:.2f})."
        ),
        "active_models": active_models,
        "details": details,
    }


class NemotronAgent:
    """
    OpenRouter Nemotron AI Threat Analyzer & Agent Orchestration Layer.

    Supports dual alert ingestion (Ryu SDN controller & FastAPI scoring API),
    thread-safe alert batching with auto-flush triggers and payload chunking,
    OpenRouter Nemotron 3 Ultra reasoning with multi-model ensemble context,
    and graceful degraded mode fallback.

    NOTE ON DEGRADED MODE:
    The heuristic fallback provides safe, deterministic, template-based mitigation
    proposals that match Nemotron's proposed ACTION in common cases, but does NOT
    match its reasoning depth or multi-step threat explanation. Degraded mode is
    a safe fallback ensuring 100% action queueing and continuous system availability.
    """

    MAX_BUFFER_SIZE = 100      # Auto-flush trigger threshold
    MAX_LLM_BATCH_SIZE = 20    # Max alerts per single Nemotron API payload

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        confidence_threshold: float = 0.7,
        chunk_delay: float = 0.1,
    ):
        self.api_key = api_key or os.environ.get("OPENROUTER_API_KEY")
        if not self.api_key:
            logger.warning(
                "[DEGRADED MODE ACTIVE] OPENROUTER_API_KEY not set. "
                "Nemotron LLM analysis will use rule-based fallback."
            )
        self.model = model or os.environ.get(
            "OPENROUTER_MODEL", "nvidia/nemotron-3-ultra-550b-a55b:free"
        )
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
        breakdown = raw_alert.get("per_model_breakdown")
        consensus = summarize_ensemble_consensus(breakdown)

        # Extract feature completeness and degradation metadata
        comp = raw_alert.get("feature_completeness")
        if comp is None and isinstance(breakdown, dict):
            comp = breakdown.get("feature_completeness")
        try:
            comp_float = float(comp) if comp is not None else 1.0
        except (ValueError, TypeError):
            comp_float = 1.0

        degraded = raw_alert.get("degraded_confidence")
        if degraded is None and isinstance(breakdown, dict):
            degraded = breakdown.get("degraded_confidence")
        degraded_bool = bool(degraded) if degraded is not None else (comp_float < 1.0)

        deg_reason = raw_alert.get("degradation_reason")
        if deg_reason is None and isinstance(breakdown, dict):
            deg_reason = breakdown.get("degradation_reason")

        return {
            "attacker_ip": str(attacker_ip),
            "victim_ip": str(victim_ip),
            "attack_type": str(attack_type),
            "confidence": conf_float,
            "packet_count": raw_alert.get("packet_count", 0),
            "continuous_pings": raw_alert.get("continuous_pings", 0),
            "source": str(source),
            "per_model_breakdown": breakdown,
            "ensemble_consensus": consensus,
            "feature_completeness": comp_float,
            "degraded_confidence": degraded_bool,
            "degradation_reason": deg_reason,
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
            "Ingested high-confidence alert [%s]: %s -> %s (conf: %.2f, consensus: %s)",
            norm["source"],
            norm["attacker_ip"],
            norm["victim_ip"],
            norm["confidence"],
            norm["ensemble_consensus"].get("status", "NO_BREAKDOWN"),
        )

        if should_flush:
            logger.info(
                "Buffer limit reached (%d alerts). Triggering auto-flush.",
                self.MAX_BUFFER_SIZE,
            )
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
        for i in range(0, len(batch), self.MAX_LLM_BATCH_SIZE):
            chunk = batch[i:i + self.MAX_LLM_BATCH_SIZE]
            results.extend(self.analyze_batch_and_propose(chunk))

        return results

    def _call_nemotron_api(self, prompt: str) -> Tuple[Optional[dict], str]:
        """
        Call Nemotron 3 Ultra via OpenRouter and parse structured JSON response.
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
                "and multi-model ensemble consensus context, and return ONLY valid JSON with keys: "
                "\"explanation\", \"attack_type_guess\", \"severity\", \"proposed_action\", \"requires_human_approval\".\n\n"
                "ENSEMBLE CONSENSUS REASONING GUIDELINES:\n"
                "1. FULL_UNANIMOUS / TABULAR_UNANIMOUS: Highest confidence signature. Raise blast-radius urgency; "
                "recommend decisive mitigation.\n"
                "2. TABULAR_UNANIMOUS_SEQUENCE_DISSENT: Tabular models (RF+XGB) carry 85% decision weight and agree; "
                "treat as high-confidence tabular attack, but examine if sequence dissent indicates atypical flow dynamics. "
                "Do NOT downgrade to a low-confidence split or majority vote.\n"
                "3. TABULAR_SPLIT / FULL_SPLIT: Tabular models disagree; treat with caution, reduce blast-radius severity, "
                "favor rate-limiting or targeted inspection over broad blocking.\n"
                "4. SINGLE_MODEL: Base confidence purely on the single model's reported confidence.\n"
                "5. The value of \"requires_human_approval\" MUST ALWAYS be true.\n"
                "6. INPUT DEGRADATION (feature_completeness < 1.0): Backward features may be zero-filled depending on capture mode. "
                "Evaluate if the attack signature relies on bidirectional response patterns; favor rate-limiting or canary validation "
                "over immediate total null-routing if confidence is distorted by asymmetric visibility."
            )
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_instruction},
                    {"role": "user", "content": prompt},
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

        for i in range(0, len(alert_batch), self.MAX_LLM_BATCH_SIZE):
            if i > 0 and self.chunk_delay > 0:
                time.sleep(self.chunk_delay)

            chunk = alert_batch[i:i + self.MAX_LLM_BATCH_SIZE]

            alert_summaries = []
            for idx, alert in enumerate(chunk, 1):
                consensus = alert.get("ensemble_consensus", {})
                status = consensus.get("status", "NO_BREAKDOWN")
                summary = consensus.get("summary", "No breakdown available")
                details = consensus.get("details", {})

                lines = [
                    f"[{idx}] Source: {alert['source']} | Attacker: {alert['attacker_ip']} -> Victim: {alert['victim_ip']} | "
                    f"Vector: {alert['attack_type']} | Aggregated Confidence: {alert['confidence']:.2f}",
                    f"    Consensus Tier: {status}",
                    f"    Consensus Summary: {summary}",
                ]

                # Format individual model predictions if present
                rf = details.get("rf")
                xgb = details.get("xgb")
                seq = details.get("sequence")
                model_parts = []
                if rf:
                    model_parts.append(f"RF={rf['label']} ({rf['confidence']:.2f})")
                if xgb:
                    model_parts.append(f"XGB={xgb['label']} ({xgb['confidence']:.2f})")
                if seq:
                    caveat_note = " [synthetic windowing caveat]" if seq.get("caveat") else ""
                    model_parts.append(f"LSTM={seq['label']} ({seq['confidence']:.2f}){caveat_note}")
                if model_parts:
                    lines.append(f"    Per-Model Predictions: {', '.join(model_parts)}")

                if alert.get("degraded_confidence"):
                    comp_f = alert.get("feature_completeness", 1.0)
                    deg_r = alert.get("degradation_reason") or "unobserved features"
                    lines.append(
                        f"    ⚠️ Input Degradation: Feature completeness is {comp_f:.2f} ({deg_r}). "
                        f"Evaluate possibility of evasion or distorted asymmetric flood dynamics."
                    )

                alert_summaries.append("\n".join(lines))

            prompt = (
                f"Batch Telemetry ({len(chunk)} high-confidence alerts with ensemble multi-model reasoning context):\n"
                + "\n".join(alert_summaries)
                + "\n\nFormulate mitigation proposals taking into account multi-model consensus agreement/disagreement and blast-radius urgency."
            )

            parsed_json, raw_text = self._call_nemotron_api(prompt)

            for alert in chunk:
                attacker_ip = alert["attacker_ip"]
                victim_ip = alert["victim_ip"]
                attack_type = alert["attack_type"]
                conf = alert["confidence"]
                consensus = alert.get("ensemble_consensus", {})
                consensus_status = consensus.get("status", "NO_BREAKDOWN")

                if parsed_json:
                    explanation = str(parsed_json.get("explanation", raw_text))
                    attack_type_guess = str(parsed_json.get("attack_type_guess", attack_type))
                    severity = str(parsed_json.get("severity", "HIGH"))
                    proposed_act = str(parsed_json.get("proposed_action", f"Block IP {attacker_ip}"))
                else:
                    # -------------------------------------------------------------
                    # Degraded / heuristic mode fallback
                    # -------------------------------------------------------------
                    if consensus_status == "SINGLE_MODEL":
                        # Condition 2: Base severity purely on that model's own confidence
                        # (no consensus adjustment up or down)
                        if conf >= 0.85:
                            severity = "HIGH"
                        elif conf >= 0.70:
                            severity = "MEDIUM"
                        else:
                            severity = "LOW"
                        explanation = (
                            f"Degraded mode (heuristic fallback, single-model): {attack_type} detected from {attacker_ip} "
                            f"targeting {victim_ip} (model confidence: {conf:.2f})."
                        )
                    elif consensus_status in ("FULL_UNANIMOUS", "TABULAR_UNANIMOUS"):
                        severity = "CRITICAL" if conf >= 0.90 else "HIGH"
                        explanation = (
                            f"Degraded mode (heuristic fallback, unanimous consensus): High-confidence {attack_type} attack "
                            f"detected from {attacker_ip} targeting {victim_ip} with model consensus (confidence: {conf:.2f})."
                        )
                    elif consensus_status == "TABULAR_UNANIMOUS_SEQUENCE_DISSENT":
                        # Condition 1: Tabular agreement is sufficient for high-confidence tier
                        severity = "HIGH" if conf >= 0.80 else "MEDIUM"
                        seq_details = consensus.get("details", {}).get("sequence", {})
                        seq_lbl = seq_details.get("label", "unknown")
                        explanation = (
                            f"Degraded mode (heuristic fallback, tabular unanimous with sequence dissent): High-confidence {attack_type} attack "
                            f"confirmed by tabular models (85% weight) from {attacker_ip} targeting {victim_ip} (confidence: {conf:.2f}). "
                            f"Sequence classifier flagged {seq_lbl} (unverified synthetic context)."
                        )
                    elif consensus_status in ("TABULAR_SPLIT", "FULL_SPLIT"):
                        severity = "MEDIUM" if conf >= 0.75 else "LOW"
                        explanation = (
                            f"Degraded mode (heuristic fallback, model disagreement): Potential {attack_type} attack detected "
                            f"from {attacker_ip} targeting {victim_ip} with split model predictions (confidence: {conf:.2f})."
                        )
                    elif consensus_status == "TABULAR_SPLIT_SEQUENCE_TIEBREAK":
                        severity = "MEDIUM"
                        explanation = (
                            f"Degraded mode (heuristic fallback, split with sequence tiebreak): Attack detected from {attacker_ip} "
                            f"targeting {victim_ip} with split tabular models and sequence alignment (confidence: {conf:.2f})."
                        )
                    else:
                        # NO_BREAKDOWN (legacy / direct SDN alerts)
                        severity = "HIGH" if conf >= 0.85 else "MEDIUM"
                        explanation = (
                            f"Degraded mode (heuristic fallback): High-confidence DDoS attack ({attack_type}) "
                            f"detected from {attacker_ip} targeting {victim_ip} (confidence: {conf:.2f})."
                        )

                    attack_type_guess = attack_type
                    proposed_act = f"Block attacker IP {attacker_ip} via iptables and SDN drop."

                    if alert.get("degraded_confidence"):
                        explanation = f"[DEGRADED INPUT] {explanation}"
                        if severity == "CRITICAL":
                            severity = "HIGH"

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
                    source=f"nemotron_agent ({alert['source']})",
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
                    "consensus_status": consensus_status,
                    "feature_completeness": alert.get("feature_completeness", 1.0),
                    "degraded_confidence": alert.get("degraded_confidence", False),
                    "degradation_reason": alert.get("degradation_reason"),
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


# Alias AIThreatAnalyzer to NemotronAgent for backward compatibility
AIThreatAnalyzer = NemotronAgent
