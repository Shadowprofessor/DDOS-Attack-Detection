# -*- coding: utf-8 -*-
"""
Tests for Nemotron 3 Ultra Agent Orchestration Layer (Codes/security/ai_threat_analyzer.py).

Verifies:
- Dual alert source ingestion (Ryu SDN controller & FastAPI scoring API)
- Confidence threshold alert batching (drops < 0.7 confidence)
- OpenRouter API mock parsing (normal structured JSON)
- Malformed/unexpected LLM response handling
- Unreachable API / HTTP error fallback (degraded mode)
- Safety invariant: requires_human_approval MUST ALWAYS be True (even if LLM returns false)
- Single unified pending-actions queue routing
"""
import json
import pytest
from unittest.mock import MagicMock, patch
from Codes.security.ai_threat_analyzer import (
    AIThreatAnalyzer,
    get_pending_actions,
    approve_action,
    _pending_actions,
    _pending_actions_lock,
)
from src.mitigation.manager import get_manager

@pytest.fixture(autouse=True)
def clear_pending_actions_queue():
    """Clear the unified PendingActionManager before each test to prevent singleton leakage."""
    mgr = get_manager()
    mgr.clear()

def test_dual_source_alert_ingestion():
    analyzer = AIThreatAnalyzer(api_key="test-key", confidence_threshold=0.7)

    # 1. Alert from Ryu SDN Controller
    sdn_alert = {
        "attacker_ip": "10.0.0.5",
        "victim_ip": "10.0.0.1",
        "attack_type": "Syn Flood",
        "confidence": 0.95,
        "source": "ryu_sdn_controller",
    }
    assert analyzer.ingest_alert(sdn_alert) is True

    # 2. Alert from FastAPI Scoring Service
    api_alert = {
        "src_ip": "192.168.1.100",
        "dst_ip": "192.168.1.1",
        "attack_family": "Reflection-Amplification",
        "attack_family_confidence": 0.88,
        "source": "fastapi_scoring_service",
    }
    assert analyzer.ingest_alert(api_alert) is True

    assert len(analyzer._alert_buffer) == 2
    norm1 = analyzer._alert_buffer[0]
    norm2 = analyzer._alert_buffer[1]

    assert norm1["attacker_ip"] == "10.0.0.5"
    assert norm1["source"] == "ryu_sdn_controller"
    assert norm2["attacker_ip"] == "192.168.1.100"
    assert norm2["attack_type"] == "Reflection-Amplification"
    assert norm2["source"] == "fastapi_scoring_service"

def test_confidence_threshold_filtering():
    analyzer = AIThreatAnalyzer(api_key="test-key", confidence_threshold=0.7)

    # Alert below threshold (0.5 < 0.7) -> should be dropped
    low_conf_alert = {
        "attacker_ip": "10.0.0.9",
        "victim_ip": "10.0.0.1",
        "confidence": 0.50,
    }
    assert analyzer.ingest_alert(low_conf_alert) is False
    assert len(analyzer._alert_buffer) == 0

    # Alert at/above threshold (0.75 >= 0.7) -> should be buffered
    high_conf_alert = {
        "attacker_ip": "10.0.0.9",
        "victim_ip": "10.0.0.1",
        "confidence": 0.75,
    }
    assert analyzer.ingest_alert(high_conf_alert) is True
    assert len(analyzer._alert_buffer) == 1

@patch("requests.post")
def test_normal_nemotron_json_response(mock_post):
    """Test successful parsing of structured JSON response from Nemotron API."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": '{"explanation": "DNS reflection attack.", "attack_type_guess": "Reflection-Amplification", "severity": "HIGH", "proposed_action": "Block 10.0.0.5", "requires_human_approval": true}'
                }
            }
        ]
    }
    mock_post.return_value = mock_resp

    analyzer = AIThreatAnalyzer(api_key="mock-key")
    analyzer.ingest_alert({
        "attacker_ip": "10.0.0.5",
        "victim_ip": "10.0.0.1",
        "attack_type": "DNS",
        "confidence": 0.92,
        "source": "ryu_controller",
    })

    results = analyzer.flush_and_analyze()
    assert len(results) == 1
    res = results[0]

    assert res["attacker_ip"] == "10.0.0.5"
    assert res["explanation"] == "DNS reflection attack."
    assert res["severity"] == "HIGH"
    assert res["requires_human_approval"] is True

    # Verify action was proposed in the unified pending queue
    pending = get_pending_actions()
    assert len(pending) == 1
    action_id = res["proposed_action_id"]
    assert action_id in pending
    assert pending[action_id]["auto_execute"] is False

@patch("requests.post")
def test_malformed_json_response_handling(mock_post):
    """Test handling when Nemotron returns non-JSON or malformed text."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": "This is raw text analysis that is not valid JSON syntax."
                }
            }
        ]
    }
    mock_post.return_value = mock_resp

    analyzer = AIThreatAnalyzer(api_key="mock-key")
    alert = {"attacker_ip": "10.0.0.6", "victim_ip": "10.0.0.1", "confidence": 0.85}

    res = analyzer.analyze_and_propose(alert)
    assert res["requires_human_approval"] is True
    assert "Degraded mode" in res["explanation"]
    assert res["proposed_action_id"] is not None

@patch("requests.post")
def test_unreachable_api_degraded_fallback(mock_post):
    """Test graceful fallback when OpenRouter API throws exception or times out."""
    mock_post.side_effect = Exception("Connection refused / Timeout")

    analyzer = AIThreatAnalyzer(api_key="mock-key")
    alert = {"attacker_ip": "10.0.0.7", "victim_ip": "10.0.0.1", "confidence": 0.90}

    # Must NOT crash, must log degraded mode and return proposed action
    res = analyzer.analyze_and_propose(alert)
    assert res["requires_human_approval"] is True
    assert "Degraded mode" in res["explanation"]
    assert res["proposed_action_id"] is not None

    pending = get_pending_actions()
    assert len(pending) == 1

def test_missing_api_key_degraded_fallback():
    """Test degraded fallback when OPENROUTER_API_KEY is not set."""
    analyzer = AIThreatAnalyzer(api_key=None)
    assert analyzer.api_key is None

    alert = {"attacker_ip": "10.0.0.8", "victim_ip": "10.0.0.1", "confidence": 0.88}
    res = analyzer.analyze_and_propose(alert)

    assert res["requires_human_approval"] is True
    assert "Degraded mode" in res["explanation"]
    assert res["proposed_action_id"] is not None

@patch("requests.post")
def test_requires_human_approval_always_true(mock_post):
    """Safety Invariant: requires_human_approval MUST ALWAYS BE TRUE even if LLM returns false."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    # LLM attempt to bypass human approval by returning false
    mock_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": '{"explanation": "Test", "requires_human_approval": false}'
                }
            }
        ]
    }
    analyzer = AIThreatAnalyzer(api_key="mock-key")
    alert = {"attacker_ip": "10.0.0.9", "victim_ip": "10.0.0.1", "confidence": 0.99}

    res = analyzer.analyze_and_propose(alert)
    assert res["requires_human_approval"] is True, "requires_human_approval must be hardcoded True"

    action = get_pending_actions()[res["proposed_action_id"]]
    assert action["auto_execute"] is False, "auto_execute in pending store must be False"

def test_concurrent_alert_ingestion():
    """Simulate 10 concurrent threads ingesting 50 alerts each (500 total)."""
    import threading
    analyzer = AIThreatAnalyzer(api_key=None, confidence_threshold=0.7)
    threads = []

    def worker(thread_idx):
        for i in range(50):
            analyzer.ingest_alert({
                "attacker_ip": f"10.0.{thread_idx}.{i+1}",
                "victim_ip": "10.0.0.1",
                "confidence": 0.85,
            })

    for t_idx in range(10):
        t = threading.Thread(target=worker, args=(t_idx,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    # Total ingested high-confidence alerts should equal 500 across buffer and pending actions
    pending = get_pending_actions()
    with analyzer._buffer_lock:
        total_count = len(analyzer._alert_buffer) + len(pending)
    assert total_count == 500, f"Expected 500 total alerts, got {total_count}"

@patch("requests.post")
def test_burst_alert_handling(mock_post):
    """Simulate a burst of 500 alerts triggering auto-flushing and chunking (<= 20 alerts/chunk)."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [{"message": {"content": '{"explanation": "Burst test", "requires_human_approval": true}'}}]
    }
    mock_post.return_value = mock_resp

    analyzer = AIThreatAnalyzer(api_key="mock-key", confidence_threshold=0.7)
    # Turn off auto-flush in loop to test flush_and_analyze chunking explicitly
    analyzer.MAX_BUFFER_SIZE = 1000

    for i in range(500):
        analyzer.ingest_alert({
            "attacker_ip": f"10.0.0.{i%250 + 1}",
            "victim_ip": "10.0.0.1",
            "confidence": 0.80,
        })

    results = analyzer.flush_and_analyze()
    assert len(results) == 500
    # 500 alerts chunked into batches of 20 = 25 API calls
    assert mock_post.call_count == 25

@patch("requests.post")
def test_invalid_model_error_logging(mock_post, caplog):
    """Distinguish invalid model HTTP 404/400 errors from temporary network issues."""
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = '{"error": {"message": "The model nvidia/nonexistent-model does not exist"}}'
    mock_post.return_value = mock_resp

    analyzer = AIThreatAnalyzer(api_key="mock-key", model="nvidia/nonexistent-model")
    alert = {"attacker_ip": "10.0.0.10", "victim_ip": "10.0.0.1", "confidence": 0.95}

    res = analyzer.analyze_and_propose(alert)
    assert res["requires_human_approval"] is True
    assert "INVALID MODEL CONFIGURATION ERROR" in caplog.text

def test_api_alert_severity_confidence_fallback():
    """Verify API-sourced alerts (no packet_count field) fall back to confidence-based severity thresholding."""
    analyzer = AIThreatAnalyzer(api_key=None)  # Degraded mode

    # High confidence API alert (no packet_count) -> HIGH severity
    api_high = {
        "src_ip": "192.168.1.50",
        "dst_ip": "192.168.1.1",
        "attack_family": "Reflection-Amplification",
        "attack_family_confidence": 0.92,
        "source": "api_scoring_service",
    }
    res_high = analyzer.analyze_and_propose(api_high)
    assert res_high["severity"] == "HIGH"
    assert res_high["attack_type_guess"] == "Reflection-Amplification"

    # Moderate confidence API alert (0.75 < 0.85) -> MEDIUM severity
    api_med = {
        "src_ip": "192.168.1.51",
        "dst_ip": "192.168.1.1",
        "attack_family": "UDP-Based",
        "attack_family_confidence": 0.75,
        "source": "api_scoring_service",
    }
    res_med = analyzer.analyze_and_propose(api_med)
    assert res_med["severity"] == "MEDIUM"
    assert res_med["attack_type_guess"] == "UDP-Based"


def test_summarize_ensemble_consensus_full_unanimous():
    """Verify 3/3 model agreement is classified as FULL_UNANIMOUS."""
    from src.agent.nemotron_agent import summarize_ensemble_consensus

    breakdown = {
        "random_forest": {"label": "WebDDoS", "confidence": 0.94},
        "xgboost": {"label": "WebDDoS", "confidence": 0.98},
        "sequence_classifier": {
            "label": "WebDDoS",
            "confidence": 0.89,
            "active": True,
            "caveat": "synthetic window caveat",
        },
    }
    summary = summarize_ensemble_consensus(breakdown)
    assert summary["status"] == "FULL_UNANIMOUS"
    assert "WebDDoS" in summary["summary"]
    assert len(summary["active_models"]) == 3


def test_summarize_ensemble_consensus_tabular_unanimous_sequence_dissent():
    """
    Prompt 6 Condition 1 Test:
    RF+XGB agree on attack while SequenceClassifier dissents.
    MUST NOT be pulled down to SPLIT or MAJORITY like an equal-weight vote.
    Must be classified as TABULAR_UNANIMOUS_SEQUENCE_DISSENT.
    """
    from src.agent.nemotron_agent import summarize_ensemble_consensus, NemotronAgent

    breakdown = {
        "random_forest": {"label": "WebDDoS", "confidence": 0.92},
        "xgboost": {"label": "WebDDoS", "confidence": 0.95},
        "sequence_classifier": {
            "label": "UDP",
            "confidence": 0.80,
            "active": True,
            "caveat": "Trained on synthetic pseudo-temporal windows; unverified on real sequences",
        },
    }
    consensus = summarize_ensemble_consensus(breakdown)

    # 1. Distinct consensus status preserving tabular high-confidence tier
    assert consensus["status"] == "TABULAR_UNANIMOUS_SEQUENCE_DISSENT"
    assert consensus["status"] != "SPLIT"
    assert consensus["status"] != "MAJORITY"
    assert consensus["status"] != "TABULAR_SPLIT"
    assert consensus["status"] != "FULL_SPLIT"

    # 2. Summary explicitly reflects tabular 85% decision weight and sequence unverified caveat
    assert "85%" in consensus["summary"]
    assert "unverified" in consensus["summary"]

    # 3. Degraded mode fallback retains HIGH severity tier for tabular agreement
    agent = NemotronAgent(api_key=None)
    alert = {
        "attacker_ip": "10.0.0.99",
        "victim_ip": "10.0.0.1",
        "attack_type": "WebDDoS",
        "confidence": 0.91,
        "per_model_breakdown": breakdown,
    }
    res = agent.analyze_and_propose(alert)
    assert res["severity"] == "HIGH"
    assert res["consensus_status"] == "TABULAR_UNANIMOUS_SEQUENCE_DISSENT"
    assert "tabular models (85% weight)" in res["explanation"]


def test_single_model_degraded_severity_rule():
    """
    Prompt 6 Condition 2 Test:
    Explicit separate severity rule for SINGLE_MODEL (e.g. live default xgb_only):
    Severity is based purely on model confidence with NO consensus-based adjustment up or down.
    """
    from src.agent.nemotron_agent import summarize_ensemble_consensus, NemotronAgent

    # 1. Single model breakdown (xgb_only)
    breakdown_high = {
        "xgboost": {"label": "Syn", "confidence": 0.92},
        "sequence_classifier": {"label": "Unknown", "confidence": 0.0, "active": False},
    }
    consensus_high = summarize_ensemble_consensus(breakdown_high)
    assert consensus_high["status"] == "SINGLE_MODEL"
    assert consensus_high["details"]["active_model"] == "xgboost"

    agent = NemotronAgent(api_key=None)

    # 2. conf >= 0.85 -> HIGH severity
    alert_high = {
        "attacker_ip": "10.0.0.101",
        "victim_ip": "10.0.0.1",
        "attack_type": "Syn",
        "confidence": 0.88,
        "per_model_breakdown": breakdown_high,
    }
    res_high = agent.analyze_and_propose(alert_high)
    assert res_high["severity"] == "HIGH"
    assert res_high["consensus_status"] == "SINGLE_MODEL"
    assert "single-model" in res_high["explanation"]

    # 3. 0.70 <= conf < 0.85 -> MEDIUM severity (unaffected by lack of other models)
    breakdown_med = {
        "xgboost": {"label": "Syn", "confidence": 0.76},
        "sequence_classifier": {"label": "Unknown", "confidence": 0.0, "active": False},
    }
    alert_med = {
        "attacker_ip": "10.0.0.102",
        "victim_ip": "10.0.0.1",
        "attack_type": "Syn",
        "confidence": 0.76,
        "per_model_breakdown": breakdown_med,
    }
    res_med = agent.analyze_and_propose(alert_med)
    assert res_med["severity"] == "MEDIUM"
    assert res_med["consensus_status"] == "SINGLE_MODEL"

    # 4. conf < 0.70 -> LOW severity
    breakdown_low = {
        "xgboost": {"label": "Syn", "confidence": 0.65},
        "sequence_classifier": {"label": "Unknown", "confidence": 0.0, "active": False},
    }
    alert_low = {
        "attacker_ip": "10.0.0.103",
        "victim_ip": "10.0.0.1",
        "attack_type": "Syn",
        "confidence": 0.65,
        "per_model_breakdown": breakdown_low,
    }
    # Direct normalize & batch propose to test low severity branch
    norm_low = agent.normalize_alert(alert_low)
    res_low = agent.analyze_batch_and_propose([norm_low])[0]
    assert res_low["severity"] == "LOW"
    assert res_low["consensus_status"] == "SINGLE_MODEL"


def test_tabular_split_degraded_severity_downgrade():
    """Verify that when tabular models (RF and XGB) disagree, severity is downgraded to MEDIUM."""
    from src.agent.nemotron_agent import summarize_ensemble_consensus, NemotronAgent

    breakdown = {
        "random_forest": {"label": "Syn", "confidence": 0.90},
        "xgboost": {"label": "UDP", "confidence": 0.89},
        "sequence_classifier": {"active": False},
    }
    consensus = summarize_ensemble_consensus(breakdown)
    assert consensus["status"] == "TABULAR_SPLIT"

    agent = NemotronAgent(api_key=None)
    alert = {
        "attacker_ip": "10.0.0.104",
        "victim_ip": "10.0.0.1",
        "attack_type": "Syn",
        "confidence": 0.89,
        "per_model_breakdown": breakdown,
    }
    res = agent.analyze_and_propose(alert)
    assert res["severity"] == "MEDIUM"
    assert res["consensus_status"] == "TABULAR_SPLIT"
    assert "model disagreement" in res["explanation"]


@patch("requests.post")
def test_prompt_template_formats_ensemble_breakdown_and_consensus(mock_post):
    """Verify that prompt delivered to OpenRouter Nemotron includes structured consensus and model breakdown."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": '{"explanation": "Verified consensus", "attack_type_guess": "WebDDoS", "severity": "HIGH", "proposed_action": "Block", "requires_human_approval": true}'
                }
            }
        ]
    }
    mock_post.return_value = mock_resp

    from src.agent.nemotron_agent import NemotronAgent

    agent = NemotronAgent(api_key="mock-key")
    alert = {
        "attacker_ip": "10.0.0.105",
        "victim_ip": "10.0.0.1",
        "attack_type": "WebDDoS",
        "confidence": 0.94,
        "per_model_breakdown": {
            "random_forest": {"label": "WebDDoS", "confidence": 0.93},
            "xgboost": {"label": "WebDDoS", "confidence": 0.97},
            "sequence_classifier": {
                "label": "Syn",
                "confidence": 0.70,
                "active": True,
                "caveat": "synthetic windowing caveat",
            },
        },
    }

    res = agent.analyze_and_propose(alert)
    assert res["requires_human_approval"] is True

    # Inspect the prompt sent to the LLM
    assert mock_post.call_count == 1
    call_args, call_kwargs = mock_post.call_args
    sent_payload = json.loads(call_kwargs["data"])
    sent_prompt = sent_payload["messages"][1]["content"]

    # Verify structured ensemble fields are present in prompt
    assert "Consensus Tier: TABULAR_UNANIMOUS_SEQUENCE_DISSENT" in sent_prompt
    assert "RF=WebDDoS (0.93)" in sent_prompt
    assert "XGB=WebDDoS (0.97)" in sent_prompt
    assert "LSTM=Syn (0.70)" in sent_prompt
    assert "[synthetic windowing caveat]" in sent_prompt


def test_degraded_confidence_blocks_critical_escalation():
    """
    Standalone named test proving that degraded confidence blocks CRITICAL escalation:
    Construct an alert where unanimous model consensus and 0.95 raw confidence would normally
    escalate to CRITICAL severity, but because feature_completeness < 1.0 (degraded_confidence=True)
    from unobserved backward features (Bwd Packets/s = 0, Down/Up Ratio = 0), the severity is
    strictly capped below CRITICAL (to HIGH), and [DEGRADED INPUT] is prepended to the explanation.
    """
    from src.agent.nemotron_agent import NemotronAgent, get_action

    agent = NemotronAgent(api_key=None)  # Triggers deterministic heuristic fallback

    breakdown = {
        "random_forest": {"label": "Syn", "confidence": 0.96},
        "xgboost": {"label": "Syn", "confidence": 0.95},
        "sequence_classifier": {"label": "Syn", "confidence": 0.95, "active": True},
        "degraded_confidence": True,
        "feature_completeness": 0.7013,
        "degradation_reason": "host_ingress: 23 backward features unobserved and zero-filled",
    }

    alert = {
        "attacker_ip": "192.168.10.50",
        "victim_ip": "10.0.0.1",
        "attack_type": "Syn",
        "confidence": 0.95,
        "per_model_breakdown": breakdown,
        "feature_completeness": 0.7013,
        "degraded_confidence": True,
        "degradation_reason": "host_ingress: 23 backward features unobserved and zero-filled",
    }

    res = agent.analyze_and_propose(alert)

    # Severity MUST NOT be CRITICAL — it must be capped below CRITICAL
    assert res["severity"] == "HIGH", f"Expected severity HIGH (capped below CRITICAL), got {res['severity']}"
    assert "[DEGRADED INPUT]" in res["explanation"]
    assert res["degraded_confidence"] is True
    assert res["feature_completeness"] == 0.7013
    assert res["requires_human_approval"] is True

    # Confirm the stored pending action reason in the manager also preserves [DEGRADED INPUT]
    action = get_action(res["proposed_action_id"])
    assert action is not None
    assert "[DEGRADED INPUT]" in action["reason"]


@patch("requests.post")
def test_prompt_formats_input_degradation_warning(mock_post):
    """
    Verify that when degraded_confidence is True, the prompt formatted for Nemotron LLM
    explicitly includes the Input Degradation warning line with completeness and reason,
    and system prompt contains Rule 6 regarding asymmetric input degradation.
    """
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": '{"explanation": "Degraded triage", "attack_type_guess": "Syn", "severity": "MEDIUM", "proposed_action": "Rate limit", "requires_human_approval": true}'
                }
            }
        ]
    }
    mock_post.return_value = mock_resp

    from src.agent.nemotron_agent import NemotronAgent

    agent = NemotronAgent(api_key="mock-key")
    alert = {
        "attacker_ip": "192.168.1.99",
        "victim_ip": "10.0.0.1",
        "attack_type": "Syn",
        "confidence": 0.92,
        "per_model_breakdown": {
            "random_forest": {"label": "Syn", "confidence": 0.91},
            "xgboost": {"label": "Syn", "confidence": 0.93},
        },
        "feature_completeness": 0.7013,
        "degraded_confidence": True,
        "degradation_reason": "host_ingress: 23 backward features unobserved and zero-filled",
    }

    res = agent.analyze_and_propose(alert)
    assert res["requires_human_approval"] is True

    assert mock_post.call_count == 1
    call_args, call_kwargs = mock_post.call_args
    sent_payload = json.loads(call_kwargs["data"])

    # System instruction must include Rule 6
    sys_prompt = sent_payload["messages"][0]["content"]
    assert "6. INPUT DEGRADATION (feature_completeness < 1.0)" in sys_prompt

    # User prompt must include the warning line
    user_prompt = sent_payload["messages"][1]["content"]
    assert "⚠️ Input Degradation: Feature completeness is 0.70 (host_ingress: 23 backward features unobserved and zero-filled)" in user_prompt
    assert "Evaluate possibility of evasion or distorted asymmetric flood dynamics." in user_prompt


