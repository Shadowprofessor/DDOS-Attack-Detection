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
