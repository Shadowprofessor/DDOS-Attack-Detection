# -*- coding: utf-8 -*-
"""
Tests for Layer 1/2 Historical Baseline & Statistical Anomaly Detector (Phase H - H9).
Verifies:
  - Normal traffic within baseline bounds evaluates as NORMAL
  - Massive volumetric surge triggers high Z-score and CRITICAL anomaly
  - Protocol mix skew detection
  - Shannon entropy calculation for IP distribution
  - Deterministic heuristic analyst notes generation
"""

import os
import pytest
from unittest.mock import patch
from src.features.anomaly_detector import (
    RollingAnomalyDetector,
    compute_shannon_entropy,
)


@pytest.fixture
def detector():
    return RollingAnomalyDetector()


def test_shannon_entropy_calculation():
    # Identical distribution across 4 IPs -> H = log2(4) = 2.0
    freq_uniform = {"10.0.0.1": 10, "10.0.0.2": 10, "10.0.0.3": 10, "10.0.0.4": 10}
    h_uniform = compute_shannon_entropy(freq_uniform)
    assert abs(h_uniform - 2.0) < 0.01

    # Highly skewed distribution (single IP dominates) -> H near 0
    freq_skewed = {"10.0.0.1": 10000, "10.0.0.2": 1}
    h_skewed = compute_shannon_entropy(freq_skewed)
    assert h_skewed < 0.1


def test_normal_baseline_traffic(detector):
    """Traffic near benign baseline (2.02 PPS) should not be flagged."""
    res = detector.evaluate_traffic(
        current_pps=2.2,
        current_bps=120.0,
        proto_counts={"tcp": 8, "udp": 2, "icmp": 0},
        generate_ai_notes=False,
    )
    assert not res.is_anomaly
    assert res.severity == "NORMAL"
    assert res.z_scores["z_pps"] < 1.0


def test_extreme_volumetric_anomaly(detector):
    """Volumetric burst of 3,000 PPS (>3,000x sigma) triggers CRITICAL anomaly."""
    with patch.dict(os.environ, {"NVIDIA_API_KEY": "", "OPENROUTER_API_KEY": ""}):
        res = detector.evaluate_traffic(
            current_pps=3000.0,
            current_bps=150000.0,
            proto_counts={"tcp": 3000, "udp": 0, "icmp": 0},
            generate_ai_notes=True,
        )
        assert res.is_anomaly
        assert res.severity == "CRITICAL"
        assert res.anomaly_score >= 80.0
        assert res.z_scores["z_pps"] > 100.0
        assert res.analyst_notes is not None
        assert res.analyst_notes["source"] == "Deterministic Blue-Team Expert (Heuristic Baseline)"
        assert "Severe Statistical Outlier" in res.analyst_notes["assessment"]


def test_protocol_skew_anomaly(detector):
    """Sudden surge where UDP becomes 99% of traffic triggers protocol skew anomaly."""
    res = detector.evaluate_traffic(
        current_pps=200.0,
        current_bps=10000.0,
        proto_counts={"tcp": 1, "udp": 99, "icmp": 0},
        generate_ai_notes=False,
    )
    assert any("Protocol Shift" in r for r in res.anomaly_reasons)
    assert res.protocol_distribution["udp"] > 0.90


def test_baseline_online_adaptation(detector):
    """Baseline adapts when updated with clean traffic observations."""
    initial_mean = detector.mean_pps
    for _ in range(20):
        detector.update_baseline(observed_pps=10.0, observed_bps=500.0)
    assert detector.mean_pps > initial_mean
