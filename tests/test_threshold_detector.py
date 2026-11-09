# -*- coding: utf-8 -*-
"""
Tests for Layer 1 Rate-Based Threshold Detector (Phase H - H6).
Verifies detection behavior against:
  - Grounded Mininet baseline (benign.pcap) -> returns NORMAL
  - Real attack PCAPs (Syn_pure_unidirectional.pcap, NTP_v2.pcap) -> returns CRITICAL
  - Sliding-window packet stream events
"""

import os
import pytest
from src.features.threshold_detector import (
    RateThresholdDetector,
    BENIGN_BASELINE_PPS,
    BENIGN_BASELINE_SYN_RATE,
)
from src.features.flow_extractor import FlowExtractor

PCAP_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "pcaps")


def test_benign_packet_stream():
    """Verify low-rate packet stream returns NORMAL status."""
    detector = RateThresholdDetector(window_seconds=2.0)
    # 2 packets per second for 2 seconds
    res = None
    for i in range(4):
        res = detector.record_packet(
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            pkt_len=60,
            is_syn=False,
            dst_port=80,
            timestamp=100.0 + (i * 0.5),
        )
    assert res is not None
    assert res.status == "NORMAL"
    assert not res.is_violation
    assert res.current_pps < 10.0


def test_high_rate_syn_stream():
    """Verify high-rate SYN flood triggers CRITICAL rate violation."""
    detector = RateThresholdDetector(window_seconds=1.0)
    res = None
    # 300 SYN packets in 0.5 seconds -> 600 PPS, 600 SYN/s
    for i in range(300):
        res = detector.record_packet(
            src_ip="10.0.0.5",
            dst_ip="10.0.0.2",
            pkt_len=60,
            is_syn=True,
            dst_port=80,
            timestamp=100.0 + (i * 0.0016),
        )
    assert res is not None
    assert res.status == "CRITICAL"
    assert res.is_violation
    assert res.vector_inference == "Rate-Based SYN Flood"
    assert any("SYN Rate" in r for r in res.triggered_rules)


def test_real_benign_pcap_evaluation():
    """Verify real Mininet benign.pcap evaluates as NORMAL under threshold detector."""
    pcap_path = os.path.join(PCAP_DIR, "benign.pcap")
    if not os.path.exists(pcap_path):
        pytest.skip("benign.pcap not found")

    extractor = FlowExtractor()
    flows = extractor.process_pcap(pcap_path)
    assert len(flows) > 0

    detector = RateThresholdDetector()
    fdict = extractor.to_flow_features(flows[0])["features"]
    res = detector.evaluate_flow_features(fdict, src_ip="10.0.0.1", dst_ip="10.0.0.2")

    assert res.status == "NORMAL"
    assert not res.is_violation
    assert res.current_pps <= 10.0  # Actually ~2.02 pps
    assert res.current_syn_rate == 0.0


def test_real_syn_pcap_evaluation():
    """Verify real Mininet Syn_pure_unidirectional.pcap evaluates as CRITICAL."""
    pcap_path = os.path.join(PCAP_DIR, "Syn_pure_unidirectional.pcap")
    if not os.path.exists(pcap_path):
        pytest.skip("Syn_pure_unidirectional.pcap not found")

    extractor = FlowExtractor()
    flows = extractor.process_pcap(pcap_path)
    assert len(flows) > 0

    detector = RateThresholdDetector()
    fdict = extractor.to_flow_features(flows[0])["features"]
    res = detector.evaluate_flow_features(fdict, src_ip="10.0.0.5", dst_ip="10.0.0.2")

    assert res.status == "CRITICAL"
    assert res.is_violation
    assert res.vector_inference == "Rate-Based SYN Flood"
    assert res.current_pps > 1000.0


def test_real_ntp_pcap_evaluation():
    """Verify real Mininet NTP_v2.pcap evaluates as CRITICAL volumetric flood."""
    pcap_path = os.path.join(PCAP_DIR, "NTP_v2.pcap")
    if not os.path.exists(pcap_path):
        pytest.skip("NTP_v2.pcap not found")

    extractor = FlowExtractor()
    flows = extractor.process_pcap(pcap_path)
    assert len(flows) > 0

    detector = RateThresholdDetector()
    fdict = extractor.to_flow_features(flows[0])["features"]
    res = detector.evaluate_flow_features(fdict, src_ip="10.0.0.5", dst_ip="10.0.0.2")

    assert res.status == "CRITICAL"
    assert res.is_violation
    assert res.current_pps > 1000.0
