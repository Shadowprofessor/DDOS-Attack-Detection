# -*- coding: utf-8 -*-
"""
Tests for Layer 1 Signature-Based Pre-Filter (Phase H - H5).
Verifies:
  - RFC 793 / 5961 flag violations (SYN+FIN, NULL, XMAS, SYN+RST)
  - LAND Attack detection
  - Bogon / Martian source address filtration
  - NTP Monlist & DNS ANY reflection signatures
  - Clean flow passthrough to ML
"""

import pytest
from src.features.signature_filter import (
    SignatureFilter,
    _TCP_SYN,
    _TCP_FIN,
    _TCP_RST,
    _TCP_PSH,
    _TCP_URG,
    _TCP_ACK,
)


@pytest.fixture
def sig_filter():
    return SignatureFilter()


def test_clean_packet(sig_filter):
    res = sig_filter.inspect_packet(
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        proto=6,
        sport=45120,
        dport=80,
        tcp_flags=_TCP_SYN,
        pkt_len=60,
    )
    assert not res.matched
    assert res.severity == "CLEAN"
    assert res.recommended_action == "FORWARD_TO_ML"


def test_tcp_syn_fin_violation(sig_filter):
    res = sig_filter.inspect_packet(
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        proto=6,
        sport=45120,
        dport=80,
        tcp_flags=_TCP_SYN | _TCP_FIN,
    )
    assert res.matched
    assert res.signature_id == "SIG-TCP-001"
    assert res.signature_name == "TCP_SYN_FIN_SCAN"
    assert res.severity == "CRITICAL"
    assert "RFC 793" in res.rfc_reference


def test_tcp_null_scan(sig_filter):
    res = sig_filter.inspect_packet(
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        proto=6,
        sport=45120,
        dport=80,
        tcp_flags=0x00,
    )
    assert res.matched
    assert res.signature_id == "SIG-TCP-002"
    assert res.severity == "HIGH"


def test_tcp_xmas_scan(sig_filter):
    res = sig_filter.inspect_packet(
        src_ip="192.168.1.50",
        dst_ip="10.0.0.1",
        proto=6,
        sport=45120,
        dport=80,
        tcp_flags=_TCP_FIN | _TCP_PSH | _TCP_URG,
    )
    assert res.matched
    assert res.signature_id == "SIG-TCP-003"
    assert res.severity == "HIGH"


def test_land_attack(sig_filter):
    res = sig_filter.inspect_packet(
        src_ip="10.0.0.1",
        dst_ip="10.0.0.1",
        proto=6,
        sport=80,
        dport=80,
        tcp_flags=_TCP_SYN,
    )
    assert res.matched
    assert res.signature_id == "SIG-IP-001"
    assert res.signature_name == "LAND_ATTACK"
    assert res.severity == "CRITICAL"


def test_bogon_source_filtering(sig_filter):
    # Loopback source
    res1 = sig_filter.inspect_packet(
        src_ip="127.0.0.1",
        dst_ip="10.0.0.1",
        proto=6,
        sport=12345,
        dport=80,
    )
    assert res1.matched
    assert res1.signature_id == "SIG-IP-002"

    # Multicast IP used as unicast source
    res2 = sig_filter.inspect_packet(
        src_ip="224.0.0.1",
        dst_ip="10.0.0.1",
        proto=17,
        sport=5000,
        dport=5000,
    )
    assert res2.matched
    assert res2.signature_id == "SIG-IP-002"


def test_ntp_monlist_amplification(sig_filter):
    monlist_req = b"\x17\x00\x03\x2a" + b"\x00" * 8
    res = sig_filter.inspect_packet(
        src_ip="198.51.100.5",
        dst_ip="10.0.0.1",
        proto=17,
        sport=123,
        dport=123,
        payload=monlist_req,
    )
    assert res.matched
    assert res.signature_id == "SIG-UDP-001"
    assert res.severity == "CRITICAL"
    assert "NTP" in res.description


def test_dns_any_amplification(sig_filter):
    dns_any_payload = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\xff\x00\x01"
    res = sig_filter.inspect_packet(
        src_ip="198.51.100.5",
        dst_ip="10.0.0.1",
        proto=17,
        sport=53,
        dport=53,
        payload=dns_any_payload,
    )
    assert res.matched
    assert res.signature_id == "SIG-UDP-002"
    assert res.severity == "HIGH"


def test_flow_features_syn_fin_inspection(sig_filter):
    features = {
        "SYN Flag Count": 100.0,
        "FIN Flag Count": 100.0,
        "RST Flag Count": 0.0,
        "ACK Flag Count": 0.0,
        "Protocol": 6.0,
    }
    res = sig_filter.inspect_flow_features(features, src_ip="192.168.1.10", dst_ip="10.0.0.2")
    assert res.matched
    assert res.signature_id == "SIG-TCP-001"
