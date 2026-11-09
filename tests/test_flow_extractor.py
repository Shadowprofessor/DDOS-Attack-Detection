# -*- coding: utf-8 -*-
"""
Tests for Step 1: Flow Feature Extractor (src/features/flow_extractor.py).

Tests cover:
  - Feature vector length and column order
  - Bidirectional flow key canonicalization
  - Forward/backward packet direction detection
  - IAT (Inter-Arrival Time) calculation correctness
  - TCP flag counting
  - Flow expiration (active and idle timeouts)
  - flush_all / expire_idle_flows lifecycle
  - Subflow / active-idle period tracking
  - Edge cases: single-packet flows, zero-length payloads
"""
import os
import sys
import math
import pytest

# Ensure src/ is on the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.features.flow_extractor import (
    FlowExtractor,
    Flow,
    Packet,
    CICFLOWMETER_FEATURE_NAMES,
    NUM_FEATURES,
)


# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------
def _make_tcp_packet(ts, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                     src_port=12345, dst_port=80, payload_len=100,
                     header_len=54, tcp_flags=0x10, tcp_window=65535):
    """Create a TCP Packet with sensible defaults."""
    return Packet(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=6,
        payload_len=payload_len,
        header_len=header_len,
        tcp_flags=tcp_flags,
        tcp_window=tcp_window,
    )


def _make_udp_packet(ts, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                     src_port=12345, dst_port=53, payload_len=64,
                     header_len=28):
    """Create a UDP Packet with sensible defaults."""
    return Packet(
        timestamp=ts,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=17,
        payload_len=payload_len,
        header_len=header_len,
    )


# -------------------------------------------------------------------------
# Test: Feature vector shape and column names
# -------------------------------------------------------------------------
class TestFeatureSchema:
    """Verify the output schema matches the CICDDoS2019 dataset."""

    def test_feature_name_count(self):
        assert len(CICFLOWMETER_FEATURE_NAMES) == 77
        assert NUM_FEATURES == 77

    def test_single_packet_flow_vector_length(self):
        """A flow with a single packet must still produce a 77-element vector."""
        ext = FlowExtractor()
        pkt = _make_tcp_packet(ts=1000.0)
        ext.process_packet(pkt)
        flows = ext.flush_all()
        assert len(flows) == 1
        vec = flows[0].to_feature_vector()
        assert len(vec) == 77

    def test_feature_dict_keys_match(self):
        """to_feature_dict() keys must be CICFLOWMETER_FEATURE_NAMES."""
        ext = FlowExtractor()
        pkt = _make_tcp_packet(ts=1000.0)
        ext.process_packet(pkt)
        flows = ext.flush_all()
        d = flows[0].to_feature_dict()
        assert list(d.keys()) == CICFLOWMETER_FEATURE_NAMES


# -------------------------------------------------------------------------
# Test: Bidirectional flow key
# -------------------------------------------------------------------------
class TestFlowKeyCanonicalization:
    """Packets from A→B and B→A must map to the same flow."""

    def test_bidirectional_same_flow(self):
        ext = FlowExtractor()
        pkt_ab = _make_tcp_packet(ts=1000.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                                  src_port=12345, dst_port=80)
        pkt_ba = _make_tcp_packet(ts=1000.1, src_ip="10.0.0.2", dst_ip="10.0.0.1",
                                  src_port=80, dst_port=12345)
        ext.process_packet(pkt_ab)
        ext.process_packet(pkt_ba)
        assert ext.active_flow_count == 1

    def test_different_ports_different_flows(self):
        ext = FlowExtractor()
        pkt1 = _make_tcp_packet(ts=1000.0, src_port=12345)
        pkt2 = _make_tcp_packet(ts=1000.0, src_port=54321)
        ext.process_packet(pkt1)
        ext.process_packet(pkt2)
        assert ext.active_flow_count == 2

    def test_different_protocols_different_flows(self):
        ext = FlowExtractor()
        tcp_pkt = _make_tcp_packet(ts=1000.0, src_port=12345, dst_port=80)
        udp_pkt = _make_udp_packet(ts=1000.0, src_port=12345, dst_port=80)
        ext.process_packet(tcp_pkt)
        ext.process_packet(udp_pkt)
        assert ext.active_flow_count == 2


# -------------------------------------------------------------------------
# Test: Forward/Backward direction & packet counts
# -------------------------------------------------------------------------
class TestDirectionDetection:
    """The first packet's source IP defines the forward direction."""

    def test_forward_backward_counts(self):
        ext = FlowExtractor()
        # 3 forward, 2 backward
        for i in range(3):
            ext.process_packet(_make_tcp_packet(ts=1000.0 + i * 0.01,
                                                src_ip="10.0.0.1", dst_ip="10.0.0.2"))
        for i in range(2):
            ext.process_packet(_make_tcp_packet(ts=1000.1 + i * 0.01,
                                                src_ip="10.0.0.2", dst_ip="10.0.0.1",
                                                src_port=80, dst_port=12345))
        flows = ext.flush_all()
        assert len(flows) == 1
        f = flows[0]
        assert f.fwd_packet_count == 3
        assert f.bwd_packet_count == 2

    def test_payload_length_accumulation(self):
        ext = FlowExtractor()
        ext.process_packet(_make_tcp_packet(ts=1000.0, payload_len=100))
        ext.process_packet(_make_tcp_packet(ts=1000.1, payload_len=200))
        flows = ext.flush_all()
        f = flows[0]
        assert sum(f.fwd_payload_lengths) == 300


# -------------------------------------------------------------------------
# Test: IAT (Inter-Arrival Time) calculations
# -------------------------------------------------------------------------
class TestIATCalculation:
    """Verify flow and direction-specific IAT values."""

    def test_flow_iat_values(self):
        ext = FlowExtractor()
        ext.process_packet(_make_tcp_packet(ts=1000.0))
        ext.process_packet(_make_tcp_packet(ts=1000.5))  # 500ms gap
        ext.process_packet(_make_tcp_packet(ts=1001.0))  # 500ms gap
        flows = ext.flush_all()
        f = flows[0]
        # Flow IATs should be in microseconds
        assert len(f.flow_iats) == 2
        assert abs(f.flow_iats[0] - 500000.0) < 100  # ~500ms in μs
        assert abs(f.flow_iats[1] - 500000.0) < 100

    def test_fwd_bwd_iat_separate(self):
        ext = FlowExtractor()
        # Fwd: t=0, t=1.0
        ext.process_packet(_make_tcp_packet(ts=1000.0, src_ip="10.0.0.1", dst_ip="10.0.0.2"))
        ext.process_packet(_make_tcp_packet(ts=1001.0, src_ip="10.0.0.1", dst_ip="10.0.0.2"))
        # Bwd: t=0.5, t=1.5 (each 1s apart from its predecessor)
        ext.process_packet(_make_tcp_packet(ts=1000.5, src_ip="10.0.0.2", dst_ip="10.0.0.1",
                                            src_port=80, dst_port=12345))
        ext.process_packet(_make_tcp_packet(ts=1001.5, src_ip="10.0.0.2", dst_ip="10.0.0.1",
                                            src_port=80, dst_port=12345))
        flows = ext.flush_all()
        f = flows[0]
        assert len(f.fwd_iats) == 1
        assert abs(f.fwd_iats[0] - 1e6) < 100  # 1 second in μs
        assert len(f.bwd_iats) == 1
        assert abs(f.bwd_iats[0] - 1e6) < 100


# -------------------------------------------------------------------------
# Test: TCP Flag counting
# -------------------------------------------------------------------------
class TestTCPFlags:
    """Verify flag counters and per-direction PSH/URG tracking."""

    def test_syn_ack_sequence(self):
        ext = FlowExtractor()
        # SYN
        ext.process_packet(_make_tcp_packet(ts=1000.0, tcp_flags=0x02))
        # SYN-ACK
        ext.process_packet(_make_tcp_packet(ts=1000.1, tcp_flags=0x12,
                                            src_ip="10.0.0.2", dst_ip="10.0.0.1",
                                            src_port=80, dst_port=12345))
        # ACK
        ext.process_packet(_make_tcp_packet(ts=1000.2, tcp_flags=0x10))
        flows = ext.flush_all()
        f = flows[0]
        assert f.syn_count == 2  # SYN + SYN-ACK
        assert f.ack_count == 2  # SYN-ACK + ACK

    def test_psh_direction_tracking(self):
        ext = FlowExtractor()
        # Fwd PSH
        ext.process_packet(_make_tcp_packet(ts=1000.0, tcp_flags=0x08))
        # Bwd PSH
        ext.process_packet(_make_tcp_packet(ts=1000.1, tcp_flags=0x08,
                                            src_ip="10.0.0.2", dst_ip="10.0.0.1",
                                            src_port=80, dst_port=12345))
        ext.process_packet(_make_tcp_packet(ts=1000.2, tcp_flags=0x08,
                                            src_ip="10.0.0.2", dst_ip="10.0.0.1",
                                            src_port=80, dst_port=12345))
        flows = ext.flush_all()
        f = flows[0]
        assert f.fwd_psh_flags == 1
        assert f.bwd_psh_flags == 2


# -------------------------------------------------------------------------
# Test: Flow expiration (active & idle timeouts)
# -------------------------------------------------------------------------
class TestFlowExpiration:
    """Verify timeout-based flow expiration."""

    def test_active_timeout_expires_flow(self):
        ext = FlowExtractor(active_timeout=10.0)
        ext.process_packet(_make_tcp_packet(ts=1000.0))
        # Same 5-tuple, but 15s later → exceeds active timeout
        expired = ext.process_packet(_make_tcp_packet(ts=1015.0))
        assert expired is not None
        assert expired.fwd_packet_count == 1  # the old flow had 1 packet
        # A new flow was started
        assert ext.active_flow_count == 1

    def test_idle_timeout_expires_flow(self):
        ext = FlowExtractor(idle_timeout=5.0)
        ext.process_packet(_make_tcp_packet(ts=1000.0))
        # 10 seconds of silence → exceeds idle timeout
        expired = ext.process_packet(_make_tcp_packet(ts=1010.0))
        assert expired is not None

    def test_expire_idle_flows_sweep(self):
        ext = FlowExtractor(idle_timeout=5.0)
        ext.process_packet(_make_tcp_packet(ts=1000.0))
        ext.process_packet(_make_udp_packet(ts=1000.0))
        assert ext.active_flow_count == 2

        expired = ext.expire_idle_flows(now=1010.0)
        assert len(expired) == 2
        assert ext.active_flow_count == 0

    def test_flush_all_returns_everything(self):
        ext = FlowExtractor()
        for i in range(5):
            ext.process_packet(_make_tcp_packet(ts=1000.0 + i, src_port=10000 + i))
        assert ext.active_flow_count == 5
        flows = ext.flush_all()
        assert len(flows) == 5
        assert ext.active_flow_count == 0


# -------------------------------------------------------------------------
# Test: Feature vector correctness for known inputs
# -------------------------------------------------------------------------
class TestFeatureVectorValues:
    """Spot-check specific feature values for a known packet sequence."""

    def test_protocol_field(self):
        ext = FlowExtractor()
        ext.process_packet(_make_tcp_packet(ts=1000.0))
        f = ext.flush_all()[0]
        vec = f.to_feature_vector()
        assert vec[0] == 6.0  # TCP protocol number

    def test_flow_duration(self):
        ext = FlowExtractor()
        ext.process_packet(_make_tcp_packet(ts=1000.0))
        ext.process_packet(_make_tcp_packet(ts=1002.0))
        f = ext.flush_all()[0]
        vec = f.to_feature_vector()
        # Duration = 2 seconds = 2,000,000 μs
        assert abs(vec[1] - 2_000_000.0) < 100

    def test_init_window_bytes(self):
        ext = FlowExtractor()
        ext.process_packet(_make_tcp_packet(ts=1000.0, tcp_window=32768))
        ext.process_packet(_make_tcp_packet(ts=1000.1, tcp_window=16384,
                                            src_ip="10.0.0.2", dst_ip="10.0.0.1",
                                            src_port=80, dst_port=12345))
        f = ext.flush_all()[0]
        d = f.to_feature_dict()
        assert d["Init Fwd Win Bytes"] == 32768.0
        assert d["Init Bwd Win Bytes"] == 16384.0

    def test_zero_payload_single_packet(self):
        """Edge case: single packet with zero payload."""
        ext = FlowExtractor()
        ext.process_packet(_make_tcp_packet(ts=1000.0, payload_len=0))
        f = ext.flush_all()[0]
        vec = f.to_feature_vector()
        assert len(vec) == 77
        # Fwd packet count should be 1
        assert vec[2] == 1.0
        # Total fwd bytes should be 0
        assert vec[4] == 0.0
        # Duration should be 0 (single packet)
        assert vec[1] == 0.0


# -------------------------------------------------------------------------
# Test: All features are finite floats (no NaN/Inf)
# -------------------------------------------------------------------------
class TestNoNanInf:
    """Verify no NaN or Inf values in feature vectors under various scenarios."""

    def test_single_packet_no_nan(self):
        ext = FlowExtractor()
        ext.process_packet(_make_tcp_packet(ts=1000.0))
        f = ext.flush_all()[0]
        vec = f.to_feature_vector()
        for i, v in enumerate(vec):
            assert math.isfinite(v), f"Feature {CICFLOWMETER_FEATURE_NAMES[i]} is {v}"

    def test_many_packets_no_nan(self):
        ext = FlowExtractor()
        for i in range(100):
            is_fwd = i % 3 != 0
            src = "10.0.0.1" if is_fwd else "10.0.0.2"
            dst = "10.0.0.2" if is_fwd else "10.0.0.1"
            sp = 12345 if is_fwd else 80
            dp = 80 if is_fwd else 12345
            ext.process_packet(_make_tcp_packet(
                ts=1000.0 + i * 0.01,
                src_ip=src, dst_ip=dst,
                src_port=sp, dst_port=dp,
                payload_len=(i * 7) % 1500,
                tcp_flags=0x18 if i % 5 == 0 else 0x10,
            ))
        flows = ext.flush_all()
        for f in flows:
            vec = f.to_feature_vector()
            for j, v in enumerate(vec):
                assert math.isfinite(v), f"Feature {CICFLOWMETER_FEATURE_NAMES[j]} is {v}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
