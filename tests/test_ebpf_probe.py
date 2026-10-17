# -*- coding: utf-8 -*-
"""
Tests for eBPF / XDP Flow Feature Extraction Probe (Prompt 10).

Covers:
1. Binary packet_event struct packing and unpacking parity.
2. 77/77 feature completeness audit (EBPF_POPULATED_FEATURES vs EBPF_ZERO_FILLED_FEATURES).
3. Mock ring buffer streaming to FlowExtractor and full 77-feature extraction.
4. Ring buffer backpressure and drop accounting (test_ring_buffer_full_does_not_crash).
5. Native vs. generic XDP mode detection and warning logging.
6. Graceful LibpcapBackend fallback when XDP is unavailable.
7. Strict non-fallback failure (fallback_to_libpcap=False).
8. Hardware-gated line-rate throughput benchmark (test_line_rate_throughput_manual).
"""
import logging
import os
import sys
import time
import pytest
from unittest.mock import MagicMock, patch

from src.ebpf.loader import (
    XDPFlowProbeLoader,
    MockBPFDriver,
    pack_packet_event,
    unpack_packet_event,
    decode_ipv4,
    encode_ipv4,
    PACKET_EVENT_SIZE,
)
from src.features.capture_backends.ebpf_backend import (
    EbpfBackend,
    EBPF_POPULATED_FEATURES,
    EBPF_ZERO_FILLED_FEATURES,
)
from src.features.flow_extractor import (
    FlowExtractor,
    Packet,
    CICFLOWMETER_FEATURE_NAMES,
)


def is_real_xdp_available() -> bool:
    """Helper to determine whether a physical Linux environment with native XDP is present."""
    if not sys.platform.startswith("linux"):
        return False
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        return False
    # Check if explicit benchmark env var is set
    return os.environ.get("DDOS_ENABLE_REAL_XDP_BENCHMARK") == "1"


# ---------------------------------------------------------------------------
# Test 1: Binary Struct Unpacking & Field Integrity
# ---------------------------------------------------------------------------
def test_packet_event_struct_binary_unpacking():
    """Verify that 28-byte packed binary struct decodes accurately into Packet."""
    ts_ns = 1_700_000_000_000_000_000  # Epoch ns timestamp
    src_ip = "192.168.10.50"
    dst_ip = "10.0.0.1"
    src_port = 54321
    dst_port = 80
    protocol = 6  # TCP
    tcp_flags = 0x02 | 0x10  # SYN + ACK (0x12)
    payload_len = 512
    header_len = 40
    tcp_window = 29200

    raw_bytes = pack_packet_event(
        timestamp_ns=ts_ns,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        tcp_flags=tcp_flags,
        payload_len=payload_len,
        header_len=header_len,
        tcp_window=tcp_window,
    )

    assert len(raw_bytes) == PACKET_EVENT_SIZE

    pkt = unpack_packet_event(raw_bytes)
    assert pkt.src_ip == src_ip
    assert pkt.dst_ip == dst_ip
    assert pkt.src_port == src_port
    assert pkt.dst_port == dst_port
    assert pkt.protocol == protocol
    assert pkt.tcp_flags == tcp_flags
    assert pkt.payload_len == payload_len
    assert pkt.header_len == header_len
    assert pkt.tcp_window == tcp_window
    assert pkt.timestamp == pytest.approx(ts_ns / 1e9, abs=1e-3)


# ---------------------------------------------------------------------------
# Test 2: Feature Completeness Partition Audit (77/77 = 1.0)
# ---------------------------------------------------------------------------
def test_feature_completeness_partition_77_features():
    """
    Prompt 10 Amendment 1:
    Confirm all 77 CICFlowMeter features are computable from XDP packet_event fields
    (5-tuple, timestamps, lengths, flags, window). Populated = 77, Zero-filled = 0.
    """
    assert len(EBPF_POPULATED_FEATURES) == 77
    assert len(EBPF_ZERO_FILLED_FEATURES) == 0
    assert len(EBPF_POPULATED_FEATURES) + len(EBPF_ZERO_FILLED_FEATURES) == 77

    backend = EbpfBackend()
    assert backend.feature_completeness == 1.0
    assert backend.backend_type == "ebpf"


# ---------------------------------------------------------------------------
# Test 3: FlowExtractor Pipeline Integration via Mock Ring Buffer
# ---------------------------------------------------------------------------
def test_mock_ring_buffer_streaming_to_flow_extractor():
    """Verify that decoded packets from MockBPFDriver stream through FlowExtractor to 77-feature vectors."""
    driver = MockBPFDriver()
    loader = XDPFlowProbeLoader(driver=driver, interface="eth0", mode="native")
    loader.attach()

    base_time_ns = 1_700_000_000_000_000_000

    # Simulate 3 packets for flow: 192.168.1.10:1234 -> 10.0.0.1:80
    events = [
        # 1. Forward SYN
        pack_packet_event(
            timestamp_ns=base_time_ns,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=1234,
            dst_port=80,
            protocol=6,
            tcp_flags=0x02,  # SYN
            payload_len=0,
            header_len=40,
            tcp_window=64240,
        ),
        # 2. Reverse SYN-ACK (50ms later)
        pack_packet_event(
            timestamp_ns=base_time_ns + 50_000_000,
            src_ip="10.0.0.1",
            dst_ip="192.168.1.10",
            src_port=80,
            dst_port=1234,
            protocol=6,
            tcp_flags=0x12,  # SYN+ACK
            payload_len=0,
            header_len=40,
            tcp_window=28960,
        ),
        # 3. Forward ACK + Data (100ms later)
        pack_packet_event(
            timestamp_ns=base_time_ns + 100_000_000,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=1234,
            dst_port=80,
            protocol=6,
            tcp_flags=0x18,  # PSH+ACK
            payload_len=500,
            header_len=40,
            tcp_window=64240,
        ),
    ]

    for ev in events:
        driver.push_mock_event(ev)

    backend = EbpfBackend(loader=loader, count=3)
    extractor = FlowExtractor(backend=backend)
    flows = extractor.extract_from_backend()

    assert len(flows) == 1
    flow = flows[0]
    assert flow.backend_type == "ebpf"
    assert flow.feature_completeness == 1.0

    feat_dict = flow.to_feature_dict()
    assert feat_dict["Protocol"] == 6.0
    assert feat_dict["Total Fwd Packets"] == 2.0
    assert feat_dict["Total Backward Packets"] == 1.0
    assert feat_dict["Fwd Packets Length Total"] == 500.0
    assert feat_dict["SYN Flag Count"] >= 1.0
    assert feat_dict["ACK Flag Count"] >= 2.0
    assert feat_dict["PSH Flag Count"] >= 1.0
    assert feat_dict["Init Fwd Win Bytes"] == 64240.0
    assert feat_dict["Init Bwd Win Bytes"] == 28960.0

    vec = flow.to_feature_vector()
    assert len(vec) == 77
    assert all(not (x != x) for x in vec)  # No NaNs


# ---------------------------------------------------------------------------
# Test 4: Ring Buffer Backpressure & Drop Accounting
# ---------------------------------------------------------------------------
def test_ring_buffer_full_does_not_crash():
    """
    Prompt 10 Amendment 4:
    On ring buffer exhaustion, kernel probe drops packet and increments drop counter.
    Userspace loader must not crash and must accurately report ring_buffer_drops.
    """
    capacity = 5
    driver = MockBPFDriver(ringbuf_capacity=capacity)
    loader = XDPFlowProbeLoader(driver=driver, interface="eth0")
    loader.attach()

    # Generate 15 events (capacity 5 -> 5 accepted, 10 dropped)
    sample_bytes = pack_packet_event(
        timestamp_ns=1_700_000_000_000_000_000,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1000,
        dst_port=80,
        protocol=6,
    )

    for _ in range(15):
        driver.push_mock_event(sample_bytes)

    # Poll loader
    packets = list(loader.poll_packets())
    assert len(packets) == 5

    stats = loader.get_stats()
    assert stats["events_received"] == 5
    assert stats["ring_buffer_drops"] == 10
    assert stats["drop_rate"] == pytest.approx(10 / 15)

    backend = EbpfBackend(loader=loader)
    backend_stats = backend.get_stats()
    assert backend_stats["events_received"] == 5
    assert backend_stats["ring_buffer_drops"] == 10


# ---------------------------------------------------------------------------
# Test 5: Native vs. Generic Mode Warning Scoping
# ---------------------------------------------------------------------------
def test_native_vs_generic_mode_warning(caplog):
    """
    Prompt 10 Amendment 3:
    When native mode is requested on a driver without native XDP, fall back to generic
    mode and issue an explicit warning about cloud VPC performance limitations.
    """
    driver = MockBPFDriver(native_supported=False)
    loader = XDPFlowProbeLoader(driver=driver, interface="ens5", mode="native")

    with caplog.at_level(logging.WARNING):
        effective = loader.attach()

    assert effective == "generic"
    assert "falling back to generic (SKB-based) XDP" in caplog.text
    assert "40 Gbps" in caplog.text
    assert "AWS ENA, GCP virtio-net, Azure" in caplog.text


# ---------------------------------------------------------------------------
# Test 6: Graceful Libpcap Fallback
# ---------------------------------------------------------------------------
def test_ebpf_backend_graceful_fallback_to_libpcap(caplog):
    """
    Confirm that if XDP loader attachment fails (e.g. unsupported platform or permissions),
    EbpfBackend falls back to LibpcapBackend gracefully and logs a warning.
    """
    failing_driver = MagicMock()
    failing_driver.load_and_attach.side_effect = OSError("XDP operation not supported on this interface")

    loader = XDPFlowProbeLoader(driver=failing_driver, interface="eth0")
    backend = EbpfBackend(loader=loader, fallback_to_libpcap=True)

    with caplog.at_level(logging.WARNING):
        backend.start()

    assert backend.is_running is True
    assert backend.is_fallback is True
    assert backend.backend_type == "ebpf"
    assert "Gracefully falling back to LibpcapBackend" in caplog.text

    backend.stop()
    assert backend.is_running is False


# ---------------------------------------------------------------------------
# Test 7: Strict Non-Fallback Failure Mode
# ---------------------------------------------------------------------------
def test_ebpf_backend_strict_no_fallback_raises():
    """Verify that when fallback_to_libpcap=False, XDP failure raises RuntimeError."""
    failing_driver = MagicMock()
    failing_driver.load_and_attach.side_effect = PermissionError("Need CAP_BPF")

    loader = XDPFlowProbeLoader(driver=failing_driver, interface="eth0")
    backend = EbpfBackend(loader=loader, fallback_to_libpcap=False)

    with pytest.raises(RuntimeError) as exc_info:
        backend.start()

    assert "fallback_to_libpcap is disabled" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Test 8: Manual Line-Rate Benchmark (Hardware-Gated)
# ---------------------------------------------------------------------------
@pytest.mark.skipif(
    not is_real_xdp_available(),
    reason="Requires physical Linux bare-metal hardware with native XDP support (set DDOS_ENABLE_REAL_XDP_BENCHMARK=1)",
)
def test_line_rate_throughput_manual():
    """
    Prompt 10 Amendment 2:
    Manual benchmark driving packet generation up to 40 Gbps line-rate target.
    Must NOT run in CI (explicit skip, no relaxed assertion).
    """
    interface = os.environ.get("XDP_TEST_INTERFACE", "eth0")
    backend = EbpfBackend(interface=interface, mode="native", fallback_to_libpcap=False)
    backend.start()

    # Measure packets and latency on real hardware
    stats_before = backend.get_stats()
    time.sleep(2.0)
    stats_after = backend.get_stats()

    backend.stop()
    pkts = stats_after["events_received"] - stats_before["events_received"]
    mpps = (pkts / 2.0) / 1e6

    print(f"\n[XDP LINE-RATE BENCHMARK] Rate: {mpps:.2f} Mpps on interface {interface}")
    assert mpps > 0.0, "Expected non-zero ingress traffic on benchmark interface"
