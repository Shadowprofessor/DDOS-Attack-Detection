# -*- coding: utf-8 -*-
"""
Test suite for PacketSanityFilter.

Validates the filter against the exact adversarial flows from Prompt 13's
test_adversarial_evasion.py that evaded ML detection.
"""
import sys
import os
import random
from typing import Dict, List

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.features.packet_sanity_filter import PacketSanityFilter, create_packet_from_features
from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES

# Copy of the adversarial flow generator from test_adversarial_evasion.py
def _create_zero_feature_dict() -> Dict[str, float]:
    """Initialize a zeroed dictionary conforming to 77 CICFlowMeter features."""
    return {name: 0.0 for name in CICFLOWMETER_FEATURE_NAMES}


def generate_fragmented_malformed_flows(n: int = 50, seed: int = 101) -> List[Dict[str, float]]:
    """
    Generate fragmented and malformed packet flows with illegal flags and boundary violations.

    Simulates evasion via protocol anomaly:
      - Tiny fragments (8 to 16 bytes total packet length)
      - Header length exceeding total packet length (RFC violation)
      - Contradictory flag combinations (SYN+FIN=0x03, NULL=0x00, or ALL flags)
      - Zero or non-standard window sizes
    """
    rng = random.Random(seed)
    flows = []
    for _ in range(n):
        f = _create_zero_feature_dict()
        f["Protocol"] = rng.choice([6.0, 17.0])  # TCP or UDP
        f["Destination Port"] = rng.choice([22.0, 53.0, 80.0, 443.0, 3389.0])

        duration_sec = rng.uniform(0.1, 5.0)
        duration_us = duration_sec * 1e6
        f["Flow Duration"] = duration_us

        fwd_pkts = rng.randint(10, 100)
        bwd_pkts = 0.0  # Asymmetric malformed requests typically generate no valid response
        f["Total Fwd Packets"] = float(fwd_pkts)
        f["Total Backward Packets"] = 0.0

        # Sub-minimum fragment lengths
        frag_len = rng.choice([8.0, 12.0, 16.0])
        f["Fwd Packet Length Min"] = frag_len
        f["Fwd Packet Length Max"] = frag_len + rng.uniform(0.0, 4.0)
        f["Fwd Packet Length Mean"] = frag_len
        f["Fwd Packet Length Std"] = rng.uniform(0.0, 2.0)
        f["Fwd Packets Length Total"] = frag_len * fwd_pkts

        f["Flow Bytes/s"] = f["Fwd Packets Length Total"] / duration_sec
        f["Flow Packets/s"] = fwd_pkts / duration_sec
        f["Fwd Packets/s"] = fwd_pkts / duration_sec
        f["Bwd Packets/s"] = 0.0

        # Contradictory TCP flags
        if f["Protocol"] == 6.0:
            anomaly_type = rng.choice(["syn_fin", "null", "all_flags"])
            if anomaly_type == "syn_fin":
                f["SYN Flag Count"] = float(fwd_pkts)
                f["FIN Flag Count"] = float(fwd_pkts)
            elif anomaly_type == "null":
                # No flags set
                pass
            elif anomaly_type == "all_flags":
                f["SYN Flag Count"] = float(fwd_pkts)
                f["FIN Flag Count"] = float(fwd_pkts)
                f["RST Flag Count"] = float(fwd_pkts)
                f["PSH Flag Count"] = float(fwd_pkts)
                f["ACK Flag Count"] = float(fwd_pkts)
                f["URG Flag Count"] = float(fwd_pkts)

        # Header anomaly: Header length disproportionate to packet length
        f["Fwd Header Length"] = float(fwd_pkts * rng.choice([32, 40, 60]))
        f["Down/Up Ratio"] = 0.0
        f["Init Fwd Win Bytes"] = float(rng.choice([0, 65535]))
        f["Avg Packet Size"] = frag_len
        f["Avg Fwd Segment Size"] = frag_len

        flows.append(f)
    return flows


def test_null_scan_detection():
    """Test detection of NULL scan (no TCP flags)."""
    filter = PacketSanityFilter()

    # Create a packet with no TCP flags
    class MockPacket:
        protocol = 6
        tcp_flags = 0
        payload_len = 0
        header_len = 40

    result = filter.check_packet(MockPacket())
    assert not result.is_valid
    assert "NULL_SCAN" in "; ".join(result.violations)
    print("✓ NULL scan detected")


def test_syn_fin_detection():
    """Test detection of SYN+FIN combination."""
    filter = PacketSanityFilter()

    class MockPacket:
        protocol = 6
        tcp_flags = 0x03  # SYN (0x02) + FIN (0x01)
        payload_len = 0
        header_len = 40

    result = filter.check_packet(MockPacket())
    assert not result.is_valid
    assert "SYN_FIN" in "; ".join(result.violations)
    print("✓ SYN+FIN detected")


def test_syn_rst_detection():
    """Test detection of SYN+RST combination."""
    filter = PacketSanityFilter()

    class MockPacket:
        protocol = 6
        tcp_flags = 0x06  # SYN (0x02) + RST (0x04)
        payload_len = 0
        header_len = 40

    result = filter.check_packet(MockPacket())
    assert not result.is_valid
    assert "SYN_RST" in "; ".join(result.violations)
    print("✓ SYN+RST detected")


def test_all_flags_detection():
    """Test detection of all flags set (XMAS scan)."""
    filter = PacketSanityFilter()

    class MockPacket:
        protocol = 6
        tcp_flags = 0xFF  # All flags
        payload_len = 0
        header_len = 40

    result = filter.check_packet(MockPacket())
    assert not result.is_valid
    assert "ALL_FLAGS" in "; ".join(result.violations)
    print("✓ ALL_FLAGS (XMAS) detected")


def test_fin_no_ack_detection():
    """Test detection of FIN without ACK."""
    filter = PacketSanityFilter()

    class MockPacket:
        protocol = 6
        tcp_flags = 0x01  # FIN only
        payload_len = 0
        header_len = 40

    result = filter.check_packet(MockPacket())
    assert not result.is_valid
    assert "FIN_NO_ACK" in "; ".join(result.violations)
    print("✓ FIN without ACK detected")


def test_psh_no_ack_detection():
    """Test detection of PSH without ACK."""
    filter = PacketSanityFilter()

    class MockPacket:
        protocol = 6
        tcp_flags = 0x08  # PSH only
        payload_len = 0
        header_len = 40

    result = filter.check_packet(MockPacket())
    assert not result.is_valid
    assert "PSH_NO_ACK" in "; ".join(result.violations)
    print("✓ PSH without ACK detected")


def test_urg_no_ack_detection():
    """Test detection of URG without ACK."""
    filter = PacketSanityFilter()

    class MockPacket:
        protocol = 6
        tcp_flags = 0x20  # URG only
        payload_len = 0
        header_len = 40

    result = filter.check_packet(MockPacket())
    assert not result.is_valid
    assert "URG_NO_ACK" in "; ".join(result.violations)
    print("✓ URG without ACK detected")


def test_rst_with_other_detection():
    """Test detection of RST combined with FIN/PSH/URG."""
    filter = PacketSanityFilter()

    class MockPacket:
        protocol = 6
        tcp_flags = 0x05  # RST + FIN
        payload_len = 0
        header_len = 40

    result = filter.check_packet(MockPacket())
    assert not result.is_valid
    assert "RST_WITH_OTHER" in "; ".join(result.violations)
    print("✓ RST with FIN/PSH/URG detected")


def test_ecn_without_syn_detection():
    """Test detection of ECE/CWR without SYN."""
    filter = PacketSanityFilter()

    class MockPacket:
        protocol = 6
        tcp_flags = 0x40  # ECE only
        payload_len = 0
        header_len = 40

    result = filter.check_packet(MockPacket())
    assert not result.is_valid
    assert "ECN_WITHOUT_SYN" in "; ".join(result.violations)
    print("✓ ECN without SYN detected")


def test_header_gt_total_detection():
    """Test detection of header length > total packet length."""
    filter = PacketSanityFilter()

    class MockPacket:
        def __init__(self):
            self.protocol = 6
            self.tcp_flags = 0x12  # SYN+ACK
            self.payload_len = 0
            self.header_len = 100  # Header > payload

    result = filter.check_packet(MockPacket())
    assert not result.is_valid
    assert "HEADER_GT_PAYLOAD" in "; ".join(result.violations)
    print("✓ Header length > payload length detected")


def test_sub_min_payload_detection():
    """Test detection of sub-minimum payload sizes."""
    filter = PacketSanityFilter(min_payload_bytes=8)

    class MockPacket:
        protocol = 6
        tcp_flags = 0x12  # SYN+ACK
        payload_len = 4  # Sub-minimum
        header_len = 40

    result = filter.check_packet(MockPacket())
    assert not result.is_valid
    assert "SUB_MIN_PAYLOAD" in "; ".join(result.violations)
    print("✓ Sub-minimum payload detected")


def test_excessive_tcp_header_detection():
    """Test detection of excessive TCP header."""
    filter = PacketSanityFilter()

    class MockPacket:
        protocol = 6
        tcp_flags = 0x12  # SYN+ACK
        payload_len = 100
        header_len = 150  # Excessive header

    result = filter.check_packet(MockPacket())
    assert not result.is_valid
    assert "EXCESSIVE_TCP_HEADER" in "; ".join(result.violations)
    print("✓ Excessive TCP header detected")


def test_zero_payload_with_data_flags():
    """Test detection of zero payload with PSH/URG flags."""
    filter = PacketSanityFilter()

    class MockPacket:
        protocol = 6
        tcp_flags = 0x28  # PSH + ACK
        payload_len = 0
        header_len = 40

    result = filter.check_packet(MockPacket())
    assert not result.is_valid
    assert "ZERO_PAYLOAD_WITH_DATA_FLAGS" in "; ".join(result.violations)
    print("✓ Zero payload with data flags detected")


def test_fragment_mf_flag_detection():
    """Test detection of IP MF (More Fragments) flag."""
    filter = PacketSanityFilter()

    class MockPacket:
        protocol = 6
        tcp_flags = 0x12
        payload_len = 100
        header_len = 40
        ip_flags = 0x1  # MF flag
        ip_frag_offset = 0

    result = filter.check_packet(MockPacket())
    assert not result.is_valid
    assert "IP_MF_FLAG" in "; ".join(result.violations)
    print("✓ IP MF flag detected")


def test_fragment_offset_detection():
    """Test detection of non-zero fragment offset."""
    filter = PacketSanityFilter()

    class MockPacket:
        protocol = 6
        tcp_flags = 0x12
        payload_len = 100
        header_len = 40
        ip_flags = 0x0
        ip_frag_offset = 1480  # Not first fragment

    result = filter.check_packet(MockPacket())
    assert not result.is_valid
    assert "IP_FRAGMENT" in "; ".join(result.violations)
    print("✓ Fragment offset detected")


def test_tiny_first_fragment_detection():
    """Test detection of tiny first fragment."""
    filter = PacketSanityFilter(min_payload_bytes=8)

    class MockPacket:
        protocol = 6
        tcp_flags = 0x12
        payload_len = 4  # Tiny payload
        header_len = 40
        ip_flags = 0x1  # MF flag
        ip_frag_offset = 0  # First fragment

    result = filter.check_packet(MockPacket())
    assert not result.is_valid
    assert "TINY_FIRST_FRAGMENT" in "; ".join(result.violations)
    print("✓ Tiny first fragment detected")


def test_valid_packet_passes():
    """Test that a valid normal packet passes the filter."""
    filter = PacketSanityFilter()

    class MockPacket:
        protocol = 6
        tcp_flags = 0x12  # SYN+ACK (normal)
        payload_len = 100
        header_len = 40
        ip_flags = 0x0
        ip_frag_offset = 0

    result = filter.check_packet(MockPacket())
    assert result.is_valid
    assert result.violation_count == 0
    print("✓ Valid packet passes")


def test_udp_packet_basic_checks():
    """Test that UDP packets get basic size checks."""
    filter = PacketSanityFilter()

    class MockPacket:
        protocol = 17  # UDP
        tcp_flags = 0
        payload_len = 50
        header_len = 28  # IP (20) + UDP (8)

    result = filter.check_packet(MockPacket())
    # Should pass basic checks
    assert result.is_valid or result.violation_count == 0
    print("✓ UDP packet basic checks")


def test_icmp_packet_basic_checks():
    """Test that ICMP packets get basic size checks."""
    filter = PacketSanityFilter()

    class MockPacket:
        protocol = 1  # ICMP
        tcp_flags = 0
        payload_len = 56
        header_len = 28  # IP (20) + ICMP (8)

    result = filter.check_packet(MockPacket())
    assert result.is_valid
    print("✓ ICMP packet basic checks")


def test_adversarial_fragmented_malformed_flows():
    """
    CRITICAL TEST: Re-run the exact fragmented/malformed flows from Prompt 13
    that scored ~95% Benign and evaded ML detection.

    This validates the filter catches what the ensemble missed.
    """
    filter = PacketSanityFilter()

    # Generate the exact same adversarial flows from Prompt 13
    flows = generate_fragmented_malformed_flows(n=50, seed=101)

    caught = 0
    evaded = 0
    violation_types = {
        "tcp_flags": 0,
        "size_anomalies": 0,
        "fragmentation": 0
    }

    for flow in flows:
        # Convert flow features to mock packet for sanity checking
        mock_pkt = create_packet_from_features(flow)
        result = filter.check_packet(mock_pkt)

        if not result.is_valid:
            caught += 1
            # Categorize violations
            for v in result.violations:
                if v.startswith("SYN_FIN") or v.startswith("SYN_RST") or v.startswith("NULL_SCAN") or v.startswith("FIN_NO_ACK") or v.startswith("PSH_NO_ACK") or v.startswith("URG_NO_ACK") or v.startswith("RST_WITH_OTHER") or v.startswith("ECN_WITHOUT_SYN") or v.startswith("ALL_FLAGS") or v.startswith("SYN_FIN_RST"):
                    violation_types["tcp_flags"] += 1
                elif v.startswith("HEADER_GT") or v.startswith("SUB_MIN_PAYLOAD") or v.startswith("EXCESSIVE_TCP_HEADER") or v.startswith("ZERO_PAYLOAD_WITH_DATA_FLAGS"):
                    violation_types["size_anomalies"] += 1
                elif v.startswith("IP_MF_FLAG") or v.startswith("IP_FRAGMENT") or v.startswith("TINY_FIRST_FRAGMENT"):
                    violation_types["fragmentation"] += 1
        else:
            evaded += 1

    catch_rate = (caught / len(flows)) * 100

    print(f"\n=== Adversarial Fragmented/Malformed Flow Test ===")
    print(f"Total flows tested: {len(flows)}")
    print(f"Caught by sanity filter: {caught} ({catch_rate:.1f}%)")
    print(f"Evaded sanity filter: {evaded} ({100-catch_rate:.1f}%)")
    print(f"Violation types found:")
    print(f"  TCP Flag Violations: {violation_types['tcp_flags']}")
    print(f"  Size/Anomaly Violations: {violation_types['size_anomalies']}")
    print(f"  Fragmentation Violations: {violation_types['fragmentation']}")

    # The ensemble scored 0% detection (all 50 flows scored Benign)
    # The sanity filter should catch a very high percentage
    # We expect at least 90% catch rate on these adversarial flows
    assert catch_rate >= 90.0, f"Catch rate {catch_rate:.1f}% below 90% threshold"

    print(f"✓ Sanity filter catches {catch_rate:.1f}% of adversarial flows (ensemble caught 0%) with breakdown:")
    print(f"  TCP Flag Violations: {violation_types['tcp_flags']}")
    print(f"  Size/Anomaly Violations: {violation_types['size_anomalies']}")
    print(f"  Fragmentation Violations: {violation_types['fragmentation']}")

    return catch_rate
    """
    CRITICAL TEST: Re-run the exact fragmented/malformed flows from Prompt 13
    that scored ~95% Benign and evaded ML detection.

    This validates the filter catches what the ensemble missed.
    """
    filter = PacketSanityFilter()

    # Generate the exact same adversarial flows from Prompt 13
    flows = generate_fragmented_malformed_flows(n=50, seed=101)

    caught = 0
    evaded = 0
    violation_types = {}

    for flow in flows:
        # Convert flow features to mock packet for sanity checking
        mock_pkt = create_packet_from_features(flow)
        result = filter.check_packet(mock_pkt)

        if not result.is_valid:
            caught += 1
            for v in result.violations:
                violation_types[v] = violation_types.get(v, 0) + 1
        else:
            evaded += 1

    catch_rate = (caught / len(flows)) * 100

    print(f"\n=== Adversarial Fragmented/Malformed Flow Test ===")
    print(f"Total flows tested: {len(flows)}")
    print(f"Caught by sanity filter: {caught} ({catch_rate:.1f}%)")
    print(f"Evaded sanity filter: {evaded} ({100-catch_rate:.1f}%)")
    print(f"Violation types found:")
    for vt, count in sorted(violation_types.items(), key=lambda x: -x[1]):
        print(f"  {vt}: {count}")

    # The ensemble scored 0% detection (all 50 flows scored Benign)
    # The sanity filter should catch a very high percentage
    # We expect at least 90% catch rate on these adversarial flows
    assert catch_rate >= 90.0, f"Catch rate {catch_rate:.1f}% below 90% threshold"

    print(f"✓ Sanity filter catches {catch_rate:.1f}% of adversarial flows (ensemble caught 0%)")

    return catch_rate


def test_flow_level_checks():
    """Test flow-level sanity checks against adversarial flows."""
    filter = PacketSanityFilter()

    flows = generate_fragmented_malformed_flows(n=50, seed=101)

    caught = 0
    for flow in flows:
        result = filter.check_flow(flow)
        if not result.is_valid:
            caught += 1

    catch_rate = (caught / len(flows)) * 100
    print(f"\n=== Flow-Level Sanity Check ===")
    print(f"Total flows: {len(flows)}")
    print(f"Caught by flow-level check: {caught} ({catch_rate:.1f}%)")

    # Flow-level checks should also catch most
    assert catch_rate >= 80.0
    print("✓ Flow-level checks catch majority of adversarial flows")


def test_filter_integration_with_flow_extractor():
    """Test that PacketSanityFilter integrates with FlowExtractor."""
    from src.features.flow_extractor import FlowExtractor, Packet

    filter = PacketSanityFilter()
    extractor = FlowExtractor(sanity_filter=filter)

    # Valid packet should be processed
    valid_pkt = Packet(
        timestamp=1.0,
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        protocol=6,
        payload_len=100,
        header_len=40,
        tcp_flags=0x12,  # SYN+ACK
        tcp_window=65535,
    )

    expired = extractor.process_packet(valid_pkt)
    assert expired is None  # No flow expired yet
    assert extractor.active_flow_count == 1

    # Invalid packet (SYN+FIN) should be rejected
    invalid_pkt = Packet(
        timestamp=2.0,
        src_ip="192.168.1.2",
        dst_ip="10.0.0.1",
        src_port=12346,
        dst_port=80,
        protocol=6,
        payload_len=0,
        header_len=40,
        tcp_flags=0x03,  # SYN+FIN
        tcp_window=0,
    )

    expired = extractor.process_packet(invalid_pkt)
    # Packet should be flagged and NOT added to flow
    assert hasattr(invalid_pkt, 'sanity_violation')
    assert invalid_pkt.sanity_violation is True
    assert 'sanity_result' in dir(invalid_pkt) or hasattr(invalid_pkt, 'sanity_result')

    # Flow count should still be 1 (invalid packet not added)
    assert extractor.active_flow_count == 1

    print("✓ FlowExtractor integration works - invalid packets flagged and excluded")


def test_filter_stats_tracking():
    """Test that filter tracks statistics correctly."""
    filter = PacketSanityFilter()
    filter.reset_stats()

    class MockPacket:
        protocol = 6
        tcp_flags = 0x03
        payload_len = 0
        header_len = 40

    # Check 5 invalid packets
    for _ in range(5):
        filter.check_packet(MockPacket())

    # Check 3 valid packets
    class ValidPacket:
        protocol = 6
        tcp_flags = 0x12
        payload_len = 100
        header_len = 40

    for _ in range(3):
        filter.check_packet(ValidPacket())

    stats = filter.get_stats()
    assert stats["total_checked"] == 8
    assert stats["flagged"] == 5
    # The violation keys include the full message
    syn_fin_key = "SYN_FIN: SYN and FIN flags set simultaneously"
    assert syn_fin_key in stats["violations_by_type"]
    assert stats["violations_by_type"][syn_fin_key] == 5

    print("✓ Statistics tracking works correctly")


def generate_fragmentation_evasion_flows(n: int = 20, seed: int = 202) -> List[Dict[str, float]]:
    """
    Generate flows specifically designed to test IP fragmentation evasion detection:
      - Non-first fragments with offset > 0 (Condition A -> IP_FRAGMENT)
      - Tiny fragments with MF flag set and total length < 576 bytes (Condition B -> TINY_MF_FRAGMENT)
      - Fragment floods (>50 fragments in a 1-second window) (Condition C -> FRAGMENT_FLOOD)
      - Combined non-first tiny fragments with MF set (Condition A + B)
    """
    rng = random.Random(seed)
    flows = []

    # 1. Condition A: 5 flows with ip_frag_offset > 0, ip_flags = 0x0 (non-first fragment)
    for i in range(5):
        f = _create_zero_feature_dict()
        f["Protocol"] = 6.0
        f["Destination Port"] = 80.0
        duration_sec = 1.0
        f["Flow Duration"] = duration_sec * 1e6
        fwd_pkts = 10.0
        f["Total Fwd Packets"] = fwd_pkts
        f["Total Backward Packets"] = 0.0

        # Normal packet size >= 576 bytes so Condition B is not triggered
        payload_len = 600.0
        f["Fwd Packet Length Min"] = payload_len
        f["Fwd Packet Length Max"] = payload_len
        f["Fwd Packet Length Mean"] = payload_len
        f["Fwd Packets Length Total"] = payload_len * fwd_pkts
        f["Fwd Header Length"] = 40.0 * fwd_pkts

        f["Flow Bytes/s"] = f["Fwd Packets Length Total"] / duration_sec
        f["Flow Packets/s"] = fwd_pkts / duration_sec
        f["Fwd Packets/s"] = fwd_pkts / duration_sec
        f["Avg Packet Size"] = payload_len

        # Fragmentation fields
        f["ip_flags"] = 0.0
        f["ip_frag_offset"] = float(1480 * (i + 1))
        f["flow_id"] = f"frag-offset-flow-{i}"
        f["src_ip"] = f"192.168.1.{10 + i}"
        f["dst_ip"] = "10.0.0.1"
        f["timestamp"] = 1000.0 + float(i)
        flows.append(f)

    # 2. Condition B: 5 flows with ip_flags = 0x1 (MF set) and total packet length < 576 bytes
    for i in range(5):
        f = _create_zero_feature_dict()
        f["Protocol"] = 6.0
        f["Destination Port"] = 443.0
        duration_sec = 1.0
        f["Flow Duration"] = duration_sec * 1e6
        fwd_pkts = 10.0
        f["Total Fwd Packets"] = fwd_pkts
        f["Total Backward Packets"] = 0.0

        # Tiny payload: total pkt len = 40 + 20 = 60 bytes (< 576 bytes RFC 791 limit)
        payload_len = 20.0
        f["Fwd Packet Length Min"] = payload_len
        f["Fwd Packet Length Max"] = payload_len
        f["Fwd Packet Length Mean"] = payload_len
        f["Fwd Packets Length Total"] = payload_len * fwd_pkts
        f["Fwd Header Length"] = 40.0 * fwd_pkts

        f["Flow Bytes/s"] = f["Fwd Packets Length Total"] / duration_sec
        f["Flow Packets/s"] = fwd_pkts / duration_sec
        f["Fwd Packets/s"] = fwd_pkts / duration_sec
        f["Avg Packet Size"] = payload_len

        # Fragmentation fields
        f["ip_flags"] = 1.0  # MF bit set
        f["ip_frag_offset"] = 0.0
        f["flow_id"] = f"tiny-mf-flow-{i}"
        f["src_ip"] = f"192.168.2.{10 + i}"
        f["dst_ip"] = "10.0.0.1"
        f["timestamp"] = 2000.0 + float(i)
        flows.append(f)

    # 3. Condition C: 5 flows simulating fragment flood (>50 fragments in 1s window)
    for i in range(5):
        f = _create_zero_feature_dict()
        f["Protocol"] = 6.0
        f["Destination Port"] = 80.0
        duration_sec = 0.5
        f["Flow Duration"] = duration_sec * 1e6
        fwd_pkts = 55.0
        f["Total Fwd Packets"] = fwd_pkts
        f["Total Backward Packets"] = 0.0

        # Normal size >= 576 bytes so Condition B is not triggered
        payload_len = 600.0
        f["Fwd Packet Length Min"] = payload_len
        f["Fwd Packet Length Max"] = payload_len
        f["Fwd Packet Length Mean"] = payload_len
        f["Fwd Packets Length Total"] = payload_len * fwd_pkts
        f["Fwd Header Length"] = 40.0 * fwd_pkts

        f["Flow Bytes/s"] = f["Fwd Packets Length Total"] / duration_sec
        f["Flow Packets/s"] = fwd_pkts / duration_sec
        f["Fwd Packets/s"] = fwd_pkts / duration_sec
        f["Avg Packet Size"] = payload_len

        # Fragmentation fields
        f["ip_flags"] = 1.0  # MF bit set
        f["ip_frag_offset"] = 0.0
        f["flow_id"] = "frag-flood-shared-flow"
        f["src_ip"] = "192.168.3.100"
        f["dst_ip"] = "10.0.0.1"
        f["timestamp"] = 3000.0 + float(i) * 0.05
        f["is_flood"] = 1.0
        flows.append(f)

    # 4. Combined Condition A + B: 5 flows with both MF set and offset > 0, total len < 576 bytes
    for i in range(5):
        f = _create_zero_feature_dict()
        f["Protocol"] = 6.0
        f["Destination Port"] = 8080.0
        duration_sec = 1.0
        f["Flow Duration"] = duration_sec * 1e6
        fwd_pkts = 10.0
        f["Total Fwd Packets"] = fwd_pkts
        f["Total Backward Packets"] = 0.0

        payload_len = 30.0
        f["Fwd Packet Length Min"] = payload_len
        f["Fwd Packet Length Max"] = payload_len
        f["Fwd Packet Length Mean"] = payload_len
        f["Fwd Packets Length Total"] = payload_len * fwd_pkts
        f["Fwd Header Length"] = 40.0 * fwd_pkts

        f["Flow Bytes/s"] = f["Fwd Packets Length Total"] / duration_sec
        f["Flow Packets/s"] = fwd_pkts / duration_sec
        f["Fwd Packets/s"] = fwd_pkts / duration_sec
        f["Avg Packet Size"] = payload_len

        # Fragmentation fields
        f["ip_flags"] = 1.0
        f["ip_frag_offset"] = float(1480 * (i + 1))
        f["flow_id"] = f"frag-combo-flow-{i}"
        f["src_ip"] = f"192.168.4.{10 + i}"
        f["dst_ip"] = "10.0.0.1"
        f["timestamp"] = 4000.0 + float(i)
        flows.append(f)

    return flows[:n]


def test_adversarial_fragmentation_evasion():
    """
    Test packet sanity filter on adversarial IP fragmentation evasion flows.
    Validates detection across:
      - IP_FRAGMENT (Condition A: offset > 0)
      - TINY_MF_FRAGMENT (Condition B: MF set and total length < 576 bytes)
      - FRAGMENT_FLOOD (Condition C: >50 fragments in 1-second window)
    """
    filter = PacketSanityFilter()
    flows = generate_fragmentation_evasion_flows(n=20, seed=202)

    caught = 0
    evaded = 0
    violation_types = {
        "IP_FRAGMENT": 0,
        "TINY_MF_FRAGMENT": 0,
        "FRAGMENT_FLOOD": 0,
    }

    for flow in flows:
        # For fragment flood flows, simulate arrival of 50 prior fragments within 1s window
        if flow.get("is_flood") and flow["flow_id"] not in filter._frag_tracker:
            filter._frag_tracker[flow["flow_id"]] = [
                flow["timestamp"] - 0.01 * (50 - j) for j in range(50)
            ]

        mock_pkt = create_packet_from_features(flow)
        result = filter.check_packet(mock_pkt)

        if not result.is_valid:
            caught += 1
            for v in result.violations:
                if v.startswith("IP_FRAGMENT"):
                    violation_types["IP_FRAGMENT"] += 1
                elif v.startswith("TINY_MF_FRAGMENT"):
                    violation_types["TINY_MF_FRAGMENT"] += 1
                elif v.startswith("FRAGMENT_FLOOD"):
                    violation_types["FRAGMENT_FLOOD"] += 1
        else:
            evaded += 1

    catch_rate = (caught / len(flows)) * 100

    print("\n=== Adversarial Fragmentation Evasion Test ===")
    print(f"Total flows tested: {len(flows)}")
    print(f"Caught by sanity filter: {caught} ({catch_rate:.1f}%)")
    print(f"Evaded sanity filter: {evaded} ({100 - catch_rate:.1f}%)")
    print("Fragmentation violation breakdown:")
    print(f"  IP_FRAGMENT: {violation_types['IP_FRAGMENT']}")
    print(f"  TINY_MF_FRAGMENT: {violation_types['TINY_MF_FRAGMENT']}")
    print(f"  FRAGMENT_FLOOD: {violation_types['FRAGMENT_FLOOD']}")

    assert catch_rate >= 90.0, f"Catch rate {catch_rate:.1f}% below 90% threshold"
    print(f"[PASS] Sanity filter catches {catch_rate:.1f}% of fragmentation evasion flows")


if __name__ == "__main__":
    # Run all tests
    print("Running PacketSanityFilter tests...\n")

    test_null_scan_detection()
    test_syn_fin_detection()
    test_syn_rst_detection()
    test_all_flags_detection()
    test_fin_no_ack_detection()
    test_psh_no_ack_detection()
    test_urg_no_ack_detection()
    test_rst_with_other_detection()
    test_ecn_without_syn_detection()
    test_header_gt_total_detection()
    test_sub_min_payload_detection()
    test_excessive_tcp_header_detection()
    test_zero_payload_with_data_flags()
    test_fragment_mf_flag_detection()
    test_fragment_offset_detection()
    test_tiny_first_fragment_detection()
    test_valid_packet_passes()
    test_udp_packet_basic_checks()
    test_icmp_packet_basic_checks()

    print("\n--- Adversarial Flow Validation ---")
    catch_rate = test_adversarial_fragmented_malformed_flows()
    test_flow_level_checks()
    test_filter_integration_with_flow_extractor()
    test_filter_stats_tracking()

    print(f"\n=== ALL TESTS PASSED ===")
    print(f"Adversarial catch rate: {catch_rate:.1f}%")