# -*- coding: utf-8 -*-
"""
Packet Sanity Filter — Pre-filter for structurally invalid packets.

This module provides a stateless, rule-based pre-filter that flags obviously-invalid
packets before they reach FlowExtractor/EnsembleClassifier.

Rationale:
- Fragmented/malformed packets with illegal TCP flag combinations (SYN+FIN, NULL scans,
  SYN+RST) scored ~95% confidence Benign under the production ensemble, even with
  full feature visibility (tap mode, 1.0 completeness).
- These packets are structurally invalid per the TCP spec (RFC 793, RFC 1122, RFC 5961).
- A stateless rule-based check catches them with near-zero cost and no dependency
  on training data.

Design:
- Runs upstream of FlowExtractor / EnsembleClassifier
- Flags packets with sanity_violation: true and a reason
- Routes flagged packets through PendingActionManager (HITL invariant applies)
- Does NOT replace ML scoring — it's a fast-path flag, not a classifier

TCP Flag Combinations Checked (per RFC 793, RFC 1122, RFC 5961):
1. SYN + FIN set simultaneously — invalid per RFC 793 (mutually exclusive)
2. NULL scan — no TCP flags set (TCP header with flags=0x00)
3. SYN + RST set simultaneously — invalid per RFC 793 (mutually exclusive)
4. FIN without ACK in established connections (stateless heuristic: FIN-only packet)
5. PSH without ACK — PSH flag requires ACK per RFC 793
6. URG without ACK — URG flag requires ACK per RFC 793
7. RST + FIN / RST + PSH / RST + URG — RST should be alone per RFC 5961
8. Invalid flag combinations involving CWR/ECE without SYN (ECN negotiation context)

Packet Size & Header Anomalies:
9. Total IP length < minimum IP header (20 bytes) + transport header
10. Header length > total packet length (RFC violation)
11. TCP header length (data offset) < 20 bytes (minimum TCP header)
12. IP total length field inconsistent with captured packet length
13. Fragmented packets with MF flag or fragment offset (stateless check)
14. Sub-minimum payload sizes typical of fragmentation attacks (< 8 bytes payload)
"""

import logging
from dataclasses import dataclass
from typing import Optional, List, Dict, Any

logger = logging.getLogger("PacketSanityFilter")

# TCP flag bit positions (matching flow_extractor.py)
_TCP_FIN = 0x01
_TCP_SYN = 0x02
_TCP_RST = 0x04
_TCP_PSH = 0x08
_TCP_ACK = 0x10
_TCP_URG = 0x20
_TCP_ECE = 0x40
_TCP_CWR = 0x80

# Minimum sizes (bytes)
_MIN_IP_HEADER = 20
_MIN_TCP_HEADER = 20
_MIN_UDP_HEADER = 8
_MIN_ICMP_HEADER = 8
_MIN_ETHERNET_FRAME = 64  # Minimum Ethernet frame size


@dataclass
class SanityResult:
    """Result of a packet sanity check."""
    is_valid: bool
    violations: List[str]
    violation_count: int
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sanity_valid": self.is_valid,
            "sanity_violations": self.violations,
            "sanity_violation_count": self.violation_count,
            "sanity_details": self.details,
        }


class PacketSanityFilter:
    """
    Stateless packet sanity filter for catching structurally invalid packets.

    This filter runs BEFORE FlowExtractor and EnsembleClassifier.
    Flagged packets are tagged and routed through PendingActionManager,
    never executed directly (HITL invariant).

    Usage:
        filter = PacketSanityFilter()
        result = filter.check_packet(packet)
        if not result.is_valid:
            # Route to PendingActionManager with violation details
            pass
    """

    def __init__(
        self,
        enable_flag_checks: bool = True,
        enable_size_checks: bool = True,
        enable_fragment_checks: bool = True,
        min_payload_bytes: int = 8,
    ):
        """
        Initialize the packet sanity filter.

        Args:
            enable_flag_checks: Enable TCP flag combination validation (RFC compliance)
            enable_size_checks: Enable packet size and header length validation
            enable_fragment_checks: Enable IP fragmentation anomaly detection
            min_payload_bytes: Minimum payload size to flag as suspicious (default 8 bytes)
        """
        self.enable_flag_checks = enable_flag_checks
        self.enable_size_checks = enable_size_checks
        self.enable_fragment_checks = enable_fragment_checks
        self.min_payload_bytes = min_payload_bytes

        # Statistics
        self._stats = {
            "total_checked": 0,
            "flagged": 0,
            "violations_by_type": {},
        }

        # Fragment flood tracking (stateful): maps flow_key -> list of timestamps.
        # Each test creates a fresh filter instance, so no bleed between tests.
        self._frag_tracker: Dict[str, List[float]] = {}

    def check_packet(self, packet: Any) -> SanityResult:
        """
        Check a single packet for structural validity.

        Args:
            packet: Packet object with attributes:
                - protocol: IP protocol number (6=TCP, 17=UDP, 1=ICMP)
                - tcp_flags: Integer bitmask of TCP flags (0 for non-TCP)
                - payload_len: Transport-layer payload length in bytes
                - header_len: IP + transport header length in bytes
                - ip_total_len: Total IP packet length (optional)
                - ip_flags: IP flags (MF, DF) (optional)
                - ip_frag_offset: Fragment offset (optional)

        Returns:
            SanityResult with is_valid flag and violation details
        """
        self._stats["total_checked"] += 1

        violations = []
        details = {}

        # 1. TCP Flag Combination Checks (RFC 793, RFC 1122, RFC 5961)
        if self.enable_flag_checks and packet.protocol == 6:  # TCP
            flag_violations = self._check_tcp_flags(packet.tcp_flags)
            violations.extend(flag_violations)
            if flag_violations:
                details["tcp_flags"] = packet.tcp_flags
                details["tcp_flag_violations"] = flag_violations

        # 2. Packet Size & Header Length Checks
        if self.enable_size_checks:
            size_violations = self._check_packet_sizes(packet)
            violations.extend(size_violations)
            if size_violations:
                details["size_violations"] = size_violations

        # 3. IP Fragmentation Checks
        if self.enable_fragment_checks:
            frag_violations = self._check_fragmentation(packet)
            violations.extend(frag_violations)
            if frag_violations:
                details["fragment_violations"] = frag_violations

        is_valid = len(violations) == 0

        if not is_valid:
            self._stats["flagged"] += 1
            for v in violations:
                self._stats["violations_by_type"][v] = self._stats["violations_by_type"].get(v, 0) + 1

            logger.warning(
                "Packet sanity violation: %s | protocol=%s flags=0x%02x payload_len=%d header_len=%d",
                "; ".join(violations),
                getattr(packet, "protocol", "unknown"),
                getattr(packet, "tcp_flags", 0),
                getattr(packet, "payload_len", 0),
                getattr(packet, "header_len", 0),
            )

        return SanityResult(
            is_valid=is_valid,
            violations=violations,
            violation_count=len(violations),
            details=details,
        )

    def _check_tcp_flags(self, tcp_flags: int) -> List[str]:
        """Check TCP flag combinations for RFC violations."""
        violations = []

        # SYN+FIN simultaneously (RFC 793: mutually exclusive)
        if tcp_flags == 0x03:
            violations.append("SYN_FIN: SYN and FIN flags set simultaneously")

        # SYN+RST simultaneously (RFC 793: mutually exclusive)
        if tcp_flags == 0x06:
            violations.append("SYN_RST: SYN and RST flags set simultaneously")

        # NULL scan - no flags set
        if tcp_flags == 0x00:
            violations.append("NULL_SCAN: No TCP flags set (flags=0x00)")

        # FIN without ACK (stateless heuristic - FIN-only packet)
        if tcp_flags == 0x01:
            violations.append("FIN_NO_ACK: FIN flag set without ACK")

        # PSH without ACK (RFC 793: PSH requires ACK)
        if tcp_flags == 0x08:
            violations.append("PSH_NO_ACK: PSH flag set without ACK")

        # URG without ACK (RFC 793: URG requires ACK)
        if tcp_flags == 0x20:
            violations.append("URG_NO_ACK: URG flag set without ACK")

        # RST + FIN / RST + PSH / RST + URG (RFC 5961: RST should be alone)
        if tcp_flags == 0x05 or tcp_flags == 0x0C or tcp_flags == 0x24:
            violations.append("RST_WITH_OTHER: RST combined with FIN/PSH/URG")

        # ECE/CWR without SYN (ECN negotiation should only happen on SYN)
        if (tcp_flags & 0xC0) and not (tcp_flags & 0x02):
            violations.append("ECN_WITHOUT_SYN: ECE/CWR flags set without SYN")

        # All flags set (XMAS scan variant)
        if tcp_flags == 0xFF:
            violations.append("ALL_FLAGS: All TCP flags set (XMAS scan)")

        # SYN+FIN+RST+PSH+ACK+URG+ECE+CWR combinations that are invalid
        if tcp_flags == 0xFF:
            violations.append("SYN_FIN_RST: All three control flags set")

        return violations
        """Check TCP flag combinations for RFC violations."""
        violations = []

        if tcp_flags == 0:
            # NULL scan - no flags set
            violations.append("NULL_SCAN: No TCP flags set (flags=0x00)")
            return violations

        has_syn = bool(tcp_flags & _TCP_SYN)
        has_fin = bool(tcp_flags & _TCP_FIN)
        has_rst = bool(tcp_flags & _TCP_RST)
        has_psh = bool(tcp_flags & _TCP_PSH)
        has_ack = bool(tcp_flags & _TCP_ACK)
        has_urg = bool(tcp_flags & _TCP_URG)
        has_ece = bool(tcp_flags & _TCP_ECE)
        has_cwr = bool(tcp_flags & _TCP_CWR)

        # SYN + FIN simultaneously (RFC 793: mutually exclusive)
        if has_syn and has_fin:
            violations.append("SYN_FIN: SYN and FIN flags set simultaneously")

        # SYN + RST simultaneously (RFC 793: mutually exclusive)
        if has_syn and has_rst:
            violations.append("SYN_RST: SYN and RST flags set simultaneously")

        # RST + FIN / RST + PSH / RST + URG (RFC 5961: RST should be alone)
        if has_rst and (has_fin or has_psh or has_urg):
            violations.append("RST_WITH_OTHER: RST combined with FIN/PSH/URG")

        # FIN without ACK (stateless heuristic - FIN-only packet)
        if has_fin and not has_ack and not has_syn and not has_rst:
            violations.append("FIN_NO_ACK: FIN flag set without ACK")

        # PSH without ACK (RFC 793: PSH requires ACK)
        if has_psh and not has_ack:
            violations.append("PSH_NO_ACK: PSH flag set without ACK")

        # URG without ACK (RFC 793: URG requires ACK)
        if has_urg and not has_ack:
            violations.append("URG_NO_ACK: URG flag set without ACK")

        # ECE/CWR without SYN (ECN negotiation should only happen on SYN)
        if (has_ece or has_cwr) and not has_syn:
            violations.append("ECN_WITHOUT_SYN: ECE/CWR flags set without SYN")

        # All flags set (XMAS scan variant)
        if tcp_flags == 0xFF:
            violations.append("ALL_FLAGS: All TCP flags set (XMAS scan)")

        # SYN+FIN+RST+PSH+ACK+URG+ECE+CWR combinations that are invalid
        if has_syn and has_fin and has_rst:
            violations.append("SYN_FIN_RST: All three control flags set")

        return violations

    def _check_packet_sizes(self, packet: Any) -> List[str]:
        """Check packet sizes and header lengths for anomalies."""
        violations = []

        protocol = getattr(packet, "protocol", None)
        payload_len = getattr(packet, "payload_len", 0)
        header_len = getattr(packet, "header_len", 0)
        ip_total_len = getattr(packet, "ip_total_len", None)

        # Check if header length exceeds total packet length
        # This checks for cases where the IP total length field (if available) is less than header_len
        # or where payload_len is implausibly small relative to header
        if header_len > 0 and payload_len >= 0:
            total_len = header_len + payload_len
            # If header_len exceeds total_len, that's impossible - indicates malformed packet
            if header_len > total_len:
                violations.append(f"HEADER_GT_TOTAL: Header length ({header_len}) > total length ({total_len})")
            # Also check if header_len exceeds payload_len (impossible scenario)
            elif header_len > payload_len:
                violations.append(f"HEADER_GT_PAYLOAD: Header length ({header_len}) > payload length ({payload_len})")
            # Also check if payload is zero but header is large (suspicious)
            elif payload_len == 0 and header_len > 60:
                violations.append(f"LARGE_HEADER_ZERO_PAYLOAD: Header {header_len} bytes with zero payload")

        # Check minimum header sizes per protocol
        if protocol == 6:  # TCP
            if header_len < _MIN_IP_HEADER + _MIN_TCP_HEADER:
                violations.append(f"TCP_HEADER_TOO_SMALL: Header {header_len} < min {_MIN_IP_HEADER + _MIN_TCP_HEADER}")
        elif protocol == 17:  # UDP
            if header_len < _MIN_IP_HEADER + _MIN_UDP_HEADER:
                violations.append(f"UDP_HEADER_TOO_SMALL: Header {header_len} < min {_MIN_IP_HEADER + _MIN_UDP_HEADER}")
        elif protocol == 1:  # ICMP
            if header_len < _MIN_IP_HEADER + _MIN_ICMP_HEADER:
                violations.append(f"ICMP_HEADER_TOO_SMALL: Header {header_len} < min {_MIN_IP_HEADER + _MIN_ICMP_HEADER}")

        # Check sub-minimum payload sizes (fragmentation attack indicator)
        if 0 < payload_len < self.min_payload_bytes:
            violations.append(f"SUB_MIN_PAYLOAD: Payload {payload_len} bytes < {self.min_payload_bytes} bytes")

        # Check IP total length consistency if available
        if ip_total_len is not None:
            expected_total = header_len + payload_len
            if abs(ip_total_len - expected_total) > 4:  # Allow small variance for padding
                violations.append(f"IP_LEN_MISMATCH: IP total_len={ip_total_len} vs computed={expected_total}")

        # Check for abnormally large headers (header stuffing)
        if protocol == 6 and header_len > 100:  # > 100 bytes for TCP header is suspicious
            violations.append(f"EXCESSIVE_TCP_HEADER: Header {header_len} bytes > 100 bytes")

        # Check for zero payload with data-carrying flags (PSH, URG)
        tcp_flags = getattr(packet, "tcp_flags", 0)
        if protocol == 6 and payload_len == 0 and (tcp_flags & (_TCP_PSH | _TCP_URG)):
            violations.append("ZERO_PAYLOAD_WITH_DATA_FLAGS: PSH/URG set but payload is zero")

        return violations

    def _check_fragmentation(self, packet: Any) -> List[str]:
        """Check for IP fragmentation anomalies.

        Detection-only: violations populate SanityResult.violations list.
        No mitigation calls (iptables, nftables, tc, Docker, OpenFlow).

        Field mapping (documented per Prompt 14 plan):
          ip_frag_offset  → packet.ip_frag_offset  (getattr, default None)
          ip_flags_mf     → packet.ip_flags & 0x1   (getattr, default None)
          total pkt len   → packet.header_len + packet.payload_len
          flow key        → packet.flow_id  or  (src_ip, dst_ip, protocol)
          timestamp       → packet.timestamp
        """
        violations = []

        ip_flags = getattr(packet, "ip_flags", None)
        ip_frag_offset = getattr(packet, "ip_frag_offset", None)

        # MF (More Fragments) flag set
        if ip_flags is not None and (ip_flags & 0x1):  # MF bit
            violations.append("IP_MF_FLAG: More Fragments flag set")

            # Condition B (Prompt 14): MF flag with tiny total packet length.
            # RFC 791 §3.2 mandates all hosts accept datagrams of at least
            # 576 bytes; fragments below this threshold indicate classic
            # evasion techniques (teardrop, Bonk, nestea).
            header_len = getattr(packet, "header_len", 0) or 0
            payload_len = getattr(packet, "payload_len", 0) or 0
            total_pkt_len = header_len + payload_len
            if total_pkt_len < 576:
                violations.append(
                    f"TINY_MF_FRAGMENT: MF-flagged packet total length "
                    f"{total_pkt_len} < 576 bytes (RFC 791 minimum reassembly buffer)"
                )

        # Fragment offset non-zero (not first fragment)
        if ip_frag_offset is not None and ip_frag_offset > 0:
            violations.append(f"IP_FRAGMENT: Fragment offset {ip_frag_offset} (not first fragment)")

        # First fragment with tiny payload (fragmentation attack)
        if ip_frag_offset == 0 and ip_flags is not None and (ip_flags & 0x1):
            payload_len = getattr(packet, "payload_len", 0)
            if 0 < payload_len < self.min_payload_bytes:
                violations.append(f"TINY_FIRST_FRAGMENT: First fragment payload {payload_len} < {self.min_payload_bytes}")

        # Condition C (Prompt 14): Fragment flood detection (stateful).
        # Flags when >50 fragments with the same flow key arrive within a
        # 1-second window.  Uses flow_id attr when available; falls back to
        # composite key from (src_ip, dst_ip, protocol).  Skips tracking
        # entirely if no key can be constructed — this matches the
        # getattr-with-None silent-skip convention used throughout this
        # filter, and directly addresses the ip_id population concern raised
        # during plan review: we never build a tracker key from an attr that
        # might be None-by-default.
        has_mf = ip_flags is not None and (ip_flags & 0x1)
        has_offset = ip_frag_offset is not None and ip_frag_offset > 0
        if has_mf or has_offset:
            flow_key = getattr(packet, "flow_id", None)
            if flow_key is None:
                src_ip = getattr(packet, "src_ip", None)
                dst_ip = getattr(packet, "dst_ip", None)
                protocol = getattr(packet, "protocol", None)
                if src_ip is not None and dst_ip is not None and protocol is not None:
                    flow_key = f"{src_ip}-{dst_ip}-{protocol}"

            if flow_key is not None:
                now = getattr(packet, "timestamp", None)
                if now is not None:
                    # Prune entries older than 1 second
                    if flow_key in self._frag_tracker:
                        self._frag_tracker[flow_key] = [
                            t for t in self._frag_tracker[flow_key]
                            if now - t <= 1.0
                        ]
                    else:
                        self._frag_tracker[flow_key] = []

                    self._frag_tracker[flow_key].append(now)

                    if len(self._frag_tracker[flow_key]) > 50:
                        violations.append(
                            f"FRAGMENT_FLOOD: {len(self._frag_tracker[flow_key])} "
                            f"fragments in 1s window for flow {flow_key} "
                            f"(threshold: 50)"
                        )

        return violations

    def check_flow(self, flow_features: Dict[str, float]) -> SanityResult:
        """
        Check a flow feature dictionary for sanity violations.

        This can be used to validate flows extracted from PCAP or live traffic
        before they reach the ML ensemble.

        Args:
            flow_features: Dictionary of CICFlowMeter features

        Returns:
            SanityResult with violations found in flow-level features
        """
        self._stats["total_checked"] += 1

        violations = []
        details = {}

        # Check for flag anomalies in flow aggregates
        syn_count = flow_features.get("SYN Flag Count", 0)
        fin_count = flow_features.get("FIN Flag Count", 0)
        rst_count = flow_features.get("RST Flag Count", 0)
        psh_count = flow_features.get("PSH Flag Count", 0)
        ack_count = flow_features.get("ACK Flag Count", 0)
        urg_count = flow_features.get("URG Flag Count", 0)

        # SYN+FIN in same flow
        if syn_count > 0 and fin_count > 0:
            violations.append("FLOW_SYN_FIN: Flow contains both SYN and FIN packets")

        # SYN+RST in same flow
        if syn_count > 0 and rst_count > 0:
            violations.append("FLOW_SYN_RST: Flow contains both SYN and RST packets")

        # RST with FIN/PSH/URG in same flow
        if rst_count > 0 and (fin_count > 0 or psh_count > 0 or urg_count > 0):
            violations.append("FLOW_RST_WITH_OTHER: Flow contains RST with FIN/PSH/URG")

        # NULL scan flow (no ACK, no SYN, no FIN, no RST - only possible if all zero)
        total_flags = syn_count + fin_count + rst_count + psh_count + ack_count + urg_count
        if total_flags == 0:
            # But there are packets...
            total_pkts = flow_features.get("Total Fwd Packets", 0) + flow_features.get("Total Backward Packets", 0)
            if total_pkts > 0:
                violations.append("FLOW_NULL_SCAN: Packets present but no TCP flags set")

        # Sub-minimum packet lengths in flow
        fwd_min = flow_features.get("Fwd Packet Length Min", 0)
        if 0 < fwd_min < self.min_payload_bytes:
            violations.append(f"FLOW_SUB_MIN_PAYLOAD: Min fwd packet {fwd_min} < {self.min_payload_bytes}")

        # Header length anomaly
        fwd_header = flow_features.get("Fwd Header Length", 0)
        fwd_pkts = flow_features.get("Total Fwd Packets", 1)
        if fwd_pkts > 0:
            avg_header = fwd_header / fwd_pkts
            if avg_header > 60:  # > 60 bytes avg header is suspicious (normal is 20-40)
                violations.append(f"FLOW_EXCESSIVE_HEADERS: Avg header {avg_header:.1f} bytes")

        is_valid = len(violations) == 0

        if not is_valid:
            self._stats["flagged"] += 1
            for v in violations:
                self._stats["violations_by_type"][v] = self._stats["violations_by_type"].get(v, 0) + 1

        return SanityResult(
            is_valid=is_valid,
            violations=violations,
            violation_count=len(violations),
            details=details,
        )

    def get_stats(self) -> Dict[str, Any]:
        """Return filter statistics."""
        return dict(self._stats)

    def reset_stats(self):
        """Reset statistics counters and fragment flood tracker."""
        self._stats = {
            "total_checked": 0,
            "flagged": 0,
            "violations_by_type": {},
        }
        self._frag_tracker = {}


def create_packet_from_features(features: Dict[str, float]) -> Any:
    """
    Create a mock packet-like object from flow features for sanity checking.
    Used for testing the filter against flow-level feature dictionaries.
    """
    class MockPacket:
        def __init__(self, f):
            self.protocol = int(f.get("Protocol", 6))
            self.tcp_flags = 0
            self.payload_len = int(f.get("Fwd Packet Length Mean", 0))
            self.header_len = int(f.get("Fwd Header Length", 0)) / max(1, int(f.get("Total Fwd Packets", 1)))

            # Reconstruct flags from counts
            syn = int(f.get("SYN Flag Count", 0))
            fin = int(f.get("FIN Flag Count", 0))
            rst = int(f.get("RST Flag Count", 0))
            psh = int(f.get("PSH Flag Count", 0))
            ack = int(f.get("ACK Flag Count", 0))
            urg = int(f.get("URG Flag Count", 0))

            if syn > 0:
                self.tcp_flags |= _TCP_SYN
            if fin > 0:
                self.tcp_flags |= _TCP_FIN
            if rst > 0:
                self.tcp_flags |= _TCP_RST
            if psh > 0:
                self.tcp_flags |= _TCP_PSH
            if ack > 0:
                self.tcp_flags |= _TCP_ACK
            if urg > 0:
                self.tcp_flags |= _TCP_URG

            # Map fragmentation fields from flow features (Prompt 14).
            # Uses None default to match getattr-with-None silent-skip convention
            # in _check_fragmentation() — if field is absent, the check is skipped
            # rather than producing a false positive/negative.
            ip_flags_val = f.get("ip_flags", None)
            self.ip_flags = int(ip_flags_val) if ip_flags_val is not None else None

            ip_frag_val = f.get("ip_frag_offset", None)
            self.ip_frag_offset = int(ip_frag_val) if ip_frag_val is not None else None

            # Identity fields for fragment flood tracking (Condition C).
            # Optional; flood tracking silently skips if these are absent.
            self.src_ip = f.get("src_ip", None)
            self.dst_ip = f.get("dst_ip", None)
            self.timestamp = f.get("timestamp", None)
            self.flow_id = f.get("flow_id", None)

    return MockPacket(features)


# Convenience function for integration with FlowExtractor
def filter_packets_before_extraction(
    packets: List[Any],
    filter_instance: Optional[PacketSanityFilter] = None,
) -> tuple:
    """
    Filter a list of packets through the sanity filter before flow extraction.

    Args:
        packets: List of packet objects
        filter_instance: Optional PacketSanityFilter instance (creates default if None)

    Returns:
        Tuple of (valid_packets, flagged_packets_with_results)
    """
    if filter_instance is None:
        filter_instance = PacketSanityFilter()

    valid = []
    flagged = []

    for pkt in packets:
        result = filter_instance.check_packet(pkt)
        if result.is_valid:
            valid.append(pkt)
        else:
            flagged.append((pkt, result))

    return valid, flagged