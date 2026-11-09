# -*- coding: utf-8 -*-
"""
Layer 1 Signature-Based Pre-Filter & Fast-Path Engine (Phase H - H5).

Stateless, deterministic signature matching executed upstream of ML scoring.
Catches structurally invalid packets, well-known amplification vectors,
malformed TCP flags, spoofed bogons, and legacy protocol exploits in <0.05ms.

Signatures Checked:
  - SIG-TCP-001: SYN+FIN set simultaneously (RFC 793 violation)
  - SIG-TCP-002: NULL scan - all flags 0x00 (RFC 793 violation)
  - SIG-TCP-003: XMAS scan - FIN+PSH+URG set (RFC 793 reconnaissance)
  - SIG-TCP-004: SYN+RST set simultaneously (RFC 793 / RFC 5961 violation)
  - SIG-TCP-005: PSH/URG without ACK in non-SYN packet (RFC 793 violation)
  - SIG-IP-001:  LAND Attack (Source IP == Destination IP)
  - SIG-IP-002:  Bogon / Martian Source IP (0.0.0.0/8, 127.0.0.0/8, 240.0.0.0/4, Multicast src)
  - SIG-UDP-001: NTP Monlist Amplification query (UDP/123 Mode 7 ReqCode 42)
  - SIG-UDP-002: DNS ANY Amplification query (UDP/53 QTYPE 255)
  - SIG-UDP-003: Chargen Amplification flood (UDP/19)
  - SIG-ICMP-001: Oversized ICMP / Ping of Death (>1500 bytes payload)
  - SIG-FRAG-001: Tiny Fragment Evasion (MF=1 with IP payload < 8 bytes)
"""

import ipaddress
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger("SignatureFilter")

# TCP Flag masks
_TCP_FIN = 0x01
_TCP_SYN = 0x02
_TCP_RST = 0x04
_TCP_PSH = 0x08
_TCP_ACK = 0x10
_TCP_URG = 0x20
_TCP_ECE = 0x40
_TCP_CWR = 0x80

# Bogon networks
_BOGON_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("224.0.0.0/4"),  # Multicast not valid as source
    ipaddress.ip_network("240.0.0.0/4"),  # Reserved
]


@dataclass
class SignatureMatchResult:
    """Outcome of signature pre-filter evaluation."""
    matched: bool
    signature_id: Optional[str] = None
    signature_name: Optional[str] = None
    category: Optional[str] = None
    severity: str = "CLEAN"  # "CLEAN", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    description: str = "No signature violation detected"
    recommended_action: str = "FORWARD_TO_ML"
    rfc_reference: Optional[str] = None
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "matched": self.matched,
            "signature_id": self.signature_id,
            "signature_name": self.signature_name,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "recommended_action": self.recommended_action,
            "rfc_reference": self.rfc_reference,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
        }


class SignatureFilter:
    """
    Stateless, fast-path signature inspection engine.
    Runs upstream of ML scoring.
    """

    def inspect_packet(
        self,
        src_ip: Any,
        dst_ip: Optional[str] = None,
        proto: Optional[int] = None,
        sport: Optional[int] = None,
        dport: Optional[int] = None,
        tcp_flags: Optional[int] = None,
        payload: Optional[bytes] = None,
        pkt_len: Optional[int] = None,
        more_fragments: bool = False,
        frag_offset: int = 0,
    ) -> SignatureMatchResult:
        """
        Evaluate individual packet fields against signature catalog.
        Accepts either explicit scalar parameters or a Scapy Packet as the first argument.
        """
        # Scapy packet auto-extraction
        if hasattr(src_ip, "haslayer"):
            pkt = src_ip
            if pkt.haslayer("IP"):
                ip = pkt["IP"]
                s_ip = ip.src
                d_ip = ip.dst
                pr = int(ip.proto)
                sp = None
                dp = None
                t_flags = None
                p_load = bytes(pkt["Raw"]) if pkt.haslayer("Raw") else None
                p_len = len(pkt)
                mf = bool(ip.flags & 1)
                fo = int(ip.frag)

                if pkt.haslayer("TCP"):
                    tcp = pkt["TCP"]
                    sp = int(tcp.sport)
                    dp = int(tcp.dport)
                    t_flags = int(tcp.flags)
                elif pkt.haslayer("UDP"):
                    udp = pkt["UDP"]
                    sp = int(udp.sport)
                    dp = int(udp.dport)

                return self.inspect_packet(
                    src_ip=s_ip,
                    dst_ip=d_ip,
                    proto=pr,
                    sport=sp,
                    dport=dp,
                    tcp_flags=t_flags,
                    payload=p_load,
                    pkt_len=p_len,
                    more_fragments=mf,
                    frag_offset=fo,
                )
            return SignatureMatchResult(
                matched=False,
                severity="CLEAN",
                description="Non-IP packet",
                recommended_action="FORWARD_TO_ML",
            )

        # 1. LAND Attack check
        if src_ip and dst_ip and src_ip == dst_ip:
            if sport is not None and dport is not None and sport == dport:
                return SignatureMatchResult(
                    matched=True,
                    signature_id="SIG-IP-001",
                    signature_name="LAND_ATTACK",
                    category="SPOOF_ANOMALY",
                    severity="CRITICAL",
                    description=f"LAND Attack: Source IP and port match destination ({src_ip}:{sport})",
                    recommended_action="DROP_IMMEDIATELY",
                    rfc_reference="RFC 1812",
                    source_ip=src_ip,
                    target_ip=dst_ip,
                )

        # 2. Bogon / Martian source address check
        try:
            sip = ipaddress.ip_address(src_ip)
            for bogon in _BOGON_NETWORKS:
                if sip in bogon:
                    return SignatureMatchResult(
                        matched=True,
                        signature_id="SIG-IP-002",
                        signature_name="BOGON_SOURCE_IP",
                        category="SPOOF_ANOMALY",
                        severity="CRITICAL",
                        description=f"Martian/Bogon source address {src_ip} in reserved block {bogon}",
                        recommended_action="DROP_IMMEDIATELY",
                        rfc_reference="RFC 6890 / BCP 38",
                        source_ip=src_ip,
                        target_ip=dst_ip,
                    )
        except ValueError:
            pass

        # 3. TCP Flag RFC Violations (Protocol == 6)
        if proto == 6 and tcp_flags is not None:
            # SYN + FIN
            if (tcp_flags & _TCP_SYN) and (tcp_flags & _TCP_FIN):
                return SignatureMatchResult(
                    matched=True,
                    signature_id="SIG-TCP-001",
                    signature_name="TCP_SYN_FIN_SCAN",
                    category="RFC_VIOLATION",
                    severity="CRITICAL",
                    description="SYN and FIN flags set simultaneously (illegal TCP state)",
                    recommended_action="DROP_IMMEDIATELY",
                    rfc_reference="RFC 793 Section 3.4",
                    source_ip=src_ip,
                    target_ip=dst_ip,
                )

            # NULL Scan (No flags)
            if (tcp_flags & 0xFF) == 0:
                return SignatureMatchResult(
                    matched=True,
                    signature_id="SIG-TCP-002",
                    signature_name="TCP_NULL_SCAN",
                    category="RFC_VIOLATION",
                    severity="HIGH",
                    description="TCP NULL packet with zero flags set (reconnaissance probe)",
                    recommended_action="DROP_IMMEDIATELY",
                    rfc_reference="RFC 793 Section 3.9",
                    source_ip=src_ip,
                    target_ip=dst_ip,
                )

            # XMAS Scan (FIN + PSH + URG)
            if (tcp_flags & _TCP_FIN) and (tcp_flags & _TCP_PSH) and (tcp_flags & _TCP_URG):
                return SignatureMatchResult(
                    matched=True,
                    signature_id="SIG-TCP-003",
                    signature_name="TCP_XMAS_SCAN",
                    category="RFC_VIOLATION",
                    severity="HIGH",
                    description="TCP XMAS scan with FIN+PSH+URG flags set simultaneously",
                    recommended_action="DROP_IMMEDIATELY",
                    rfc_reference="RFC 793 Section 3.9",
                    source_ip=src_ip,
                    target_ip=dst_ip,
                )

            # SYN + RST
            if (tcp_flags & _TCP_SYN) and (tcp_flags & _TCP_RST):
                return SignatureMatchResult(
                    matched=True,
                    signature_id="SIG-TCP-004",
                    signature_name="TCP_SYN_RST_ANOMALY",
                    category="RFC_VIOLATION",
                    severity="HIGH",
                    description="SYN and RST flags set simultaneously (mutually exclusive)",
                    recommended_action="DROP_IMMEDIATELY",
                    rfc_reference="RFC 5961",
                    source_ip=src_ip,
                    target_ip=dst_ip,
                )

            # PSH or URG without ACK (in non-SYN packet)
            if not (tcp_flags & _TCP_SYN) and not (tcp_flags & _TCP_ACK):
                if (tcp_flags & _TCP_PSH) or (tcp_flags & _TCP_URG):
                    return SignatureMatchResult(
                        matched=True,
                        signature_id="SIG-TCP-005",
                        signature_name="TCP_PSH_URG_NO_ACK",
                        category="RFC_VIOLATION",
                        severity="MEDIUM",
                        description="TCP PSH or URG flag asserted without ACK acknowledgment",
                        recommended_action="DROP_IMMEDIATELY",
                        rfc_reference="RFC 793 Section 3.1",
                        source_ip=src_ip,
                        target_ip=dst_ip,
                    )

        # 4. UDP Well-Known Amplification Exploits (Protocol == 17)
        if proto == 17:
            # NTP Monlist (UDP port 123)
            if (dport == 123 or sport == 123) and payload:
                # Mode 7 monlist request starts with 0x17, 0x00, 0x03, 0x2a (ReqCode 42)
                if len(payload) >= 4 and payload[0] == 0x17 and payload[3] == 0x2A:
                    return SignatureMatchResult(
                        matched=True,
                        signature_id="SIG-UDP-001",
                        signature_name="NTP_MONLIST_AMPLIFICATION",
                        category="AMPLIFICATION_VECTOR",
                        severity="CRITICAL",
                        description="NTP Mode 7 monlist command detected (high-ratio reflection vector)",
                        recommended_action="DROP_IMMEDIATELY",
                        rfc_reference="CVE-2013-5211",
                        source_ip=src_ip,
                        target_ip=dst_ip,
                    )

            # DNS ANY query (UDP port 53)
            if (dport == 53 or sport == 53) and payload:
                # QTYPE 255 (ANY) query byte pattern in standard DNS wire format
                if b"\x00\xff\x00\x01" in payload:
                    return SignatureMatchResult(
                        matched=True,
                        signature_id="SIG-UDP-002",
                        signature_name="DNS_ANY_AMPLIFICATION",
                        category="AMPLIFICATION_VECTOR",
                        severity="HIGH",
                        description="DNS ANY query reflection pattern detected (QTYPE 255)",
                        recommended_action="DROP_IMMEDIATELY",
                        rfc_reference="RFC 8482",
                        source_ip=src_ip,
                        target_ip=dst_ip,
                    )

            # Chargen flood (UDP port 19)
            if dport == 19 or sport == 19:
                return SignatureMatchResult(
                    matched=True,
                    signature_id="SIG-UDP-003",
                    signature_name="CHARGEN_AMPLIFICATION",
                    category="AMPLIFICATION_VECTOR",
                    severity="CRITICAL",
                    description="Chargen (UDP/19) reflection traffic detected",
                    recommended_action="DROP_IMMEDIATELY",
                    rfc_reference="RFC 864",
                    source_ip=src_ip,
                    target_ip=dst_ip,
                )

        # 5. ICMP Oversized / Ping of Death (Protocol == 1)
        if proto == 1 and pkt_len is not None and pkt_len > 1500:
            return SignatureMatchResult(
                matched=True,
                signature_id="SIG-ICMP-001",
                signature_name="PING_OF_DEATH",
                category="OVERSIZED_PAYLOAD",
                severity="HIGH",
                description=f"Oversized ICMP packet ({pkt_len} bytes > 1500 byte MTU)",
                recommended_action="DROP_IMMEDIATELY",
                rfc_reference="RFC 792",
                source_ip=src_ip,
                target_ip=dst_ip,
            )

        # 6. Fragmentation Evasion
        if more_fragments and frag_offset == 0 and payload and len(payload) < 8:
            return SignatureMatchResult(
                matched=True,
                signature_id="SIG-FRAG-001",
                signature_name="TINY_FRAGMENT_EVASION",
                category="FRAGMENTATION_EVASION",
                severity="HIGH",
                description="Tiny initial fragment (<8 bytes payload) hiding transport header",
                recommended_action="DROP_IMMEDIATELY",
                rfc_reference="RFC 1858 / RFC 3128",
                source_ip=src_ip,
                target_ip=dst_ip,
            )

        # Clean packet
        return SignatureMatchResult(
            matched=False,
            severity="CLEAN",
            description="No signature violation detected",
            recommended_action="FORWARD_TO_ML",
            source_ip=src_ip,
            target_ip=dst_ip,
        )

    def inspect_flow_features(
        self,
        features: Dict[str, Any],
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
    ) -> SignatureMatchResult:
        """
        Evaluate extracted flow features for flag and structural anomalies.
        """
        syn_cnt = float(features.get("SYN Flag Count", 0.0))
        fin_cnt = float(features.get("FIN Flag Count", 0.0))
        rst_cnt = float(features.get("RST Flag Count", 0.0))
        psh_cnt = float(features.get("PSH Flag Count", 0.0))
        urg_cnt = float(features.get("URG Flag Count", 0.0))
        ack_cnt = float(features.get("ACK Flag Count", 0.0))
        proto = int(features.get("Protocol", 6))

        # Check simultaneous SYN+FIN in single flow
        if syn_cnt > 0 and fin_cnt > 0 and syn_cnt == fin_cnt:
            return SignatureMatchResult(
                matched=True,
                signature_id="SIG-TCP-001",
                signature_name="TCP_SYN_FIN_SCAN",
                category="RFC_VIOLATION",
                severity="CRITICAL",
                description=f"Flow with simultaneous SYN and FIN flags ({syn_cnt:.0f} packets)",
                recommended_action="DROP_IMMEDIATELY",
                rfc_reference="RFC 793 Section 3.4",
                source_ip=src_ip,
                target_ip=dst_ip,
            )

        # Check simultaneous SYN+RST in single flow
        if syn_cnt > 0 and rst_cnt > 0 and ack_cnt == 0:
            return SignatureMatchResult(
                matched=True,
                signature_id="SIG-TCP-004",
                signature_name="TCP_SYN_RST_ANOMALY",
                category="RFC_VIOLATION",
                severity="HIGH",
                description="Flow asserting SYN and RST without ACK",
                recommended_action="DROP_IMMEDIATELY",
                rfc_reference="RFC 5961",
                source_ip=src_ip,
                target_ip=dst_ip,
            )

        # Check Bogon if src_ip is provided
        if src_ip:
            try:
                sip = ipaddress.ip_address(src_ip)
                for bogon in _BOGON_NETWORKS:
                    if sip in bogon:
                        return SignatureMatchResult(
                            matched=True,
                            signature_id="SIG-IP-002",
                            signature_name="BOGON_SOURCE_IP",
                            category="SPOOF_ANOMALY",
                            severity="CRITICAL",
                            description=f"Martian/Bogon source address {src_ip} in reserved block {bogon}",
                            recommended_action="DROP_IMMEDIATELY",
                            rfc_reference="RFC 6890 / BCP 38",
                            source_ip=src_ip,
                            target_ip=dst_ip,
                        )
            except ValueError:
                pass

        return SignatureMatchResult(
            matched=False,
            severity="CLEAN",
            description="Flow adheres to signature pre-filter standards",
            recommended_action="FORWARD_TO_ML",
            source_ip=src_ip,
            target_ip=dst_ip,
        )
