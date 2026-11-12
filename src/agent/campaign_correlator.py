# -*- coding: utf-8 -*-
"""
Attack Campaign & Multi-Flow Correlator (Phase H - H8).

Correlates multi-flow attack telemetry by grouping alerts by (victim_ip, attack_family)
within a configurable sliding time window (default: 60s).

Aggregates:
  - Coordinated botnet count (unique participating source IPs)
  - Aggregate packet rate (PPS) and bandwidth (Mbps)
  - Flow count and temporal attack duration
  - Active vs. Concluded campaign lifecycle state

Includes optional Nemotron "AI Threat Analyst Notes" integration for
expert campaign judgment (e.g. coordinated botnet vs. uncoordinated noise),
with seamless deterministic offline heuristic fallback.
"""

import os
import time
import uuid
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any

logger = logging.getLogger("CampaignCorrelator")

# Known amplification reflection service ports (Layer 1 H5 pre-filter alignment)
KNOWN_AMPLIFIER_SERVICES: Dict[int, str] = {
    19: "Chargen (UDP/19)",
    53: "DNS-Amplifier (UDP/53)",
    69: "TFTP-Reflector (UDP/69)",
    111: "Portmap/RPC-Reflector (UDP/111)",
    123: "NTP-Monlist-Amplifier (UDP/123)",
    137: "NetBIOS-Name-Service (UDP/137)",
    161: "SNMP-Reflector (UDP/161)",
    389: "CLDAP-Amplifier (UDP/389)",
    1434: "MSSQL-Resolution-Amplifier (UDP/1434)",
    1900: "SSDP-Amplifier (UDP/1900)",
}


@dataclass
class BotParticipant:
    """Individual bot or reflector participant metrics within a campaign."""
    ip: str
    packet_count: int = 0
    byte_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    aggregate_pps: float = 0.0
    is_known_amplifier: bool = False
    amplifier_vector: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        duration = max(0.0, self.last_seen - self.first_seen)
        return {
            "ip": self.ip,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": round(duration, 2),
            "pps": round(self.aggregate_pps, 2),
            "is_known_amplifier": self.is_known_amplifier,
            "amplifier_vector": self.amplifier_vector or "N/A",
        }


@dataclass
class AttackCampaign:
    """Aggregated multi-flow attack campaign representation."""
    campaign_id: str
    victim_ip: str
    attack_family: str
    participating_ips: Set[str] = field(default_factory=set)
    flow_count: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    aggregate_pps: float = 0.0
    aggregate_bps: float = 0.0
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    status: str = "ACTIVE"  # "ACTIVE", "CONCLUDED"
    analyst_notes: Optional[Dict[str, Any]] = None
    bot_details: Dict[str, BotParticipant] = field(default_factory=dict)
    timeline_events: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def bot_count(self) -> int:
        return len(self.participating_ips)

    @property
    def duration_seconds(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def aggregate_mbps(self) -> float:
        return (self.aggregate_bps * 8.0) / 1_000_000.0

    @property
    def ramp_profile(self) -> str:
        if self.bot_count <= 1:
            return "SINGLE_SOURCE_PERSISTENT"
        join_times = [e["timestamp"] for e in self.timeline_events if e.get("event") == "BOT_JOINED"]
        if join_times and (max(join_times) - min(join_times) <= 1.0):
            return "IMMEDIATE_FULL_VOLUME (Burst / Pulse Activation)"
        return "GRADUAL_RAMP_UP (Stealth Expansion)"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "victim_ip": self.victim_ip,
            "attack_family": self.attack_family,
            "bot_count": self.bot_count,
            "participating_ips": sorted(list(self.participating_ips)),
            "bot_breakdown": [b.to_dict() for b in self.bot_details.values()],
            "timeline": self.timeline_events[-50:],
            "ramp_profile": self.ramp_profile,
            "geo_asn_context": {
                "status": "OMITTED_SYNTHETIC_RANGE",
                "synthetic_network_environment": True,
                "notice": "Source IPs reside in private / synthetic test ranges (RFC 1918 / RFC 5737). Geolocation / ASN resolution is deliberately omitted to prevent fabricated geographic telemetry.",
            },
            "flow_count": self.flow_count,
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "aggregate_pps": round(self.aggregate_pps, 2),
            "aggregate_mbps": round(self.aggregate_mbps, 3),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "duration_seconds": round(self.duration_seconds, 2),
            "status": self.status,
            "analyst_notes": self.analyst_notes,
        }


def normalize_attack_family(raw_label: str) -> str:
    """Map granular class labels into high-level tactical attack families."""
    if not raw_label:
        return "Unknown"
    lbl = raw_label.lower().strip()
    if "syn" in lbl:
        return "TCP-SYN-Flood"
    elif any(k in lbl for k in ["ntp", "dns", "ldap", "snmp", "mssql", "netbios", "portmap", "tftp", "reflection"]):
        return "UDP-Reflection-Amplification"
    elif "udp" in lbl:
        return "UDP-Volumetric-Flood"
    elif "web" in lbl or "http" in lbl:
        return "HTTP-Application-Flood"
    elif "benign" in lbl or "normal" in lbl:
        return "Benign"
    return "Volumetric-Attack"


class CampaignCorrelator:
    """
    Stateful multi-flow correlator.
    Groups incoming flow alerts into coordinated DDoS campaigns.
    """

    def __init__(self, window_seconds: float = 60.0, idle_timeout: float = 120.0):
        self.window_seconds = window_seconds
        self.idle_timeout = idle_timeout
        # (victim_ip, attack_family) -> AttackCampaign
        self._active_campaigns: Dict[Tuple[str, str], AttackCampaign] = {}
        self._concluded_campaigns: List[AttackCampaign] = []

    def _record_bot_activity(
        self,
        campaign: AttackCampaign,
        src_ip: str,
        packet_count: int,
        byte_count: int,
        pps: float,
        now: float,
        src_port: Optional[int],
        attack_label: str,
    ) -> None:
        is_new_bot = src_ip not in campaign.bot_details
        if is_new_bot:
            # Check amplifier signature alignment (Layer 1 H5 pre-filter alignment)
            amp_vector = None
            is_amp = False
            if src_port and src_port in KNOWN_AMPLIFIER_SERVICES:
                is_amp = True
                amp_vector = KNOWN_AMPLIFIER_SERVICES[src_port]
            elif any(k in attack_label.lower() for k in ["ntp", "dns", "ldap", "snmp", "mssql", "netbios", "portmap", "tftp", "reflection"]):
                is_amp = True
                amp_vector = f"Reflection-Amplifier ({attack_label})"

            bot = BotParticipant(
                ip=src_ip,
                packet_count=packet_count,
                byte_count=byte_count,
                first_seen=now,
                last_seen=now,
                aggregate_pps=pps,
                is_known_amplifier=is_amp,
                amplifier_vector=amp_vector,
            )
            campaign.bot_details[src_ip] = bot
            campaign.timeline_events.append({
                "timestamp": now,
                "relative_time_s": round(max(0.0, now - campaign.first_seen), 3),
                "event": "BOT_JOINED",
                "ip": src_ip,
                "cumulative_bots": len(campaign.participating_ips),
                "instant_pps": round(pps, 2),
                "is_known_amplifier": is_amp,
            })
        else:
            bot = campaign.bot_details[src_ip]
            bot.packet_count += packet_count
            bot.byte_count += byte_count
            bot.last_seen = now
            bot.aggregate_pps = max(bot.aggregate_pps, pps)
            if packet_count >= 100:
                campaign.timeline_events.append({
                    "timestamp": now,
                    "relative_time_s": round(max(0.0, now - campaign.first_seen), 3),
                    "event": "FLOW_BURST",
                    "ip": src_ip,
                    "packet_count": packet_count,
                    "instant_pps": round(pps, 2),
                })

    def ingest_flow_alert(
        self,
        src_ip: str,
        victim_ip: str,
        attack_label: str,
        pps: float = 0.0,
        bps: float = 0.0,
        packet_count: int = 1,
        byte_count: int = 60,
        timestamp: Optional[float] = None,
        generate_ai_notes: bool = True,
        src_port: Optional[int] = None,
        protocol: Optional[str] = None,
    ) -> AttackCampaign:
        """
        Ingest a flow alert and correlate into an active or new campaign.
        """
        now = timestamp if timestamp is not None else time.time()
        family = normalize_attack_family(attack_label)

        # Periodic cleanup of idle campaigns
        self._expire_idle_campaigns(now)

        key = (victim_ip, family)
        campaign = self._active_campaigns.get(key)

        if campaign and (now - campaign.last_seen <= self.window_seconds):
            # Correlate into existing campaign
            campaign.participating_ips.add(src_ip)
            campaign.flow_count += 1
            campaign.total_packets += packet_count
            campaign.total_bytes += byte_count
            campaign.aggregate_pps += pps
            campaign.aggregate_bps += bps
            campaign.last_seen = now
            self._record_bot_activity(campaign, src_ip, packet_count, byte_count, pps, now, src_port, attack_label)
        else:
            # Conclude previous if expired
            if campaign:
                campaign.status = "CONCLUDED"
                self._concluded_campaigns.append(campaign)

            # Spawn new campaign
            camp_id = f"CAMP-{uuid.uuid4().hex[:8].upper()}"
            campaign = AttackCampaign(
                campaign_id=camp_id,
                victim_ip=victim_ip,
                attack_family=family,
                participating_ips={src_ip},
                flow_count=1,
                total_packets=packet_count,
                total_bytes=byte_count,
                aggregate_pps=pps,
                aggregate_bps=bps,
                first_seen=now,
                last_seen=now,
                status="ACTIVE",
            )
            self._record_bot_activity(campaign, src_ip, packet_count, byte_count, pps, now, src_port, attack_label)
            self._active_campaigns[key] = campaign

        if generate_ai_notes:
            campaign.analyst_notes = self.generate_analyst_notes(campaign)

        return campaign

    def _expire_idle_campaigns(self, now: float) -> None:
        to_expire = []
        for key, camp in self._active_campaigns.items():
            if now - camp.last_seen > self.idle_timeout:
                camp.status = "CONCLUDED"
                to_expire.append(key)
                self._concluded_campaigns.append(camp)

        for key in to_expire:
            del self._active_campaigns[key]

    def get_active_campaigns(self) -> List[Dict[str, Any]]:
        return [c.to_dict() for c in self._active_campaigns.values()]

    def get_concluded_campaigns(self) -> List[Dict[str, Any]]:
        return [c.to_dict() for c in self._concluded_campaigns]

    def generate_analyst_notes(self, campaign: AttackCampaign) -> Dict[str, Any]:
        """
        Generate "AI Threat Analyst Notes" for the campaign.
        Uses NVIDIA NIM / OpenRouter if configured, otherwise uses deterministic
        expert heuristic notes.
        """
        # Check if live LLM is configured
        nim_key = os.environ.get("NVIDIA_API_KEY") or os.environ.get("OPENROUTER_API_KEY")
        if nim_key:
            try:
                from src.agent.nemotron_agent import NemotronAgent
                agent = NemotronAgent()
                prompt = (
                    f"Campaign Analysis Request:\n"
                    f"- Campaign ID: {campaign.campaign_id}\n"
                    f"- Target Victim: {campaign.victim_ip}\n"
                    f"- Attack Family: {campaign.attack_family}\n"
                    f"- Distinct Bot/Reflector IPs ({campaign.bot_count}): {sorted(list(campaign.participating_ips))[:10]}\n"
                    f"- Total Flows: {campaign.flow_count}\n"
                    f"- Aggregate Rate: {campaign.aggregate_pps:.1f} PPS, {campaign.aggregate_mbps:.3f} Mbps\n"
                    f"- Duration: {campaign.duration_seconds:.1f}s\n"
                    f"Assess whether this attack represents a coordinated botnet or independent scans, "
                    f"and provide 2 concise tactical notes for the SOC operator."
                )
                res, _ = agent._call_nemotron_api(prompt)
                if res and isinstance(res, dict):
                    return {
                        "source": f"Nemotron ({getattr(agent, 'model', 'LLM')})",
                        "assessment": res.get("explanation", "Multi-flow coordinated attack detected."),
                        "severity": res.get("severity", "HIGH"),
                        "coordination_confidence": "HIGH" if campaign.bot_count > 3 else "MEDIUM",
                        "recommended_mitigation_scope": res.get("proposed_action", "Apply distributed rate limit"),
                    }
            except Exception as e:
                logger.debug("Nemotron LLM call failed, falling back to heuristic: %s", e)

        # Deterministic Blue-Team Expert Fallback Notes
        bot_count = campaign.bot_count
        if bot_count >= 10:
            assessment = (
                f"Distributed Botnet Cluster: Confirmed multi-source coordination across {bot_count} "
                f"endpoints targeting {campaign.victim_ip}. Traffic pattern indicates synchronized "
                f"command-and-control (C2) activation."
            )
            scope = "Coordinated Subnet ACL / BGP Flowspec rate-limit"
            coordination = "VERY_HIGH"
            severity = "CRITICAL"
        elif bot_count >= 2:
            assessment = (
                f"Multi-Source Coordinated Vector: {bot_count} distinct source endpoints participating "
                f"in {campaign.attack_family}. Correlated timing indicates non-random campaign activity."
            )
            scope = "Quarantine active participant pool & inspect common autonomous systems (ASNs)"
            coordination = "HIGH"
            severity = "HIGH"
        else:
            assessment = (
                f"Single-Source Focused Vector: 1 active source endpoint targeting {campaign.victim_ip}. "
                f"Unlikely to be a distributed botnet; likely direct high-volume socket injection."
            )
            scope = "Targeted single-IP drop at ingress edge switch"
            coordination = "LOW"
            severity = "MEDIUM" if campaign.aggregate_pps < 500 else "HIGH"

        return {
            "source": "Deterministic Blue-Team Expert (Heuristic Baseline)",
            "assessment": assessment,
            "severity": severity,
            "coordination_confidence": coordination,
            "recommended_mitigation_scope": scope,
        }
