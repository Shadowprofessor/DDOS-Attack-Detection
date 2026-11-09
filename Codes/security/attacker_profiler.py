import json
import time
import math
import logging
from datetime import datetime

logger = logging.getLogger("AttackerProfiler")

class AttackerProfiler:
    """
    Identifies attacker IPs, analyzes behavioral traffic patterns,
    calculates threat scores, and maintains dynamic attacker profiles.
    """
    def __init__(self, high_threat_threshold=30):
        self.high_threat_threshold = high_threat_threshold
        # ip -> profile dict
        self.attacker_profiles = {}
        # ip -> total threat score
        self.threat_scores = {}

    def analyze_flow(self, ip_src, ip_dst, packet_count, byte_count, duration, ip_proto, tp_src, tp_dst):
        """
        Analyze flow statistics to profile potential attacker behavior.
        Thresholds calibrated for Mininet SDN emulation environment.
        """
        if not ip_src or ip_src == "0.0.0.0":
            return None

        rate_pps = packet_count / max(duration, 0.001)
        rate_bps = (byte_count * 8) / max(duration, 0.001)

        if ip_src not in self.attacker_profiles:
            self.attacker_profiles[ip_src] = {
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "total_packets": 0,
                "total_bytes": 0,
                "target_ips": set(),
                "target_ports": set(),
                "protocols": set(),
                "max_pps": 0,
                "anomaly_flags": []
            }

        prof = self.attacker_profiles[ip_src]
        prof["last_seen"] = datetime.now().isoformat()
        prof["total_packets"] += packet_count
        prof["total_bytes"] += byte_count
        prof["target_ips"].add(ip_dst)
        prof["target_ports"].add(tp_dst)
        prof["protocols"].add(ip_proto)
        prof["max_pps"] = max(prof["max_pps"], rate_pps)

        # Explicit packet count rules requested by user:
        # 1. Detect if packets exceed 50 (Score >= 50)
        # 2. Execute full prevention (FLOW_DROP_BLOCK) if packets reach 100 (Score = 100)
        threat_score = 0
        if packet_count >= 100 or prof["total_packets"] >= 100:
            threat_score += 100
            prof["anomaly_flags"].append("PACKET_COUNT_EXCEEDS_100_FULL_PREVENTION")
        elif packet_count > 50 or prof["total_packets"] > 50:
            threat_score += 50
            prof["anomaly_flags"].append("PACKET_COUNT_EXCEEDS_50_DETECTION")
        elif rate_pps > 20:
            threat_score += 30
        elif rate_pps > 5:
            threat_score += 15

        # Multi-target scanning / distributed flood
        if len(prof["target_ips"]) > 2:
            threat_score += 25
            prof["anomaly_flags"].append("PORT_OR_HOST_SCANNING")

        # Asymmetric flow payload (high pps with tiny byte sizes typical of SYN/ICMP flood)
        avg_packet_size = byte_count / max(packet_count, 1)
        if avg_packet_size < 128:
            threat_score += 20
            prof["anomaly_flags"].append("SMALL_PACKET_FLOOD")

        # Update threat score (Max 100)
        self.threat_scores[ip_src] = min(100, self.threat_scores.get(ip_src, 0) + threat_score)

        is_high_threat = self.threat_scores[ip_src] >= self.high_threat_threshold
        
        return {
            "ip_src": ip_src,
            "threat_score": self.threat_scores[ip_src],
            "is_high_threat": is_high_threat,
            "anomaly_flags": list(set(prof["anomaly_flags"])),
            "targets_count": len(prof["target_ips"])
        }

    def get_profile(self, ip_src):
        if ip_src in self.attacker_profiles:
            p = self.attacker_profiles[ip_src].copy()
            p["target_ips"] = list(p["target_ips"])
            p["target_ports"] = list(p["target_ports"])
            p["protocols"] = list(p["protocols"])
            p["threat_score"] = self.threat_scores.get(ip_src, 0)
            return p
        return None

    def get_all_attackers(self, min_threat=50):
        results = {}
        for ip, score in self.threat_scores.items():
            if score >= min_threat:
                results[ip] = self.get_profile(ip)
        return results
