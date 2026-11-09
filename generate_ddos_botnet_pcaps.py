#!/usr/bin/env python3
"""
generate_ddos_botnet_pcaps.py

Synthesize genuine multi-source DDoS botnet traffic for local sandbox testing.
Uses ONLY IETF-reserved documentation ranges (RFC 5737) to avoid real public IPs.
Covers two attack types:
  1. Direct floods (Distributed SYN Flood)
  2. Reflection botnets (Distributed NTP/DNS Amplification)

Botnet IPs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 — RFC 5737):
  - Victim: 10.0.0.1
  - Botnet: 198.51.100.12, 203.0.113.45, 192.0.2.42, 198.51.100.33,
            203.0.113.17, 192.0.2.88, 198.51.100.25, 203.0.113.40,
            192.0.2.12, 198.51.100.55
"""

import json
import os
import struct
import random
import math
from datetime import datetime, timedelta

# RFC 5737 Documentation Ranges (never real public infrastructure)
BOTNET_SUBNETS = [
    {"base": "198.51.100.0", "prefix": "/24", "label": "TEST-198-51-100"},
    {"base": "203.0.113.0", "prefix": "/24", "label": "TEST-203-0-113"},
    {"base": "192.0.2.0", "prefix": "/24", "label": "TEST-192-0-2"},
]

BOTNET_IPS = [
    "198.51.100.12",
    "203.0.113.45",
    "192.0.2.42",
    "198.51.100.33",
    "203.0.113.17",
    "192.0.2.88",
    "198.51.100.25",
    "203.0.113.40",
    "192.0.2.12",
    "198.51.100.55",
]

VICTIM_IP = "10.0.0.1"
VICTIM_SUBNET = "10.0.0.0/24"

NUM_BOTNET_NODES = len(BOTNET_IPS)
ATTACK_DURATION_SECONDS = 30
SYN_RATE_PER_BOT = 50  # packets per second per bot
NTPSERVER_PORT = 123
DTSSERVER_PORT = 53

# Time window for campaign correlation (60s sliding window)
CORRELATION_WINDOW_SECONDS = 60
MIN_DISTINCT_ATTACKERS_FOR_DDOS = 3


def ip_to_int(ip_str):
    """Convert dotted-quad IPv4 string to 32-bit integer."""
    parts = ip_str.split(".")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


def int_to_ip(n):
    """Convert 32-bit integer to dotted-quad IPv4 string."""
    return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"


def generate_syn_flood_pcap(bot_ip, victim_ip, duration, rate_per_sec, start_time):
    """Generate a SYN flood PCAP-like JSON structure (no real packets; for modeling)."""
    packets = []
    num_packets = int(duration * rate_per_sec)

    for i in range(num_packets):
        timestamp = start_time + timedelta(seconds=i / rate_per_sec)
        # Ethereal-style flow features
        packet = {
            "timestamp": timestamp.isoformat(),
            "src_ip": bot_ip,
            "dst_ip": victim_ip,
            "protocol": 6,  # TCP
            "tcp_flags": 0x02,  # SYN only
            "payload_len": 0,
            "header_len": 40,
            "ip_total_len": 40,
            "ip_flags": 0,
            "ip_frag_offset": 0,
            "flow_id": f"{bot_ip}-{victim_ip}-6",
        }
        packets.append(packet)

    return {
        "attack_type": "Syn Flood",
        "bot_ip": bot_ip,
        "victim_ip": victim_ip,
        "attack_type_detail": "Distributed SYN Flood",
        "packets": packets,
        "duration_sec": duration,
        "rate_pkts_per_sec": rate_per_sec,
        "total_packets": num_packets,
        "feature_set": {
            "Protocol": 6,
            "Duration": duration,
            "Tot Fwd Pkts": num_packets,
            "Fwd Pkts/s": rate_per_sec,
            "Bwd Pkts/s": 0.0,
            "Fwd Pkt Len Mean": 40.0,
            "Fwd Pkt Len Std": 0.0,
            "Bwd Pkt Len Mean": 0.0,
            "Bwd Pkt Len Std": 0.0,
            "Flow IAT Mean": 1.0 / rate_per_sec if rate_per_sec > 0 else 0.0,
            "Flow IAT Std": 0.0,
            "Flow IAT Max": 1.0 / rate_per_sec if rate_per_sec > 0 else 0.0,
            "Flow IAT Min": 1.0 / rate_per_sec if rate_per_sec > 0 else 0.0,
            "SYN Flag Count": num_packets,
            "FIN Flag Count": 0,
            "RST Flag Count": 0,
            "PSH Flag Count": 0,
            "ACK Flag Count": 0,
            "URG Flag Count": 0,
            "Avg Fwd Segment Size": 40.0,
            "Avg Bwd Segment Size": 0.0,
            "Fwd Header Len": 40,
            "Fwd Packets": num_packets,
            "Bwd Packets": 0,
            "Idle Mean": 0.0,
            "Idle Std": 0.0,
            "Label": "Attack",
        },
    }


def generate_ntp_amplification_pcap(bot_ip, victim_ip, duration, start_time):
    """Generate NTP monlist reflection amplification PCAP-like JSON structure."""
    # NTP amplification: each request (~234 bytes) generates a monlist response (~600+ bytes)
    # Amplification factor: ~556x bandwidth multiplication
    num_packets = int(duration * 20)  # ~20 NTP packets per second

    packets = []
    for i in range(num_packets):
        timestamp = start_time + timedelta(seconds=i / 20.0)
        packet = {
            "timestamp": timestamp.isoformat(),
            "src_ip": bot_ip,
            "dst_ip": victim_ip,
            "protocol": 17,  # UDP
            "udp_src_port": random.randint(49152, 65535),  # ephemeral source port
            "udp_dst_port": DTSSERVER_PORT,  # DNS port... wait, NTP is 123
            "udp_dst_port": NTPSERVER_PORT,
            "payload_len": random.randint(234, 468),  # request size
            "header_len": 28,
            "ip_total_len": 28 + random.randint(234, 468),
            "ip_flags": 0,
            "ip_frag_offset": 0,
            "flow_id": f"{bot_ip}-{victim_ip}-17",
        }
        packets.append(packet)

    return {
        "attack_type": "NTP Amplification",
        "bot_ip": bot_ip,
        "victim_ip": victim_ip,
        "attack_type_detail": "Distributed NTP Monlist Reflection-Amplification Flood",
        "packets": packets,
        "duration_sec": duration,
        "rate_pkts_per_sec": int(num_packets / duration),
        "total_packets": num_packets,
        "feature_set": {
            "Protocol": 17,
            "Duration": duration,
            "Tot Fwd Pkts": num_packets,
            "Fwd Pkts/s": int(num_packets / duration),
            "Bwd Pkts/s": 0.0,
            "Fwd Pkt Len Mean": 301.0,  # typical NTP response size
            "Fwd Pkt Len Std": 80.0,
            "Bwd Pkt Len Mean": 0.0,
            "Bwd Pkt Len Std": 0.0,
            "Flow IAT Mean": 0.05,
            "Flow IAT Std": 0.01,
            "Flow IAT Max": 0.1,
            "Flow IAT Min": 0.01,
            "UDP Flag Count": num_packets,
            "Total Fwd Packets": num_packets,
            "Total Backward Packets": 0,
            "Fwd Segment Size": 301.0,
            "Init Win bytes forward": 0,
            "Init Win bytes backward": 0,
            "Fwd Act Data Pkts": num_packets,
            "Fwd Segments": num_packets,
            "Bwd Segments": 0,
            "Label": "Attack",
        },
    }


def generate_dns_amplification_pcap(bot_ip, victim_ip, duration, start_time):
    """Generate DNS open resolver reflection amplification PCAP-like JSON structure."""
    num_packets = int(duration * 30)  # ~30 DNS packets per second

    packets = []
    for i in range(num_packets):
        timestamp = start_time + timedelta(seconds=i / 30.0)
        packet = {
            "timestamp": timestamp.isoformat(),
            "src_ip": bot_ip,
            "dst_ip": victim_ip,
            "protocol": 17,  # UDP
            "udp_src_port": random.randint(49152, 65535),
            "udp_dst_port": DTSSERVER_PORT,  # DNS port 53
            "payload_len": random.randint(60, 120),  # small DNS request
            "header_len": 28,
            "ip_total_len": 28 + random.randint(60, 120),
            "ip_flags": 0,
            "ip_frag_offset": 0,
            "flow_id": f"{bot_ip}-{victim_ip}-17",
        }
        packets.append(packet)

    return {
        "attack_type": "DNS Amplification",
        "bot_ip": bot_ip,
        "victim_ip": victim_ip,
        "attack_type_detail": "Distributed DNS Open Resolver Reflection-Amplification Flood",
        "packets": packets,
        "duration_sec": duration,
        "rate_pkts_per_sec": int(num_packets / duration),
        "total_packets": num_packets,
        "feature_set": {
            "Protocol": 17,
            "Duration": duration,
            "Tot Fwd Pkts": num_packets,
            "Fwd Pkts/s": int(num_packets / duration),
            "Bwd Pkts/s": 0.0,
            "Fwd Pkt Len Mean": 88.0,  # typical DNS response
            "Fwd Pkt Len Std": 25.0,
            "Bwd Pkt Len Mean": 0.0,
            "Bwd Pkt Len Std": 0.0,
            "Flow IAT Mean": 0.033,
            "Flow IAT Std": 0.008,
            "Flow IAT Max": 0.06,
            "Flow IAT Min": 0.005,
            "UDP Flag Count": num_packets,
            "Total Fwd Packets": num_packets,
            "Total Backward Packets": 0,
            "Label": "Attack",
        },
    }


def main():
    print("=" * 72)
    print("DDoS Botnet Traffic Generator (Synthetic Test Data)")
    print("=" * 72)
    print(f"Victim: {VICTIM_IP}")
    print(f"Botnet size: {NUM_BOTNET_NODES} nodes across {len(BOTNET_SUBNETS)} subnets")
    print(f"Attack duration: {ATTACK_DURATION_SECONDS}s per bot")
    print(f"Using RFC 5737 documentation ranges only (NO real public IPs)")
    print()

    # Create output directory
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "pcaps", "botnet")
    os.makedirs(output_dir, exist_ok=True)
    print(f"Output directory: {output_dir}")

    start_time = datetime.utcnow()

    # === 1. Generate Distributed SYN Flood botnet traffic ===
    print("\n[1/2] Generating Distributed SYN Flood botnet traffic...")
    syn_flood_results = []
    for i, bot_ip in enumerate(BOTNET_IPS):
        pkt_data = generate_syn_flood_pcap(
            bot_ip=bot_ip,
            victim_ip=VICTIM_IP,
            duration=ATTACK_DURATION_SECONDS,
            rate_per_sec=SYN_RATE_PER_BOT,
            start_time=start_time,
        )
        syn_flood_results.append(pkt_data)

        # Save individual bot PCAP
        fname = f"syn_flood_{bot_ip.replace('.', '_')}.json"
        fpath = os.path.join(output_dir, fname)
        with open(fpath, "w") as f:
            json.dump(pkt_data, f, indent=2)
        print(f"  Saved: {fname} ({pkt_data['total_packets']} packets)")

    # === 2. Generate NTP Amplification botnet traffic ===
    print("\n[2/2] Generating Distributed NTP Amplification botnet traffic...")
    ntp_results = []
    for i, bot_ip in enumerate(BOTNET_IPS):
        pkt_data = generate_ntp_amplification_pcap(
            bot_ip=bot_ip,
            victim_ip=VICTIM_IP,
            duration=ATTACK_DURATION_SECONDS,
            start_time=start_time,
        )
        ntp_results.append(pkt_data)

        # Save individual bot PCAP
        fname = f"ntp_amplification_{bot_ip.replace('.', '_')}.json"
        fpath = os.path.join(output_dir, fname)
        with open(fpath, "w") as f:
            json.dump(pkt_data, f, indent=2)
        print(f"  Saved: {fname} ({pkt_data['total_packets']} packets)")

    # === 3. Generate DNS Amplification botnet traffic ===
    print("\n[3/2] Generating Distributed DNS Amplification botnet traffic...")
    dns_results = []
    for i, bot_ip in enumerate(BOTNET_IPS):
        pkt_data = generate_dns_amplification_pcap(
            bot_ip=bot_ip,
            victim_ip=VICTIM_IP,
            duration=ATTACK_DURATION_SECONDS,
            start_time=start_time,
        )
        dns_results.append(pkt_data)

        # Save individual bot PCAP
        fname = f"dns_amplification_{bot_ip.replace('.', '_')}.json"
        fpath = os.path.join(output_dir, fname)
        with open(fpath, "w") as f:
            json.dump(pkt_data, f, indent=2)
        print(f"  Saved: {fname} ({pkt_data['total_packets']} packets)")

    # === 4. Generate consolidated campaign summary ===
    print("\n[4/2] Generating consolidated campaign summary...")
    all_bots = BOTNET_IPS  # All 10 botnet IPs

    # Compute aggregate telemetry
    total_syn_pkts = sum(r["total_packets"] for r in syn_flood_results)
    total_ntp_pkts = sum(r["total_packets"] for r in ntp_results)
    total_dns_pkts = sum(r["total_packets"] for r in dns_results)
    total_packets = total_syn_pkts + total_ntp_pkts + total_dns_pkts

    summary = {
        "campaign_id": f"DDOS_CAMPAIGN_{int(start_time.timestamp())}",
        "start_time_utc": start_time.isoformat() + "Z",
        "duration_sec": ATTACK_DURATION_SECONDS,
        "victim_ip": VICTIM_IP,
        "botnet_size": NUM_BOTNET_NODES,
        "distinct_attacker_ips": all_bots,
        "attack_vectors": {
            "syn_flood": {
                "node_count": NUM_BOTNET_NODES,
                "total_packets": total_syn_pkts,
                "rate_pkts_per_sec": SYN_RATE_PER_BOT * NUM_BOTNET_NODES,
                "bot_ips": BOTNET_IPS,
            },
            "ntp_amplification": {
                "node_count": NUM_BOTNET_NODES,
                "total_packets": total_ntp_pkts,
                "rate_pkts_per_sec": int(total_ntp_pkts / ATTACK_DURATION_SECONDS),
                "bot_ips": BOTNET_IPS,
                "amplification_factor": "~556x",  # NTP monlist factor
            },
            "dns_amplification": {
                "node_count": NUM_BOTNET_NODES,
                "total_packets": total_dns_pkts,
                "rate_pkts_per_sec": int(total_dns_pkts / ATTACK_DURATION_SECONDS),
                "bot_ips": BOTNET_IPS,
                "amplification_factor": "~50-70x",  # DNS ANY factor
            },
        },
        "aggregate_telemetry": {
            "total_packets": total_packets,
            "total_pkts_per_sec": (
                SYN_RATE_PER_BOT * NUM_BOTNET_NODES
                + int(total_ntp_pkts / ATTACK_DURATION_SECONDS)
                + int(total_dns_pkts / ATTACK_DURATION_SECONDS)
            ),
            "correlation_window_sec": CORRELATION_WINDOW_SECONDS,
            "ddos_detected": NUM_BOTNET_NODES >= MIN_DISTINCT_ATTACKERS_FOR_DDOS,
        },
        "geo_ip_traceback": {
            # IPs are RFC 5737 documentation ranges; mark as test ranges
            "note": "Botnet IPs use RFC 5737 documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). "
            "GeoIP lookup would return 'Local / Private Network' or 'Unknown Location'. "
            "For production deployment, replace with real botnet IPs and integrate MaxMind GeoLite2.",
            "bot_ip_geolocation": {
                ip: {"country": "Test Range", "country_code": "TR"}
                for ip in BOTNET_IPS
            },
        },
        "blue_team_dossier": {
            "containment_plan": {
                "action": "Batch IPSet block / subnet null-route",
                "instructions": [
                    f"ipset block {', '.join(BOTNET_IPS)}",
                    f"iptables -A INPUT -m set --match-set blacklist src -j DROP",
                    f"route null-{VICTIM_IP} via blackhole subnet",
                ],
            },
            "aggregate_attack_volume": {
                "total_packets": total_packets,
                "pps_estimate": SYN_RATE_PER_BOT * NUM_BOTNET_NODES,
                "amplification_total": f"{total_ntp_pkts} NTP + {total_dns_pkts} DNS amplified packets",
            },
            "recommended_actions": [
                "Execute batch IPSet block of all botnet IPs",
                "Null-route victim subnet prefix to sinkhole attack traffic",
                "Update GeoIP traceback with real MaxMind data for forensic attribution",
                "Deploy BCP 38 (uRPF) at upstream edge to prevent spoofed-source attacks",
            ],
        },
    }

    summary_path = os.path.join(output_dir, "campaign_summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"  Saved: campaign_summary.json")

    # === 5. Print summary ===
    print("\n" + "=" * 72)
    print("GENERATION COMPLETE")
    print("=" * 72)
    print(f"\nTotal botnet nodes: {NUM_BOTNET_NODES}")
    print(f"Total packets generated: {total_packets}")
    print(f"Attack vectors: SYN Flood, NTP Amplification, DNS Amplification")
    print(f"\nCampaign: {summary['campaign_id']}")
    print(f"DDoS detected: {summary['aggregate_telemetry']['ddos_detected']} "
          f"(>= {MIN_DISTINCT_ATTACKERS_FOR_DDOS} distinct attackers required)")
    print(f"\nAll IPs use RFC 5737 documentation ranges (safe for testing).")
    print(f"Output location: {output_dir}")
    print("\nNext steps:")
    print("  1. Load these PCAPs into the Mininet/SDN testbed")
    print("  2. Run the detection pipeline - should trigger >=3-IP correlation")
    print("  3. Verify ingress blocklist suppression works correctly")
    print("  ")

    return summary


if __name__ == "__main__":
    summary = main()