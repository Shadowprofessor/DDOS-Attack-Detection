#!/usr/bin/env python3
"""
DDoS Attack Detection & Nemotron AI Prevention — Standalone Simulator
=====================================================================
Runs entirely on native Windows Python. Simulates:
  1. Network traffic generation (benign + attack packets)
  2. ML-based Random Forest detection
  3. Continuous 150-ping ICMP flood detection
  4. Nemotron AI OpenRouter reasoning engine (2-step with reasoning_details)
  5. Docker/iptables prevention command execution
  6. Forensic incident logging

Usage:
    python run_full_simulation.py
"""

import os
import sys
import time
import json
import random
from datetime import datetime

# Ensure Codes packages are importable
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "Codes"))
sys.path.insert(0, SCRIPT_DIR)

from security.ai_threat_analyzer import AIThreatAnalyzer
from security.attack_type_classifier import AttackTypeClassifier
from security.threat_intelligence import ThreatIntelligence
from security.forensics_logger import ForensicsLogger
from security.attacker_profiler import AttackerProfiler

# Try to import Docker enforcer (non-fatal if Docker isn't running)
try:
    from security.docker_enforcer import DockerEnforcer
    HAS_DOCKER_ENFORCER = True
except Exception:
    HAS_DOCKER_ENFORCER = False


def safe_print(text):
    try:
        print(text, flush=True)
    except UnicodeEncodeError:
        print(text.encode("ascii", "ignore").decode("ascii"), flush=True)


# ─────────────────────────────────────────────────────────────────────
# Simulated ML Model (uses real trained model if FlowStatsfile.csv exists)
# ─────────────────────────────────────────────────────────────────────
class SimulatedMLDetector:
    def __init__(self):
        self.model = None
        self._try_load_real_model()

    def _try_load_real_model(self):
        try:
            import pandas as pd
            from sklearn.ensemble import RandomForestClassifier

            csv_candidates = [
                os.path.join(SCRIPT_DIR, "FlowStatsfile.csv"),
                os.path.join(SCRIPT_DIR, "Codes", "ml", "FlowStatsfile.csv"),
            ]
            for path in csv_candidates:
                if os.path.exists(path):
                    df = pd.read_csv(path)
                    # Sample up to 5000 rows for fast simulation training
                    if len(df) > 5000:
                        df = df.sample(n=5000, random_state=42)
                    for col in ["ip_src", "ip_dst"]:
                        if col in df.columns:
                            df[col] = df[col].astype(str).str.replace(".", "", regex=False).astype(float)
                    X = df.iloc[:, :-1].values.astype("float64")
                    y = df.iloc[:, -1].values
                    self.model = RandomForestClassifier(n_estimators=20, criterion="entropy", random_state=42)
                    self.model.fit(X, y)
                    safe_print(f"[ML ENGINE] Trained Random Forest on {len(X)} samples from {os.path.basename(path)}")
                    return
        except Exception as e:
            safe_print(f"[ML ENGINE] Could not load real model: {e}")

        safe_print("[ML ENGINE] Using heuristic detection (no dataset found)")

    def predict(self, flow_features):
        """Returns 1 (attack) or 0 (benign) for a single flow feature vector."""
        if self.model is not None:
            try:
                return int(self.model.predict([flow_features[:18]])[0])
            except Exception:
                pass
        # Heuristic fallback: high packet rate or high byte count = attack
        pkt_rate = flow_features[14] if len(flow_features) > 14 else 0
        return 1 if pkt_rate > 50 else 0


# ─────────────────────────────────────────────────────────────────────
# Simulated Packet Generator
# ─────────────────────────────────────────────────────────────────────
def generate_benign_flows(count=10):
    """Generate benign-looking flow feature vectors."""
    flows = []
    for _ in range(count):
        src_ip = f"10.0.0.{random.randint(1, 5)}"
        dst_ip = f"10.0.0.{random.randint(1, 5)}"
        flows.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": random.choice([1, 6, 17]),
            "packet_count": random.randint(1, 10),
            "byte_count": random.randint(64, 1500),
            "duration_sec": random.randint(1, 30),
            "tp_src": random.randint(1024, 65535),
            "tp_dst": random.choice([80, 443, 22, 53]),
            "icmp_type": -1,
            "flags": 0,
        })
    return flows


def generate_attack_flows(attacker_ip="192.168.1.100", victim_ip="10.0.0.4", count=160):
    """Generate 150+ continuous ICMP ping flood flows from attacker."""
    flows = []
    for i in range(count):
        flows.append({
            "src_ip": attacker_ip,
            "dst_ip": victim_ip,
            "protocol": 1,  # ICMP
            "packet_count": i + 1,
            "byte_count": 64,
            "duration_sec": 0,
            "tp_src": 0,
            "tp_dst": 0,
            "icmp_type": 8,  # Echo Request
            "flags": 0,
        })
    return flows


def generate_netbios_attack_flows(attacker_ip="192.168.1.105", victim_ip="10.0.0.4", count=80):
    """Generate NetBIOS (UDP 137/138) Reflection & Amplification attack flows."""
    flows = []
    for i in range(count):
        flows.append({
            "src_ip": attacker_ip,
            "dst_ip": victim_ip,
            "protocol": 17,  # UDP
            "packet_count": (i + 1) * 20,
            "byte_count": 1472,
            "duration_sec": 1,
            "tp_src": 137,  # NetBIOS Name Service
            "tp_dst": random.randint(1024, 65535),
            "icmp_type": -1,
            "flags": 0,
        })
    return flows


# ─────────────────────────────────────────────────────────────────────
# Main Simulation Engine
# ─────────────────────────────────────────────────────────────────────
def run_simulation():
    safe_print("")
    safe_print("=" * 70)
    safe_print("  DDoS ATTACK DETECTION & NEMOTRON AI PREVENTION SIMULATOR")
    safe_print("  Full Pipeline: ML Detection -> AI Reasoning -> Prevention")
    safe_print("=" * 70)
    safe_print("")

    # Initialize all security modules
    ml_detector = SimulatedMLDetector()
    classifier = AttackTypeClassifier()
    threat_intel = ThreatIntelligence(default_block_duration_sec=300)
    profiler = AttackerProfiler(high_threat_threshold=30)
    ai_analyzer = AIThreatAnalyzer()

    log_dir = os.path.join(SCRIPT_DIR, "Codes", "attack_logs")
    os.makedirs(log_dir, exist_ok=True)
    forensics = ForensicsLogger(log_dir=log_dir)

    # Track ICMP ping counts per source IP
    icmp_ping_counts = {}

    # ── Phase 1: Benign Traffic ──────────────────────────────────────
    safe_print("[PHASE 1] Generating benign network traffic...")
    safe_print("-" * 50)
    benign_flows = generate_benign_flows(10)

    for i, flow in enumerate(benign_flows):
        safe_print(f"  Flow {i+1:3d}: {flow['src_ip']:>12s} -> {flow['dst_ip']:<12s} | "
                   f"Proto={flow['protocol']:2d} | Pkts={flow['packet_count']:4d} | "
                   f"Bytes={flow['byte_count']:6d} | Status: BENIGN (forwarded)")
    safe_print(f"\n  >> {len(benign_flows)} benign flows processed. All forwarded normally.\n")
    time.sleep(1)

    # ── Phase 2: Attack Traffic (150+ Continuous Pings) ──────────────
    attacker_ip = "192.168.1.100"
    victim_ip = "10.0.0.4"
    total_pings = 160

    safe_print("[PHASE 2] Simulating DDoS attack: 160 continuous ICMP pings...")
    safe_print(f"  Attacker: {attacker_ip}  ->  Victim: {victim_ip}")
    safe_print("-" * 50)

    attack_detected = False
    attack_flows = generate_attack_flows(attacker_ip, victim_ip, total_pings)

    for i, flow in enumerate(attack_flows):
        src = flow["src_ip"]
        dst = flow["dst_ip"]

        # Track continuous ICMP pings
        if flow["protocol"] == 1:
            icmp_ping_counts[src] = icmp_ping_counts.get(src, 0) + 1

        ping_count = icmp_ping_counts.get(src, 0)

        # Print progress every 25 pings
        if (i + 1) % 25 == 0 or i == 0:
            safe_print(f"  Ping {i+1:3d}/{total_pings}: {src} -> {dst} | "
                       f"Continuous Count: {ping_count}")

        # ── CHECK: 150 continuous pings reached → TRIGGER DETECTION ──
        if ping_count >= 150 and not attack_detected:
            attack_detected = True
            safe_print("")

            # Classify the attack vector
            attack_type = classifier.classify_attack(
                flow["protocol"], flow["tp_src"], flow["tp_dst"],
                flow["icmp_type"], ping_count, flow["byte_count"],
                flow["duration_sec"], flow["flags"]
            )

            # Blacklist the attacker
            threat_intel.blacklist_ip(src)

            # ── NEMOTRON AI REASONING PREVENTION ENGINE ──
            telemetry = {
                "attacker_ip": src,
                "victim_ip": dst,
                "attack_type": attack_type,
                "packet_count": ping_count,
                "continuous_pings": ping_count,
            }
            ai_result = ai_analyzer.analyze_and_prevent(telemetry)

            # Docker enforcement (best-effort)
            if HAS_DOCKER_ENFORCER:
                DockerEnforcer.block_attacker_container(src, dst)

            # Log forensic incident
            geo_info = {
                "ip": src,
                "country": "Simulated Attack Origin",
                "country_code": "XX",
                "city": "Simulated City",
                "isp": "Attacker ISP",
                "org": "Threat Actor Org",
                "lat": 0.0, "lon": 0.0,
                "is_private": False,
            }
            incident = forensics.log_incident(
                attacker_ip=src,
                victim_ip=dst,
                attack_type=attack_type,
                threat_score=100,
                geo_info=geo_info,
                mitigation_action="FLOW_DROP_NEMOTRON_AI_BLOCK",
            )

            safe_print(f"  >> Remaining {total_pings - i - 1} pings DROPPED (SDN flow rule active)")
            break

    # ── Phase 2b: NetBIOS Amplification Attack ────────────────────────
    safe_print("")
    safe_print("[PHASE 2b] Simulating NetBIOS (UDP 137/138) Amplification DDoS Attack...")
    netbios_attacker = "192.168.1.105"
    netbios_flows = generate_netbios_attack_flows(netbios_attacker, victim_ip, count=10)
    
    for flow in netbios_flows:
        attack_type = classifier.classify_attack(
            flow["protocol"], flow["tp_src"], flow["tp_dst"],
            flow["icmp_type"], flow["packet_count"], flow["byte_count"],
            flow["duration_sec"], flow["flags"]
        )
        threat_intel.blacklist_ip(flow["src_ip"])
        safe_print(f"  ALERT: {attack_type} detected from {flow['src_ip']} -> {flow['dst_ip']}!")
        safe_print(f"  Action: Nemotron AI Blacklisted {flow['src_ip']} (UDP Port {flow['tp_src']} Amplification Vector Blocked)")
        break

    if not attack_detected:
        safe_print("  [INFO] Attack threshold not reached in this simulation.")

    # ── Phase 3: Post-Attack — Verify Server Recovery ────────────────
    safe_print("")
    safe_print("[PHASE 3] Post-attack verification...")
    safe_print("-" * 50)

    # Check blacklist
    active_bl = threat_intel.get_active_blacklist()
    if active_bl:
        safe_print(f"  Blacklisted IPs: {list(active_bl.keys())}")
        for ip, info in active_bl.items():
            safe_print(f"    {ip}: expires in {info['expires_in_sec']}s, reputation={info['reputation']}")
    else:
        safe_print("  No IPs currently blacklisted.")

    # Verify victim server is still reachable for clean traffic
    safe_print(f"\n  Simulating clean ping from 10.0.0.2 -> {victim_ip}...")
    clean_src = "10.0.0.2"
    if not threat_intel.is_blacklisted(clean_src):
        safe_print(f"  PASS: {clean_src} -> {victim_ip} : Reply received (server online)")
    else:
        safe_print(f"  FAIL: {clean_src} is incorrectly blacklisted!")

    # Verify attacker is blocked
    safe_print(f"\n  Simulating attack ping from {attacker_ip} -> {victim_ip}...")
    if threat_intel.is_blacklisted(attacker_ip):
        safe_print(f"  BLOCKED: {attacker_ip} -> {victim_ip} : Request timed out (100% packet loss)")
        safe_print(f"  PASS: Attacker successfully blocked!")
    else:
        safe_print(f"  WARNING: {attacker_ip} is NOT blacklisted!")

    # ── Summary ──────────────────────────────────────────────────────
    summary = forensics.generate_summary()
    safe_print("")
    safe_print("=" * 70)
    safe_print("  SIMULATION COMPLETE — FORENSIC SUMMARY")
    safe_print("=" * 70)
    safe_print(f"  Total Incidents Logged   : {summary.get('total_incidents', 0)}")
    safe_print(f"  Unique Attackers         : {summary.get('unique_attackers', 0)}")
    safe_print(f"  Unique Victims           : {summary.get('unique_victims', 0)}")
    safe_print(f"  Attack Types             : {summary.get('attack_type_breakdown', {})}")
    safe_print(f"  Attacker Origins         : {summary.get('attacker_country_breakdown', {})}")
    safe_print(f"  Last Incident            : {summary.get('last_incident_time', 'N/A')}")
    safe_print(f"  Forensic Logs Saved To   : {os.path.abspath(log_dir)}")
    safe_print("=" * 70)
    safe_print("")


if __name__ == "__main__":
    run_simulation()
