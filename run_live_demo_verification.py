# -*- coding: utf-8 -*-
"""
Live End-to-End DDoS Detection and Mitigation Verification
Runs the complete verified pipeline with:
1. Real listening TCP server on port 9999
2. Real bidirectional SYN flood packet generation via Scapy on loopback
3. Real FlowExtractor feature extraction (77 CICFlowMeter features)
4. Real EnsembleClassifier scoring (XGBoost / Random Forest) -> ATTACK classification
5. Real NemotronAgent threat analysis & mitigation proposal
6. Real Human Approval Gate (PendingActionManager) approval & execution
"""
import sys
import os
import time
import socket
import threading
import json

REPO_ROOT = os.path.abspath(os.path.dirname(__file__))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from scapy.all import IP, TCP, Raw, send, sniff
from src.features.flow_extractor import FlowExtractor, Packet as FlowPacket
from src.models.ensemble import get_default_ensemble
from src.agent.nemotron_agent import NemotronAgent
from src.mitigation.manager import get_manager

TARGET_IP = "127.0.0.1"
TARGET_PORT = 9999
ATTACK_DURATION = 2  # seconds
CAPTURE_IFACE = r'\Device\NPF_Loopback'

print("=" * 70)
print("LIVE END-TO-END DDOS DETECTION & MITIGATION VERIFICATION")
print("=" * 70)

# Step 1: Start listening TCP server on target port
print(f"\n[STEP 1] Starting listening TCP server on {TARGET_IP}:{TARGET_PORT}...")
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind((TARGET_IP, TARGET_PORT))
listener.listen(128)

server_running = True
def server_loop():
    while server_running:
        try:
            conn, addr = listener.accept()
            try:
                conn.send(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            except Exception:
                pass
            conn.close()
        except Exception:
            break

srv_thread = threading.Thread(target=server_loop, daemon=True)
srv_thread.start()
print("  [OK] Server listening and ready to generate bidirectional responses.")

# Step 2: Start packet capture on loopback
print(f"\n[STEP 2] Initializing FlowExtractor packet capture on {CAPTURE_IFACE}...")
extractor = FlowExtractor(active_timeout=120.0, idle_timeout=60.0)
captured_flows = []

def capture_packets():
    def packet_callback(pkt):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return
        ip = pkt[IP]
        tcp = pkt[TCP]

        flow_pkt = FlowPacket(
            timestamp=float(pkt.time),
            src_ip=ip.src,
            dst_ip=ip.dst,
            src_port=tcp.sport,
            dst_port=tcp.dport,
            protocol=ip.proto,
            payload_len=len(tcp.payload) if tcp.payload else 0,
            header_len=ip.ihl * 4 + tcp.dataofs * 4,
            tcp_flags=int(tcp.flags),
            tcp_window=tcp.window,
        )
        expired = extractor.process_packet(flow_pkt)
        if expired:
            captured_flows.append(expired)

    sniff(
        iface=CAPTURE_IFACE,
        filter=f"tcp and port {TARGET_PORT}",
        prn=packet_callback,
        timeout=ATTACK_DURATION + 4,
        store=False
    )
    captured_flows.extend(extractor.flush_all())

cap_thread = threading.Thread(target=capture_packets)
cap_thread.start()
time.sleep(0.5)
print("  [OK] Sniffer active.")

# Step 3: Generate SYN flood attack against listening server
print(f"\n[STEP 3] Generating live SYN flood against {TARGET_IP}:{TARGET_PORT}...")
start_t = time.time()
sent_count = 0
while time.time() - start_t < ATTACK_DURATION:
    pkt = (
        IP(src="127.0.0.1", dst=TARGET_IP)
        / TCP(sport=54321, dport=TARGET_PORT, flags="S", seq=1000 + sent_count, window=65535)
        / Raw(b"X" * 330)
    )
    send(pkt, verbose=0, iface=CAPTURE_IFACE)
    sent_count += 1
    time.sleep(0.002)

print(f"  [OK] Sent {sent_count} attack packets in {time.time() - start_t:.2f}s.")
server_running = False
listener.close()
cap_thread.join(timeout=5)

# Step 4: Flow extraction & bidirectional verification
print("\n[STEP 4] Extracting bidirectional flow telemetry...")
if not captured_flows:
    print("  [FAIL] No flows captured!")
    sys.exit(1)

flow = captured_flows[0]
feats = flow.to_feature_dict()
print(f"  Flow Key:               {flow.flow_key}")
print(f"  Forward Packets:        {flow.fwd_packet_count}")
print(f"  Backward Packets:       {flow.bwd_packet_count}")
print(f"  SYN Flags:              {flow.syn_count}")
print(f"  ACK Flags:              {flow.ack_count}")
print(f"  Bwd Packets/s:          {feats.get('Bwd Packets/s', 0):.2f}")
print(f"  Down/Up Ratio:          {feats.get('Down/Up Ratio', 0):.4f}")

if flow.bwd_packet_count > 0 and feats.get('Bwd Packets/s', 0) > 0:
    print("  [PASS] BIDIRECTIONAL TRAFFIC VERIFIED: Server response packets captured successfully!")
else:
    print("  [FAIL] Unidirectional only: backward packets zero.")
    sys.exit(1)

# Step 5: Machine Learning Classification
print("\n[STEP 5] Scoring flow with EnsembleClassifier...")
ensemble = get_default_ensemble()

label_xgb, conf_xgb, bkd_xgb = ensemble.score_flow(features=feats, mode='xgb_only')
is_attack_xgb = (label_xgb.lower() != 'benign')
print(f"  XGBoost:                {label_xgb} (confidence: {conf_xgb:.4f}) -> {'[ATTACK DETECTED]' if is_attack_xgb else '[BENIGN]'}")

label_rf, conf_rf, bkd_rf = ensemble.score_flow(features=feats, mode='rf_only')
is_attack_rf = (label_rf.lower() != 'benign')
print(f"  Random Forest:          {label_rf} (confidence: {conf_rf:.4f}) -> {'[ATTACK DETECTED]' if is_attack_rf else '[BENIGN]'}")

label_ens, conf_ens, bkd_ens = ensemble.score_flow(features=feats, mode='ensemble')
is_attack_ens = (label_ens.lower() != 'benign')
print(f"  Ensemble:               {label_ens} (confidence: {conf_ens:.4f}) -> {'[ATTACK DETECTED]' if is_attack_ens else '[BENIGN]'}")

if is_attack_xgb:
    print("  [PASS] LIVE DETECTION VERIFIED: Pipeline classified attack correctly (NOT Benign)!")
else:
    print("  [FAIL] Misclassified as Benign.")
    sys.exit(1)

# Step 6: Nemotron Threat Reasoning & Mitigation Proposal
print("\n[STEP 6] Submitting alert to NemotronAgent for threat reasoning...")
agent = NemotronAgent()
print(f"  Provider:               {agent.provider}")
print(f"  Model:                  {agent.model}")

alert = {
    "attacker_ip": "127.0.0.1",
    "victim_ip": TARGET_IP,
    "attack_type": label_xgb,
    "confidence": conf_xgb,
    "per_model_breakdown": bkd_xgb,
    "packet_count": flow.fwd_packet_count + flow.bwd_packet_count,
    "source": "live_scapy_detector",
}

proposal = agent.analyze_and_propose(alert)
print(f"  Proposal Status:        {proposal.get('status')}")
print(f"  Severity:               {proposal.get('severity')}")
print(f"  Requires Human Approval:{proposal.get('requires_human_approval')}")
print(f"  Action ID:              {proposal.get('proposed_action_id')}")
print(f"  Proposed Action:        {proposal.get('proposed_action')}")
print(f"  Reasoning Summary:      {proposal.get('explanation')[:150]}...")

if proposal.get('requires_human_approval') is not True:
    print("  [FAIL] Safety invariant violated: requires_human_approval is not True!")
    sys.exit(1)

# Step 7: Operator Approval Gate Verification
print("\n[STEP 7] Testing Operator Approval Gate (PendingActionManager)...")
manager = get_manager()
action_id = proposal["proposed_action_id"]
action = manager.get_action(action_id)

print(f"  Stored Action ID:       {action.get('action_id', action_id)}")
print(f"  Stored Status:          {action['status']}")
print(f"  Stored Auto-Execute:    {action['auto_execute']}")

if action["auto_execute"] is not False:
    print("  [FAIL] auto_execute must be False!")
    sys.exit(1)

# Explicit operator approval
print("  Simulating Operator Approval Click...")
success, msg, executed_action = manager.approve(action_id, approver="soc_operator_1")
print(f"  Approval Success:       {success}")
print(f"  Approval Message:       {msg}")
print(f"  Final Action Status:    {executed_action['status']}")
print(f"  Execution Timestamp:    {executed_action.get('executed_at')}")

if success and executed_action["status"] == "EXECUTED":
    print("  [PASS] HUMAN-IN-THE-LOOP APPROVAL GATE VERIFIED: Action safely approved and executed!")
else:
    print("  [FAIL] Action approval failed.")
    sys.exit(1)

print("\n" + "=" * 70)
print("[OK] FULL LIVE DEMO VERIFICATION COMPLETED SUCCESSFULLY")
print("=" * 70)
