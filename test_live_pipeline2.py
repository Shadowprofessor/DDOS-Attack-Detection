#!/usr/bin/env python3
"""Test full pipeline with live generated attack traffic - more analysis."""
import sys
import time
import threading
sys.path.insert(0, r'C:\Users\Sachit Sharma\Documents\DDoS-Attack-Detection-and-Mitigation-using-Machine-Learning')

from scapy.all import IP, TCP, Raw, send, sniff, get_if_list
from src.features.flow_extractor import FlowExtractor, Packet as FlowPacket
from src.models.classifier import DDoSClassifier
from src.models.ensemble import get_default_ensemble, score_flow

# Configuration
TARGET_IP = "127.0.0.1"
TARGET_PORT = 9999
ATTACK_DURATION = 3
CAPTURE_IFACE = r'\Device\NPF_Loopback'

print("=== REAL LIVE ATTACK PIPELINE TEST (with Ensemble) ===")
print(f"Target: {TARGET_IP}:{TARGET_PORT}")

# Start capture
extractor = FlowExtractor(active_timeout=120.0, idle_timeout=60.0)
captured_flows = []
capture_done = threading.Event()

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
        timeout=ATTACK_DURATION + 2,
        store=False
    )
    captured_flows.extend(extractor.flush_all())
    capture_done.set()

# Start capture thread
capture_thread = threading.Thread(target=capture_packets)
capture_thread.start()
time.sleep(0.5)

# Generate SYN flood
print(f"Generating SYN flood for {ATTACK_DURATION} seconds...")
start_time = time.time()
packet_count = 0
while time.time() - start_time < ATTACK_DURATION:
    pkt = IP(src="127.0.0.1", dst=TARGET_IP) / TCP(sport=54321, dport=TARGET_PORT, flags="S", seq=1000, window=65535)
    send(pkt, verbose=0, iface=CAPTURE_IFACE)
    packet_count += 1
    time.sleep(0.001)

print(f"Sent {packet_count} SYN packets")
capture_thread.join(timeout=5)

print(f"\nExtracted {len(captured_flows)} flows from live traffic")
for i, flow in enumerate(captured_flows):
    feats = flow.to_feature_dict()
    print(f"\nFlow {i}:")
    print(f"  Key: {flow.flow_key}")
    print(f"  Fwd pkts: {flow.fwd_packet_count}, Bwd pkts: {flow.bwd_packet_count}")
    print(f"  Duration: {flow.last_active_time - flow.start_time:.3f}s")
    print(f"  SYN flags: {flow.syn_count}, ACK flags: {flow.ack_count}")
    print(f"  Fwd Pkts/s: {feats.get('Fwd Packets/s', 0):.1f}")
    print(f"  Bwd Pkts/s: {feats.get('Bwd Packets/s', 0):.1f}")
    print(f"  Down/Up Ratio: {feats.get('Down/Up Ratio', 0):.3f}")
    print(f"  Flow Bytes/s: {feats.get('Flow Bytes/s', 0):.1f}")
    print(f"  Flow Packets/s: {feats.get('Flow Packets/s', 0):.1f}")

# Classify with RF
print("\n--- RF Classifier ---")
clf = DDoSClassifier(r'models\cicddos2019_rf.pkl')
for i, flow in enumerate(captured_flows):
    feats = flow.to_feature_dict()
    result = clf.predict_vector(feats)
    print(f"Flow {i}: pred={result['label']}, is_attack={result['is_attack']}, conf={result['confidence']:.3f}")

# Classify with XGBoost
print("\n--- XGBoost Classifier ---")
clf_xgb = DDoSClassifier(r'models\cicddos2019_xgboost.pkl')
for i, flow in enumerate(captured_flows):
    feats = flow.to_feature_dict()
    result = clf_xgb.predict_vector(feats)
    print(f"Flow {i}: pred={result['label']}, is_attack={result['is_attack']}, conf={result['confidence']:.3f}")

# Classify with Ensemble
print("\n--- Ensemble (rf_only) ---")
ensemble = get_default_ensemble()
for i, flow in enumerate(captured_flows):
    feats = flow.to_feature_dict()
    label, conf, breakdown = ensemble.score_flow(features=feats, mode='rf_only')
    print(f"Flow {i}: pred={label}, conf={conf:.3f}")

print("\n--- Ensemble (xgb_only) ---")
for i, flow in enumerate(captured_flows):
    feats = flow.to_feature_dict()
    label, conf, breakdown = ensemble.score_flow(features=feats, mode='xgb_only')
    print(f"Flow {i}: pred={label}, conf={conf:.3f}")

print("\n--- Ensemble (ensemble) ---")
for i, flow in enumerate(captured_flows):
    feats = flow.to_feature_dict()
    label, conf, breakdown = ensemble.score_flow(features=feats, mode='ensemble')
    print(f"Flow {i}: pred={label}, conf={conf:.3f}")
    if breakdown:
        print(f"  Breakdown mode: {breakdown.get('mode')}")
        for model_name, model_data in breakdown.items():
            if isinstance(model_data, dict) and 'label' in model_data:
                print(f"  {model_name}: {model_data['label']} ({model_data['confidence']:.3f})")