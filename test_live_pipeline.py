#!/usr/bin/env python3
"""Test full pipeline with live generated attack traffic."""
import sys
import time
import threading
sys.path.insert(0, r'C:\Users\Sachit Sharma\Documents\DDoS-Attack-Detection-and-Mitigation-using-Machine-Learning')

from scapy.all import IP, TCP, Raw, send, sniff, get_if_list
from src.features.flow_extractor import FlowExtractor, Packet as FlowPacket
from src.models.classifier import DDoSClassifier

# Configuration
TARGET_IP = "127.0.0.1"
TARGET_PORT = 9999  # Some unused port
ATTACK_DURATION = 3  # seconds
CAPTURE_IFACE = r'\Device\NPF_Loopback'

print("=== REAL LIVE ATTACK PIPELINE TEST ===")
print(f"Target: {TARGET_IP}:{TARGET_PORT}")
print(f"Capture interface: {CAPTURE_IFACE}")

# Start capture in background
extractor = FlowExtractor(active_timeout=120.0, idle_timeout=60.0)
captured_flows = []
capture_done = threading.Event()

def capture_packets():
    """Capture packets on loopback and feed to extractor."""
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
    # Flush remaining flows
    captured_flows.extend(extractor.flush_all())
    capture_done.set()

# Start capture thread
print("\n1. Starting packet capture...")
capture_thread = threading.Thread(target=capture_packets)
capture_thread.start()
time.sleep(0.5)  # Let capture start

# Generate SYN flood attack traffic
print(f"2. Generating SYN flood for {ATTACK_DURATION} seconds...")
start_time = time.time()
packet_count = 0
while time.time() - start_time < ATTACK_DURATION:
    # Craft SYN packet
    pkt = IP(src="127.0.0.1", dst=TARGET_IP) / TCP(sport=54321, dport=TARGET_PORT, flags="S", seq=1000, window=65535)
    send(pkt, verbose=0, iface=CAPTURE_IFACE)
    packet_count += 1
    time.sleep(0.001)  # ~1000 packets/sec

print(f"   Sent {packet_count} SYN packets")

# Wait for capture to complete
capture_thread.join(timeout=5)

print(f"\n3. Extracted {len(captured_flows)} flows from live traffic")
for i, flow in enumerate(captured_flows):
    feats = flow.to_feature_dict()
    print(f"   Flow {i}: {flow.fwd_src_ip}:{flow.flow_key[2]} -> {flow.flow_key[1]}:{flow.flow_key[3]}")
    print(f"     Fwd pkts: {flow.fwd_packet_count}, Bwd pkts: {flow.bwd_packet_count}")
    print(f"     Duration: {flow.last_active_time - flow.start_time:.3f}s")
    print(f"     SYN flags: {flow.syn_count}")

# Classify flows
print("\n4. Classifying extracted flows with RF model...")
clf = DDoSClassifier(r'models\cicddos2019_rf.pkl')
for i, flow in enumerate(captured_flows):
    feats = flow.to_feature_dict()
    result = clf.predict_vector(feats)
    print(f"   Flow {i}: pred={result['label']}, is_attack={result['is_attack']}, conf={result['confidence']:.3f}")

print("\n=== PIPELINE TEST COMPLETE ===")