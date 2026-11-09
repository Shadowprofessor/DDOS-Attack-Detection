import sys
import time
import threading
import socket

sys.path.insert(0, r'C:\Users\Sachit Sharma\Documents\DDoS-Attack-Detection-and-Mitigation-using-Machine-Learning')

from scapy.all import IP, TCP, send, sniff
from src.features.flow_extractor import FlowExtractor, Packet as FlowPacket
from src.models.classifier import DDoSClassifier

# ============================================================
# Configuration
# ============================================================
TARGET_IP = "127.0.0.1"
TARGET_PORT = 9999
ATTACK_DURATION = 3  # seconds
CAPTURE_IFACE = r'\Device\NPF_Loopback'

# ============================================================
# Start a TCP listener on the target port
# ============================================================
print("Starting TCP listener on port", TARGET_PORT, "...")
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind((TARGET_IP, TARGET_PORT))
listener.listen(5)
listener.settimeout(ATTACK_DURATION + 5)

# Accept connections in background (we don't need to handle data, just let OS respond with SYN-ACK)
def accept_connections():
    try:
        while True:
            try:
                conn, addr = listener.accept()
                conn.settimeout(1.0)
                try:
                    data = conn.recv(1024)  # Read any data
                    conn.send(b"OK")  # Send ACK response
                except:
                    pass
                conn.close()
            except socket.timeout:
                break
            except:
                break
    except:
        pass

accept_thread = threading.Thread(target=accept_connections, daemon=True)
accept_thread.start()
time.sleep(0.5)

# ============================================================
# Capture packets on loopback
# ============================================================
print("Starting packet capture...")
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
        timeout=ATTACK_DURATION + 5,
        store=False
    )
    captured_flows.extend(extractor.flush_all())

capture_thread = threading.Thread(target=capture_packets)
capture_thread.start()
time.sleep(0.5)

# ============================================================
# Generate SYN flood - with listening port, OS sends SYN-ACK back
# ============================================================
print(f"Generating SYN flood for {ATTACK_DURATION} seconds...")
start_time = time.time()
packet_count = 0
while time.time() - start_time < ATTACK_DURATION:
    # Use fixed source port so all packets aggregate into a single high-volume flow
    sport = 54321
    pkt = IP(src="127.0.0.1", dst=TARGET_IP) / TCP(sport=sport, dport=TARGET_PORT, flags="S", seq=1000 + packet_count, window=65535)
    send(pkt, verbose=0, iface=CAPTURE_IFACE)
    packet_count += 1
    time.sleep(0.001)

print(f"Sent {packet_count} SYN packets")
listener.close()
capture_thread.join(timeout=5)

# ============================================================
# Analyze extracted flows
# ============================================================
print(f"\n=== Extracted {len(captured_flows)} flows from live traffic ===")
for i, flow in enumerate(captured_flows):
    feats = flow.to_feature_dict()
    print(f"\nFlow {i}:")
    print(f"  Flow Key: {flow.flow_key}")
    print(f"  Fwd pkts: {flow.fwd_packet_count}, Bwd pkts: {flow.bwd_packet_count}")
    print(f"  Duration: {flow.last_active_time - flow.start_time:.3f}s")
    print(f"  SYN flags: {flow.syn_count}, ACK flags: {flow.ack_count}, RST flags: {flow.rst_count}, FIN flags: {flow.fin_count}")

    # Key features that matter for classification
    key_features = [
        'Down/Up Ratio',
        'Flow Packets/s',
        'Fwd Packets/s',
        'Bwd Packets/s',
        'Flow Duration',
        'Flow Bytes/s',
        'Flow IAT Mean',
        'Flow IAT Std',
        'Fwd IAT Mean',
        'Bwd IAT Mean',
        'Total Fwd Packets',
        'Total Backward Packets',
        'Fwd Packet Length Mean',
        'Bwd Packet Length Mean',
        'SYN Flag Count',
        'ACK Flag Count',
    ]
    for k in key_features:
        print(f"  {k}: {feats.get(k, 0):.3f}")

# ============================================================
# Classify with RF model
# ============================================================
print("\n=== Classification with RF model (cicddos2019_rf.pkl) ===")
try:
    clf_rf = DDoSClassifier(r'models\cicddos2019_rf.pkl')
    for i, flow in enumerate(captured_flows):
        feats = flow.to_feature_dict()
        result = clf_rf.predict_vector(feats)
        print(f"Flow {i}: pred={result['label']}, is_attack={result['is_attack']}, conf={result['confidence']:.3f}")
except Exception as e:
    print(f"RF classifier error: {e}")

# ============================================================
# Classify with XGBoost model
# ============================================================
print("\n=== Classification with XGBoost model (cicddos2019_xgboost.pkl) ===")
try:
    clf_xgb = DDoSClassifier(r'models\cicddos2019_xgboost.pkl')
    for i, flow in enumerate(captured_flows):
        feats = flow.to_feature_dict()
        result = clf_xgb.predict_vector(feats)
        print(f"Flow {i}: pred={result['label']}, is_attack={result['is_attack']}, conf={result['confidence']:.3f}")
except Exception as e:
    print(f"XGBoost classifier error: {e}")

# ============================================================
# Classify with Ensemble
# ============================================================
print("\n=== Classification with Ensemble ===")
try:
    from src.models.ensemble import get_default_ensemble, score_flow
    ensemble = get_default_ensemble()

    for mode in ['rf_only', 'xgb_only', 'ensemble']:
        print(f"\n--- Ensemble mode: {mode} ---")
        for i, flow in enumerate(captured_flows):
            feats = flow.to_feature_dict()
            label, conf, breakdown = ensemble.score_flow(features=feats, mode=mode)
            print(f"Flow {i}: pred={label}, conf={conf:.3f}")
            if breakdown:
                for model_name, model_data in breakdown.items():
                    if isinstance(model_data, dict) and 'label' in model_data:
                        print(f"  {model_name}: {model_data['label']} ({model_data['confidence']:.3f})")
except Exception as e:
    print(f"Ensemble error: {e}")

print("\n=== Test Complete ===")