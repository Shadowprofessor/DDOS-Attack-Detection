import sys, time, threading
sys.path.insert(0, r'.')

from scapy.all import IP, TCP, send, sniff, socket
from src.features.flow_extractor import FlowExtractor, Packet as FlowPacket

TARGET_IP = '127.0.0.1'
TARGET_PORT = 9999
ATTACK_DURATION = 3

# Start a simple TCP echo listener
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((TARGET_IP, TARGET_PORT))
server.listen(5)
print(f'Listening on {TARGET_IP}:{TARGET_PORT}', flush=True)

# Accept a connection in background
def accept_conn():
    conn, addr = server.accept()
    conn.settimeout(ATTACK_DURATION + 2)
    try:
        data = conn.recv(1024)
        print(f'Received {len(data)} bytes from {addr}', flush=True)
        conn.send(b'ACK')
    except:
        pass
    conn.close()

accept_thread = threading.Thread(target=accept_conn, daemon=True)
accept_thread.start()

extractor = FlowExtractor(active_timeout=120.0, idle_timeout=60.0)
captured_flows = []
capture_done = __import__('threading').Event()

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
        iface=r'\Device\NPF_Loopback',
        filter=f'tcp and port {TARGET_PORT}',
        prn=packet_callback,
        timeout=ATTACK_DURATION + 5,
        store=False
    )
    captured_flows.extend(extractor.flush_all())
    capture_done.set()

capture_thread = threading.Thread(target=capture_packets)
capture_thread.start()
time.sleep(0.5)

print('Generating SYN flood...', flush=True)
start_time = time.time()
packet_count = 0
while time.time() - start_time < ATTACK_DURATION:
    pkt = IP(src='127.0.0.1', dst=TARGET_IP) / TCP(sport=54321, dport=TARGET_PORT, flags='S', seq=1000, window=65535)
    send(pkt, verbose=0, iface=r'\Device\NPF_Loopback')
    packet_count += 1
    time.sleep(0.001)

print(f'Sent {packet_count} SYN packets', flush=True)
server.close()

capture_thread.join(timeout=5)

print(f'\n=== Results: {len(captured_flows)} flows ===')
for i, flow in enumerate(captured_flows):
    feats = flow.to_feature_dict()
    print(f'Flow {i}: fwd={flow.fwd_packet_count}, bwd={flow.bwd_packet_count}', flush=True)
    print(f'  SYN: {flow.syn_count}, ACK: {flow.ack_count}, RST: {flow.rst_count}', flush=True)
    # Show key features that matter for classification
    for k in ['Down/Up Ratio', 'Flow Packets/s', 'Fwd Packets/s', 'Bwd Packets/s', 'Flow Duration', 'Flow Bytes/s']:
        print(f'  {k}: {feats.get(k, 0):.3f}', flush=True)