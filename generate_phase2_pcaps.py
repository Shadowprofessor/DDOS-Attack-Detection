#!/usr/bin/env python3
import time
import subprocess
from mininet.net import Mininet
from mininet.node import Controller
from mininet.log import setLogLevel

setLogLevel('info')

attacks = [
    ("Syn", "hping3 -S -p 80 -c 1000 -i u1000 10.0.0.2"),
    ("UDP", "hping3 --udp -p 80 -c 1000 -i u1000 10.0.0.2"),
    ("NTP", """python3 -c "from scapy.all import *; pkts = [IP(dst='10.0.0.2')/UDP(sport=RandShort(),dport=123)/Raw(b'\\x17\\x00\\x03\\x2a'+b'\\x00'*4) for _ in range(500)]; send(pkts, verbose=0)" """),
    ("DNS", """python3 -c "from scapy.all import *; pkts = [IP(dst='10.0.0.2')/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname='test.com')) for _ in range(500)]; send(pkts, verbose=0)" """),
    ("LDAP", """python3 -c "from scapy.all import *; pkts = [IP(dst='10.0.0.2')/TCP(dport=389,flags='S') for _ in range(500)]; send(pkts, verbose=0)" """),
    ("MSSQL", """python3 -c "from scapy.all import *; pkts = [IP(dst='10.0.0.2')/UDP(dport=1434)/Raw(b'\\x02') for _ in range(500)]; send(pkts, verbose=0)" """),
    ("NetBIOS", """python3 -c "from scapy.all import *; pkts = [IP(dst='10.0.0.2')/UDP(dport=137)/Raw(b'\\x00'*50) for _ in range(500)]; send(pkts, verbose=0)" """),
    ("Portmap", """python3 -c "from scapy.all import *; pkts = [IP(dst='10.0.0.2')/UDP(dport=111)/Raw(b'\\x00'*50) for _ in range(500)]; send(pkts, verbose=0)" """),
    ("SNMP", """python3 -c "from scapy.all import *; pkts = [IP(dst='10.0.0.2')/UDP(dport=161)/Raw(b'\\x30\\x26\\x02\\x01') for _ in range(500)]; send(pkts, verbose=0)" """),
    ("TFTP", """python3 -c "from scapy.all import *; pkts = [IP(dst='10.0.0.2')/UDP(dport=69)/Raw(b'\\x00\\x01'+b'test\\x00'+b'octet\\x00') for _ in range(500)]; send(pkts, verbose=0)" """),
    ("UDP-Lag", """python3 -c "from scapy.all import *; pkts = [IP(dst='10.0.0.2')/UDP(dport=RandShort())/Raw(b'\\x00'*1400) for _ in range(500)]; send(pkts, verbose=0)" """),
    ("WebDDoS", """python3 -c "from scapy.all import *; pkts = [IP(dst='10.0.0.2')/TCP(dport=80,flags='S') for _ in range(500)]; send(pkts, verbose=0)" """),
]

def main():
    net = Mininet(controller=Controller)
    c0 = net.addController('c0')
    h1 = net.addHost('h1', ip='10.0.0.1')
    h2 = net.addHost('h2', ip='10.0.0.2')
    s1 = net.addSwitch('s1')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.start()

    print("=== Mininet Started ===")
    h1.cmd('ping -c 2 10.0.0.2')

    for name, cmd in attacks:
        pcap_file = f"/root/pcaps/{name}.pcap"
        print(f"\n[*] Generating attack: {name} -> {pcap_file}")
        # Start tcpdump on switch interface s1-eth1
        tcpdump_proc = subprocess.Popen(["tcpdump", "-i", "s1-eth1", "-c", "1000", "-w", pcap_file],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)
        h1.cmd(cmd)
        time.sleep(1.0)
        tcpdump_proc.terminate()
        try:
            tcpdump_proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            tcpdump_proc.kill()
        
        # Verify packet count
        res = subprocess.run(f"tcpdump -r {pcap_file} 2>/dev/null | wc -l", shell=True, capture_output=True, text=True)
        count = int(res.stdout.strip()) if res.stdout.strip() else 0
        print(f"    [OK] {name} captured {count} packets.")
        subprocess.run(f"cp {pcap_file} /tmp/{name}.pcap 2>/dev/null", shell=True)

    # Benign baseline
    benign_pcap = "/root/pcaps/benign.pcap"
    print(f"\n[*] Generating benign baseline -> {benign_pcap}")
    tcpdump_proc = subprocess.Popen(["tcpdump", "-i", "s1-eth1", "-c", "100", "-w", benign_pcap],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    h1.cmd("ping -c 30 10.0.0.2")
    time.sleep(1.0)
    tcpdump_proc.terminate()
    try:
        tcpdump_proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        tcpdump_proc.kill()
    
    res = subprocess.run(f"tcpdump -r {benign_pcap} 2>/dev/null | wc -l", shell=True, capture_output=True, text=True)
    count = int(res.stdout.strip()) if res.stdout.strip() else 0
    print(f"    [OK] Benign captured {count} packets.")
    subprocess.run(f"cp {benign_pcap} /tmp/benign.pcap 2>/dev/null", shell=True)

    net.stop()
    print("\n=== Mininet Stopped. All PCAPs generated! ===")

if __name__ == '__main__':
    main()
