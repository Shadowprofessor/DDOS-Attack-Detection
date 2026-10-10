import os
import pandas as pd
import numpy as np

def generate_sample_dataset(filename="FlowStatsfile.csv", num_samples=2000):
    """
    Generates realistic SDN Flow Statistics dataset containing both
    Benign network traffic (HTTP, HTTPS, SSH, DNS) and DDoS Attack vectors
    (TCP SYN Flood, ICMP Echo Flood, UDP Amplification, LAND Attack).
    """
    np.random.seed(42)
    data = []
    
    for _ in range(num_samples):
        is_ddos = np.random.choice([0, 1], p=[0.5, 0.5])
        
        if is_ddos:
            attack_kind = np.random.choice(["SYN", "ICMP", "UDP", "LAND"])
            
            if attack_kind == "LAND":
                ip_src = "10.0.0.1"
                ip_dst = "10.0.0.1"
                tp_src = 80
                tp_dst = 80
                ip_proto = 6
                icmp_code = -1
                icmp_type = -1
            elif attack_kind == "SYN":
                ip_src = f"192.168.1.{np.random.randint(100, 254)}"
                ip_dst = f"10.0.0.{np.random.randint(1, 5)}"
                tp_src = np.random.randint(1024, 65535)
                tp_dst = 80
                ip_proto = 6  # TCP
                icmp_code = -1
                icmp_type = -1
            elif attack_kind == "ICMP":
                ip_src = f"192.168.1.{np.random.randint(100, 254)}"
                ip_dst = f"10.0.0.{np.random.randint(1, 5)}"
                tp_src = 0
                tp_dst = 0
                ip_proto = 1  # ICMP
                icmp_code = 0
                icmp_type = 8
            else:  # UDP
                ip_src = f"192.168.1.{np.random.randint(100, 254)}"
                ip_dst = f"10.0.0.{np.random.randint(1, 5)}"
                tp_src = np.random.randint(1024, 65535)
                tp_dst = 53
                ip_proto = 17  # UDP
                icmp_code = -1
                icmp_type = -1
            
            duration_sec = np.random.randint(1, 5)
            duration_nsec = np.random.randint(1000, 999999)
            idle_timeout = 0
            hard_timeout = 0
            flags = 2 if ip_proto == 6 else 0
            pkt_cnt = np.random.randint(8000, 60000)
            byte_cnt = pkt_cnt * np.random.randint(64, 128)
        else:
            # Benign traffic
            ip_src = f"10.0.0.{np.random.randint(1, 18)}"
            ip_dst = f"10.0.0.{np.random.randint(1, 18)}"
            tp_src = np.random.randint(1024, 65535)
            tp_dst = np.random.choice([80, 443, 22, 53])
            ip_proto = 17 if tp_dst == 53 else 6
            icmp_code = -1
            icmp_type = -1
            duration_sec = np.random.randint(10, 120)
            duration_nsec = np.random.randint(1000, 999999)
            idle_timeout = 0
            hard_timeout = 0
            flags = 16
            pkt_cnt = np.random.randint(10, 400)
            byte_cnt = pkt_cnt * np.random.randint(200, 1400)
            
        rate_pps = pkt_cnt / max(duration_sec, 1)
        rate_npps = pkt_cnt / max(duration_nsec, 1)
        rate_bps = byte_cnt / max(duration_sec, 1)
        rate_nbps = byte_cnt / max(duration_nsec, 1)
        
        data.append([
            ip_src, tp_src, ip_dst, tp_dst, ip_proto, icmp_code, icmp_type,
            duration_sec, duration_nsec, idle_timeout, hard_timeout, flags,
            pkt_cnt, byte_cnt, rate_pps, rate_npps, rate_bps, rate_nbps, is_ddos
        ])
        
    columns = [
        'ip_src', 'tp_src', 'ip_dst', 'tp_dst', 'ip_proto', 'icmp_code',
        'icmp_type', 'flow_duration_sec', 'flow_duration_nsec', 'idle_timeout',
        'hard_timeout', 'flags', 'packet_count', 'byte_count',
        'packet_count_per_second', 'packet_count_per_nsecond',
        'byte_count_per_second', 'byte_count_per_nsecond', 'label'
    ]
    
    df = pd.DataFrame(data, columns=columns)
    
    # Save dataset to multiple expected locations
    target_locations = [
        filename,
        os.path.join(os.path.dirname(__file__), "FlowStatsfile.csv"),
        os.path.join(os.path.dirname(__file__), "Codes", "ml", "FlowStatsfile.csv")
    ]
    
    for loc in set(target_locations):
        try:
            os.makedirs(os.path.dirname(os.path.abspath(loc)), exist_ok=True)
            df.to_csv(loc, index=False)
        except Exception:
            pass
            
    print(f"Generated high-accuracy dataset '{filename}' ({num_samples} records).")
    return df

if __name__ == "__main__":
    generate_sample_dataset()
