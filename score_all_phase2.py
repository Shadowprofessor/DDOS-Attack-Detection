#!/usr/bin/env python3
import os
import sys
import json
import urllib.request

REPO_PATH = "/mnt/c/Users/Sachit Sharma/Documents/DDoS-Attack-Detection-and-Mitigation-using-Machine-Learning"
sys.path.insert(0, REPO_PATH)

from src.features.flow_extractor import FlowExtractor

API_URL = "http://172.29.128.1:8000/score/flow?model=ensemble"
HEADERS = {
    "Content-Type": "application/json",
    "X-API-Key": "scoring-key-test"
}

targets = [
    "Syn", "UDP", "NTP", "DNS", "LDAP", "MSSQL",
    "NetBIOS", "Portmap", "SNMP", "TFTP", "UDP-Lag", "WebDDoS", "benign"
]

results = []

extractor = FlowExtractor()

for name in targets:
    pcap_file = f"/root/pcaps/{name}.pcap" if os.path.exists(f"/root/pcaps/{name}.pcap") else f"/tmp/{name}.pcap"
    out_json = f"/tmp/{name}_features.json"

    if not os.path.exists(pcap_file):
        print(f"[!] Missing PCAP {pcap_file}")
        continue

    flows = extractor.process_pcap(pcap_file)
    if not flows:
        print(f"[!] No flows in {pcap_file}")
        continue

    # Pick the primary flow (highest packet count)
    flows.sort(key=lambda f: f.fwd_packet_count + f.bwd_packet_count, reverse=True)
    primary_flow = flows[0]
    feat_dict = primary_flow.to_feature_dict()

    payload = {"features": feat_dict}
    with open(out_json, "w", encoding="utf-8") as fp:
        json.dump(payload, fp)

    # Post to scoring API
    req = urllib.request.Request(API_URL, data=json.dumps(payload).encode("utf-8"), headers=HEADERS)
    try:
        with urllib.request.urlopen(req) as resp:
            resp_body = json.loads(resp.read().decode("utf-8"))
            res = resp_body.get("result", {})
            results.append((name, res))
    except Exception as e:
        print(f"[!] API call failed for {name}: {e}")
        results.append((name, {"error": str(e)}))

print(json.dumps(results, indent=2))
