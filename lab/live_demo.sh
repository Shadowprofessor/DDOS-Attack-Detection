#!/usr/bin/env bash
# LAB-ONLY live demo (v5.2.0). In a WSL2 Ubuntu terminal, from the repo root:
#
#     sudo bash lab/live_demo.sh            # writes data/lab_runs/live1/
#     sudo bash lab/live_demo.sh live2      # another run id
#
# Same safety layer as every lab run: isolated Mininet LAN, no NAT, lab/lab_scope.yaml caps,
# containment proof first, kill switch (`touch lab/KILL` from another terminal).
# tcpdump -U writes each scenario's pcap packet by packet; the OVS poller writes switch counters.
# On Windows, `python scripts/live_bridge.py data/lab_runs/<run>` streams both into the SOC app.
set -euo pipefail
cd "$(dirname "$0")/.."

RUN="${1:-live1}"
OUT="data/lab_runs/$RUN"
SCENARIOS="${DEMO_SCENARIOS:-benign_baseline,syn_flood,icmp_flood,flash_crowd,udp_flood}"
GAP="${DEMO_GAP:-15}"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
grep -qi microsoft /proc/version || { echo "refusing: not WSL2"; exit 1; }
[ ! -e lab/KILL ] || { echo "lab/KILL exists: remove it first (rm lab/KILL)"; exit 1; }
command -v ovs-ofctl >/dev/null || { echo "ovs-ofctl missing: sudo apt install openvswitch-switch"; exit 1; }

mn -c >/dev/null 2>&1 || true
mkdir -p "$OUT"
echo "live demo -> $OUT"
echo "sequence: $SCENARIOS (gap ${GAP}s); start scripts/live_bridge.py on Windows now if not running"
python3 -m lab.traffic.orchestrate --out "$OUT" --scenarios "$SCENARIOS" --gap "$GAP" --containment --ovs-poll
echo "done: $OUT (manifest.json, *.pcap, ovs_ports.jsonl)"
