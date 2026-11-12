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
CONTAIN="${CONTAIN:-0}"   # CONTAIN=1: v5.4.0 containment demo (long floods + the lab enforcer)
if [ "$CONTAIN" = "1" ]; then
  CATALOG="demo"; SCENARIOS="${DEMO_SCENARIOS:-contain_syn_flood,contain_udp_flood}"
else
  CATALOG="main"; SCENARIOS="${DEMO_SCENARIOS:-benign_baseline,syn_flood,icmp_flood,flash_crowd,udp_flood}"
fi
GAP="${DEMO_GAP:-15}"
SEED="${DEMO_SEED:-$(date +%s)}"

[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 1; }
grep -qi microsoft /proc/version || { echo "refusing: not WSL2"; exit 1; }
[ ! -e lab/KILL ] || { echo "lab/KILL exists: remove it first (rm lab/KILL)"; exit 1; }
command -v ovs-ofctl >/dev/null || { echo "ovs-ofctl missing: sudo apt install openvswitch-switch"; exit 1; }

mn -c >/dev/null 2>&1 || true
mkdir -p "$OUT"
ENF_PID=""
if [ "$CONTAIN" = "1" ]; then
  # applies ONLY admin-approved actions (relayed by the Windows bridge); removes all its rules on exit
  python3 -m lab.traffic.enforcer --run "$OUT" > "$OUT/enforcer_stdout.txt" 2>&1 &
  ENF_PID=$!
  trap '[ -n "$ENF_PID" ] && kill -TERM "$ENF_PID" 2>/dev/null; wait "$ENF_PID" 2>/dev/null || true' EXIT
  echo "lab enforcer started (pid $ENF_PID); it applies only rules an admin approves on the website"
fi
echo "live demo -> $OUT"
echo "sequence: $SCENARIOS (gap ${GAP}s); start scripts/live_bridge.py on Windows now if not running"
python3 -m lab.traffic.orchestrate --out "$OUT" --catalog "$CATALOG" --seed "$SEED" --scenarios "$SCENARIOS"   --gap "$GAP" --containment --ovs-poll
echo "done: $OUT (manifest.json, *.pcap, ovs_ports.jsonl)"
