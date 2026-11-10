# -*- coding: utf-8 -*-
"""
LAB-ONLY orchestrator (v4.6.1). Run as root inside WSL2:

    sudo python3 -m lab.traffic.orchestrate --out data/lab_runs/<run-id> [--scenarios all] [--containment]

Builds an isolated Mininet LAN (10.99.0.0/24, one switch, no controller, NO NAT, no route out),
starts plain HTTP on the victim, then for each scenario: starts a pcap capture on the victim's
interface, runs the gated generator *inside the scenario's source host namespace*, stops the
capture, and records start/end times. Analysis happens later on the host:
`python -m src.eval.lab_analysis data/lab_runs/<run-id>`.

`--containment` adds a temporary NAT path out of the lab, loads lab/traffic/containment.nft,
sends 3 ICMP probes from a lab host to 192.0.2.1 (TEST-NET-1, documentation-only), and checks the
nftables drop counter went up and nothing left on the uplink. Then it removes the NAT path and
the rules again.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import time
from pathlib import Path

from lab.library import load_scenarios
from lab.safety import KillSwitch, SafetyError, load_scope, source_addresses

REPO = Path(__file__).resolve().parent.parent.parent
TEST_NET = "192.0.2.1"
NFT_TABLE = "ddos_lab_containment"


def build_net(scope, switch: str, with_nat: bool = False):  # pragma: no cover - needs root + Mininet
    from mininet.net import Mininet
    from mininet.node import OVSBridge
    from mininet.nodelib import LinuxBridge

    sw_cls = OVSBridge if switch == "ovs" else LinuxBridge
    net = Mininet(controller=None, switch=sw_cls, autoSetMacs=True, waitConnected=False,
                  ipBase=str(scope.networks[0]))
    s1 = net.addSwitch("s1")
    hosts = {}
    for role, ip in scope.hosts.items():
        h = net.addHost(role, ip=f"{ip}/24")
        net.addLink(h, s1)
        hosts[role] = h
    if with_nat:  # containment test only: deliberately open a path out, then prove it is dropped
        net.addNAT(name="nat0", ip="10.99.0.254/24")  # subnet from ipBase; sets host default routes
    net.start()
    for role in scope.source_pools:  # lab-only source aliases on that host
        for a in source_addresses(scope, role, 254):
            hosts[role].cmd(f"ip addr add {a}/24 dev {role}-eth0")
    v = hosts["victim"]
    for port in (80, 443):
        v.cmd(f"python3 -m http.server {port} --bind {scope.hosts['victim']} >/dev/null 2>&1 &")
    time.sleep(1.0)
    return net, hosts


def run_scenarios(net, hosts, scope, names, out: Path, gap_s: float = 3.0) -> list:  # pragma: no cover
    kill = KillSwitch.from_scope(scope)
    scs = load_scenarios()
    results = []
    v = hosts["victim"]
    repo = shlex.quote(str(REPO))  # the repo path contains spaces
    env = f"cd {repo} && PYTHONPATH={repo}"
    for sid in names:
        if kill.tripped():
            print("kill switch tripped; stopping")
            break
        sc = scs[sid]
        pcap = out / f"{sid}.pcap"
        cap = v.popen(["tcpdump", "-i", "victim-eth0", "-U", "-s", "160", "-w", str(pcap)])
        time.sleep(1.0)
        src_host = hosts[sc.profile.source_role]
        t0 = time.time()
        raw = src_host.cmd(f"{env} python3 -m lab.traffic.generator --scenario {shlex.quote(sid)}")
        t1 = time.time()
        time.sleep(1.0)
        cap.terminate()
        cap.wait()
        report = None
        for line in reversed(raw.strip().splitlines()):
            if line.startswith("{"):
                report = json.loads(line)
                break
        results.append({"scenario": sid, "pcap": pcap.name, "started_at": t0, "ended_at": t1,
                        "generator": report, "stderr_tail": None if report else raw[-500:]})
        print(sid, "->", report)
        time.sleep(gap_s)
    return results


def containment_test(net, hosts, scope, uplink: str) -> dict:  # pragma: no cover - needs root
    """With a NAT path out of the lab deliberately open, prove nftables drops lab egress."""
    nft_file = REPO / "lab" / "traffic" / "containment.nft"
    nat = net.get("nat0")
    h = hosts["client"]
    subprocess.run(["nft", "-f", str(nft_file)], check=True)  # list args: spaces in path are safe
    before = _drop_count()
    cap = nat.popen(["tcpdump", "-i", uplink, "-n", "-l", f"host {TEST_NET}"])
    time.sleep(1.0)
    h.cmd(f"ping -c 3 -W 1 {TEST_NET}")
    time.sleep(2.0)
    cap.terminate()
    out, _ = cap.communicate(timeout=5)
    seen = len([ln for ln in (out or b"").decode(errors="ignore").splitlines() if TEST_NET in ln])
    after = _drop_count()
    subprocess.run(["nft", "delete", "table", "inet", NFT_TABLE], check=False)
    return {"probe": TEST_NET, "drops_before": before, "drops_after": after,
            "uplink": uplink, "packets_seen_on_uplink": seen, "contained": after > before and seen == 0}


def _drop_count() -> int:  # pragma: no cover
    import re

    txt = subprocess.run(["nft", "list", "table", "inet", NFT_TABLE], capture_output=True, text=True).stdout
    return sum(int(n) for n in re.findall(r"counter packets (\d+) bytes \d+ drop", txt))


def main() -> None:  # pragma: no cover
    ap = argparse.ArgumentParser(description="LAB-ONLY Mininet orchestrator (run as root in WSL2)")
    ap.add_argument("--out", required=True)
    ap.add_argument("--scenarios", default="all")
    ap.add_argument("--switch", choices=["ovs", "lxbr"], default="ovs")  # OVS is running in this WSL2
    ap.add_argument("--containment", action="store_true")
    ap.add_argument("--uplink", default="eth0")
    args = ap.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run with sudo inside WSL2")
    if "microsoft" not in Path("/proc/version").read_text().lower():
        raise SafetyError("refusing: not WSL2")
    scope = load_scope()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    names = [] if args.scenarios == "none" else (list(load_scenarios()) if args.scenarios == "all"
                                                 else args.scenarios.split(","))
    manifest = {"started": time.time(), "scope": [str(n) for n in scope.networks], "switch": args.switch}
    try:
        if args.containment:  # separate net with a NAT path; torn down before any scenario runs
            net, hosts = build_net(scope, args.switch, with_nat=True)
            try:
                manifest["containment"] = containment_test(net, hosts, scope, args.uplink)
                print("containment:", manifest["containment"])
            finally:
                net.stop()
        if args.scenarios != "none":
            net, hosts = build_net(scope, args.switch)  # no NAT, no route out
            try:
                manifest["runs"] = run_scenarios(net, hosts, scope, names, out)
            finally:
                net.stop()
    finally:
        manifest["ended"] = time.time()
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
        print("wrote", out / "manifest.json")


if __name__ == "__main__":  # pragma: no cover
    main()
