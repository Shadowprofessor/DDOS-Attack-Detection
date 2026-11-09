# -*- coding: utf-8 -*-
"""
Mininet lab topology for the SDN DDoS testbed.

Builds a linear chain of OpenFlow 1.3 Open vSwitch nodes, each hosting a small group
of CPU-limited hosts on the 10.0.0.0/24 subnet, and designates one host as the victim
running a real HTTP service. The network is driven by a remote Ryu controller.

Lab use only.
"""
import os
import sys

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.clean import cleanup
from mininet.node import OVSKernelSwitch, RemoteController

SWITCH_COUNT = 6
HOSTS_PER_SWITCH = 3
HOST_CPU_SHARE = 1.0 / 20        # throttle each host so a flood cannot starve the VM
VICTIM_HOST = "h3"               # host that runs the target HTTP service
CONTROLLER_IP = "127.0.0.1"
CONTROLLER_PORT = 6653
HTTP_PORT = 80


class ChainTopo(Topo):
    """Chain of switches; hosts distributed evenly, addressed 10.0.0.<n>/24."""

    def build(self):
        switches = []
        host_n = 0
        for s in range(1, SWITCH_COUNT + 1):
            switch = self.addSwitch(f"s{s}", cls=OVSKernelSwitch, protocols="OpenFlow13")
            switches.append(switch)
            for _ in range(HOSTS_PER_SWITCH):
                host_n += 1
                host = self.addHost(
                    f"h{host_n}",
                    cpu=HOST_CPU_SHARE,
                    mac="00:00:00:00:00:%02d" % host_n,
                    ip=f"10.0.0.{host_n}/24",
                )
                self.addLink(host, switch)
        for upstream, downstream in zip(switches, switches[1:]):
            self.addLink(upstream, downstream)


def ensure_ovs():
    """Best-effort start of Open vSwitch; a no-op if it is already running."""
    os.system("service openvswitch-switch start >/dev/null 2>&1")
    os.system(
        "pgrep ovs-vswitchd >/dev/null 2>&1 || "
        "ovs-vswitchd --pidfile --detach --log-file >/dev/null 2>&1"
    )


def start_network():
    """Bring up the topology under a remote controller and start the victim HTTP service."""
    ensure_ovs()
    sys.stdout.flush()
    controller = RemoteController("c0", ip=CONTROLLER_IP, port=CONTROLLER_PORT)
    try:
        net = Mininet(topo=ChainTopo(), link=TCLink, controller=controller)
    except Exception:
        cleanup()
        ensure_ovs()
        net = Mininet(topo=ChainTopo(), link=TCLink, controller=controller)
    try:
        net.start()
        victim = net.get(VICTIM_HOST)
        victim.cmd(f"python3 -m http.server {HTTP_PORT} >/tmp/h3_victim_http.log 2>&1 &")
        print(f"[*] Victim {VICTIM_HOST} (10.0.0.3) listening on HTTP port {HTTP_PORT}")
        sys.stdout.flush()
        CLI(net)
    finally:
        net.stop()


# Back-compat aliases for existing runners and docs.
MyTopo = ChainTopo
startNetwork = start_network

if __name__ == "__main__":
    setLogLevel("info")
    start_network()
