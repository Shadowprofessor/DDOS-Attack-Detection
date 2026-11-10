# -*- coding: utf-8 -*-
"""
Gated lab traffic generator (v4.6.1). LAB-ONLY: runs inside a Mininet host namespace in WSL2.

Order of guarantees (each enforced in code and tested in tests/test_lab_traffic.py):
1. `GatedTrafficRunner.run()` first calls `MockRunner.plan()`: WSL2 + Mininet detected, kill
   switch clear, source/target roles resolved from lab/lab_scope.yaml and checked, rate/duration/
   concurrency within caps. Any failure raises SafetyError before a single packet is built.
2. Every packet's destination must equal the planned lab victim AND pass `check_target`; every
   source must pass `check_target` (inside the lab network). Checked again right before emit.
3. Total packets are capped at rate_pps x duration_s. The kill switch is checked every tick
   (default 1 s) and stops the run within one tick.
4. All sending lives in `_emit_*` functions, which only `GatedTrafficRunner` calls (AST-tested).

Usage (inside a Mininet host, normally started by lab/traffic/orchestrate.py):
    python3 -m lab.traffic.generator --scenario syn_flood
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Callable, List, Optional

from lab.library import Scenario, load_scenarios
from lab.runner import MockRunner
from lab.safety import (EnvReport, KillSwitch, LabScope, SafetyError, check_target, default_probe, load_scope,
                        source_addresses)

BATCH_S = 0.01  # pacing granularity inside a tick


@dataclass
class TrafficReport:
    scenario_id: str
    started_at: float
    ended_at: float
    packets: int
    connections: int
    stopped_by: str  # completed | kill_switch
    target: str
    achieved_pps: float = 0.0  # what was really sent (python/scapy may fall short of rate_pps)


# ----------------------------------------------------------------------------- emitters (private)
_L3 = {}


def _emit_raw(pkt) -> None:
    """Send one IP packet on a reused raw L3 socket (opening one per packet caps out ~200 pps)."""
    if "sock" not in _L3:
        from scapy.all import conf  # type: ignore  # lab-only dependency

        _L3["sock"] = conf.L3socket()
    _L3["sock"].send(pkt)


def _emit_http_get(src: str, dst: str, port: int, timeout: float = 2.0) -> None:
    import socket

    with socket.create_connection((dst, port), timeout=timeout, source_address=(src, 0)) as s:
        s.sendall(f"GET / HTTP/1.1\r\nHost: {dst}\r\nUser-Agent: ddos-lab\r\nConnection: close\r\n\r\n".encode())
        s.recv(1024)


def _emit_http_slow_open(src: str, dst: str, port: int):
    import socket

    s = socket.create_connection((dst, port), timeout=5.0, source_address=(src, 0))
    s.sendall(f"GET / HTTP/1.1\r\nHost: {dst}\r\n".encode())  # headers never completed
    return s


def _emit_http_slow_keepalive(sock) -> None:
    sock.sendall(b"X-a: b\r\n")


# ----------------------------------------------------------------------------- packet builders
def build_packet(protocol: str, src: str, dst: str, dst_port: Optional[int], size: int, rng: random.Random):
    """Scapy packet for raw protocols (no sending). Payload is zero-filled padding only."""
    from scapy.all import ICMP, IP, TCP, UDP, Raw  # type: ignore

    pad = lambda n: Raw(b"\x00" * max(0, n))  # noqa: E731
    if protocol == "tcp_syn":
        return IP(src=src, dst=dst) / TCP(sport=rng.randint(1024, 65535), dport=dst_port or 80, flags="S",
                                          seq=rng.randint(0, 2**32 - 1))
    if protocol in ("udp", "udp_reflection", "dns_reflection"):
        sport = {"udp_reflection": 123, "dns_reflection": 53}.get(protocol, rng.randint(1024, 65535))
        dport = dst_port if protocol == "udp" else rng.randint(1024, 65535)
        return IP(src=src, dst=dst) / UDP(sport=sport, dport=dport or 9999) / pad(size - 28)
    if protocol == "mixed":
        kind = rng.choice(("tcp", "udp", "icmp"))
        if kind == "tcp":
            return IP(src=src, dst=dst) / TCP(sport=rng.randint(1024, 65535), dport=rng.randint(1, 65535),
                                              flags=rng.choice(("S", "A", "PA", "FA", "R"))) / pad(rng.randint(0, size))
        if kind == "udp":
            return IP(src=src, dst=dst) / UDP(sport=rng.randint(1024, 65535), dport=rng.randint(1, 65535)) / \
                pad(rng.randint(0, size))
        return IP(src=src, dst=dst) / ICMP() / pad(rng.randint(0, size))
    raise SafetyError(f"protocol {protocol!r} has no raw packet builder")


# ----------------------------------------------------------------------------- gated runner
class GatedTrafficRunner:
    def __init__(self, scope: LabScope, probe: Callable[[], EnvReport] = default_probe,
                 kill: Optional[KillSwitch] = None, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.time, seed: int = 1, emit_raw=None, emit_http=None,
                 emit_slow_open=None, emit_slow_keepalive=None):
        self.scope = scope
        self.kill = kill or KillSwitch.from_scope(scope)
        self.planner = MockRunner(scope, probe, self.kill, sleep=sleep, clock=clock)
        self.sleep = sleep
        self.clock = clock
        self.rng = random.Random(seed)
        # injectable for tests; defaults are the real emitters
        self._raw = emit_raw or _emit_raw
        self._http = emit_http or _emit_http_get
        self._slow_open = emit_slow_open or _emit_http_slow_open
        self._slow_keep = emit_slow_keepalive or _emit_http_slow_keepalive

    def _guard(self, src: str, dst: str, target: str) -> None:
        if dst != target:
            raise SafetyError(f"packet destination {dst} is not the planned target {target}")
        check_target(self.scope, dst)
        check_target(self.scope, src)

    def run(self, sc: Scenario) -> TrafficReport:
        plan = self.planner.plan(sc)  # all scope / env / cap / kill checks; raises before any packet
        p = sc.profile
        target = plan["target"]
        sources: List[str] = [str(a) for a in source_addresses(self.scope, p.source_role, p.sources)]
        for s in sources:
            check_target(self.scope, s)
        budget = p.rate_pps * p.duration_s
        tick = self.scope.caps.tick_s
        rep = TrafficReport(sc.id, self.clock(), 0.0, 0, 0, "completed", target)
        slow_socks: list = []
        try:
            for _ in range(int(p.duration_s / tick)):
                if self.kill.tripped():
                    rep.stopped_by = "kill_switch"
                    break
                tick_start = self.clock()
                tick_end = tick_start + tick
                if p.protocol == "http_slow":
                    self._slow_tick(p, sources, target, slow_socks, rep)
                else:
                    per_tick = int(p.rate_pps * tick)
                    sent = 0
                    # paced by wall clock: never exceeds the rate, never stretches a tick
                    while sent < per_tick and rep.packets < budget:
                        now = self.clock()
                        if now >= tick_end:
                            break
                        due = tick_start + sent / p.rate_pps
                        if due > now:
                            self.sleep(min(due - now, BATCH_S))
                            continue
                        src = self.rng.choice(sources)
                        self._guard(src, target, target)
                        if p.protocol == "http":
                            if self.rng.random() < 0.2:  # ~1 request per 5 packets of rate budget
                                try:
                                    self._http(src, target, p.dst_port or 80)
                                    rep.connections += 1
                                except OSError:
                                    pass
                        else:
                            self._raw(build_packet(p.protocol, src, target, p.dst_port, p.packet_size, self.rng))
                        sent += 1
                        rep.packets += 1
                remaining = tick_end - self.clock()
                if remaining > 0:
                    self.sleep(remaining)
        finally:
            for s in slow_socks:
                try:
                    s.close()
                except OSError:
                    pass
            rep.ended_at = self.clock()
            rep.achieved_pps = round(rep.packets / max(1e-6, rep.ended_at - rep.started_at), 1)
        return rep

    def _slow_tick(self, p, sources, target, socks, rep) -> None:
        while len(socks) < p.slow_connections:
            src = sources[len(socks) % len(sources)]
            self._guard(src, target, target)
            try:
                socks.append(self._slow_open(src, target, p.dst_port or 80))
                rep.connections += 1
            except OSError:
                break
        for s in list(socks):
            try:
                self._slow_keep(s)
                rep.packets += 1
            except OSError:
                socks.remove(s)


def main() -> None:  # pragma: no cover - runs only inside the lab
    import argparse
    import json

    ap = argparse.ArgumentParser(description="Gated LAB-ONLY traffic generator (Mininet host)")
    ap.add_argument("--scenario", required=True)
    args = ap.parse_args()
    sc = load_scenarios()[args.scenario]
    rep = GatedTrafficRunner(load_scope()).run(sc)
    print(json.dumps(rep.__dict__))


if __name__ == "__main__":  # pragma: no cover
    main()
