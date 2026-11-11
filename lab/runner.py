# -*- coding: utf-8 -*-
"""
Mock scenario runner (v4.6.0). Sends NO packets.

`MockRunner.run()` puts a scenario through every safety check (environment, targets, caps,
concurrency, kill switch), then "runs" it as a sequence of ticks that only *describe* the traffic
(synthetic per-tick counts). The kill switch is re-checked before every tick. The synthetic
summary can be turned into an `IncidentAggregate` and replayed through L1 -> L2 -> rule L3, which
checks the pipeline wiring in CI.

That replay is a **pipeline check, not detection evidence**: the aggregate is built from the
scenario's own description. Real measurements need real traffic and the v4.6.1 Mininet runner,
which needs explicit approval before any traffic-generation code is written.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from lab.safety import (EnvReport, KillSwitch, LabScope, SafetyError, check_profile, check_target,
                        default_probe, require_lab_environment)
from lab.library import Scenario

PROTO_MIX = {
    "tcp_syn": ({"tcp": 0.98, "udp": 0.01, "icmp": 0.01}, {"syn": 0.95, "ack": 0.02}),
    "udp": ({"udp": 0.97, "tcp": 0.03}, {}),
    "udp_reflection": ({"udp": 0.97, "tcp": 0.03}, {}),
    "dns_reflection": ({"udp": 0.97, "tcp": 0.03}, {}),
    "http": ({"tcp": 0.99, "udp": 0.01}, {"syn": 0.1, "ack": 0.8}),
    "http_slow": ({"tcp": 0.99, "udp": 0.01}, {"syn": 0.05, "ack": 0.9}),
    "mixed": ({"tcp": 0.5, "udp": 0.4, "icmp": 0.1}, {"syn": 0.3, "ack": 0.5}),
    "icmp": ({"icmp": 0.99, "tcp": 0.01}, {}),
    "tcp_ack": ({"tcp": 0.99, "udp": 0.01}, {"ack": 0.97, "syn": 0.0}),
    "tcp_rst": ({"tcp": 0.99, "udp": 0.01}, {"rst": 0.97, "syn": 0.0}),
    "land": ({"tcp": 0.99, "udp": 0.01}, {"syn": 0.95}),
}


@dataclass
class RunReport:
    scenario_id: str
    planned_ticks: int
    ticks_run: int
    stopped_by: str  # "completed" | "kill_switch"
    env: EnvReport
    ticks: List[Dict] = field(default_factory=list)


class MockRunner:
    _running = 0
    _lock = threading.Lock()

    def __init__(self, scope: LabScope, probe: Callable[[], EnvReport] = default_probe,
                 kill: Optional[KillSwitch] = None, sleep: Callable[[float], None] = time.sleep,
                 clock: Callable[[], float] = time.time):
        self.scope = scope
        self.probe = probe
        self.kill = kill or KillSwitch.from_scope(scope)
        self.sleep = sleep
        self.clock = clock

    def plan(self, sc: Scenario) -> Dict:
        """All safety checks; returns the resolved plan. Raises SafetyError on any violation."""
        env = require_lab_environment(self.scope, self.probe)
        if self.kill.tripped():
            raise SafetyError("kill switch is tripped; refusing to start")
        p = sc.profile
        if p.target_role not in self.scope.hosts or p.source_role not in self.scope.hosts:
            raise SafetyError("scenario roles are not defined in the lab scope")
        target = check_target(self.scope, str(self.scope.hosts[p.target_role]))
        source = check_target(self.scope, str(self.scope.hosts[p.source_role]))
        with MockRunner._lock:
            check_profile(self.scope, p.rate_pps, p.duration_s, running=MockRunner._running)
        return {"env": env, "target": str(target), "source": str(source)}

    def run(self, sc: Scenario) -> RunReport:
        plan = self.plan(sc)
        planned = max(1, int(sc.profile.duration_s / self.scope.caps.tick_s))
        rep = RunReport(scenario_id=sc.id, planned_ticks=planned, ticks_run=0, stopped_by="completed", env=plan["env"])
        with MockRunner._lock:
            MockRunner._running += 1
        try:
            for i in range(planned):
                if self.kill.tripped():  # re-checked before EVERY tick
                    rep.stopped_by = "kill_switch"
                    break
                rep.ticks.append({"tick": i, "ts": self.clock(), "pps": sc.profile.rate_pps,
                                  "sources": sc.profile.sources, "target": plan["target"]})
                rep.ticks_run += 1
                self.sleep(self.scope.caps.tick_s)
        finally:
            with MockRunner._lock:
                MockRunner._running -= 1
        return rep


def to_aggregate(sc: Scenario, rep: RunReport, scope: LabScope) -> dict:
    """Synthetic IncidentAggregate (dict) describing the mock run, for replay through the pipeline."""
    p = sc.profile
    proto, flags = PROTO_MIX[p.protocol]
    base = int(scope.hosts[p.source_role])
    srcs = [{"key": str(type(scope.hosts[p.source_role])(base + i)), "share": round(1.0 / p.sources, 4)}
            for i in range(min(p.sources, 10))]
    agg = {
        "incident_id": f"lab-{sc.id}",
        "window_start": rep.ticks[0]["ts"] if rep.ticks else 0.0,
        "window_seconds": max(1, int(rep.ticks_run * scope.caps.tick_s)),
        "pps": float(p.rate_pps), "bps": float(p.rate_pps * p.packet_size * 8),
        "flow_count": p.sources * max(1, rep.ticks_run), "unique_src_ips": p.sources,
        "top_src_ips": srcs, "dst_ips": [str(scope.hosts[p.target_role])],
        "dst_ports": [{"key": str(p.dst_port), "share": 0.95}] if p.dst_port else [],
        "protocol_mix": proto, "tcp_flag_ratios": flags,
        "packet_size_p50": float(p.packet_size), "packet_size_p95": float(p.packet_size),
        "alert_history": [],
    }
    if p.protocol in ("http", "http_slow"):
        agg["l7"] = {"http_rps": float(p.rate_pps) if p.protocol == "http" else 5.0,
                     "slow_connections": p.slow_connections}
    return agg
