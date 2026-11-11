# -*- coding: utf-8 -*-
"""
Threat-hunt rules (v4.7.0). Each rule came from a written hunt hypothesis (docs/hunts/) and covers
a gap the per-source L1 thresholds and the per-flow ML miss by design.

H1 `LowRateReflectionRule`: distributed reflection/amplification where *each* reflector stays
   under per-source thresholds, but together they flood one victim from amplification service
   ports (DNS 53, NTP 123, LDAP 389, SSDP 1900, memcached 11211, ...).
H2 `SlowReadRule`: slow-read L7 abuse spread across many sources. Each client holds a long HTTP
   connection with a tiny advertised receive window and drains the response slowly, so no single
   source (or the per-target low-and-slow counter, which looks at *sending* rate) stands out.

Both are pure functions over flow records (no I/O) so they can run as a hunt over stored flows
or as a streaming detector. Thresholds are explicit and documented; they are starting points to
tune on more data, not validated optima.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional

REFLECTOR_SPORTS = frozenset({19, 53, 69, 111, 123, 137, 161, 389, 1434, 1900, 3702, 5683, 11211})
HTTP_PORTS = frozenset({80, 443, 8080, 8443})


@dataclass
class FlowRecord:
    src: str
    dst: str
    sport: int
    dport: int
    proto: int            # 6 tcp, 17 udp
    start: float
    end: float
    packets: int
    bytes: float          # total bytes, both directions
    fwd_bytes: float = 0.0
    bwd_bytes: float = 0.0
    init_fwd_win: Optional[int] = None  # client's advertised TCP window (CICFlowMeter "Init Fwd Win Bytes")


@dataclass
class HuntFinding:
    rule: str
    victim: str
    window_start: float
    evidence: Dict = field(default_factory=dict)


@dataclass
class LowRateReflectionRule:
    window_s: float = 60.0
    min_reflectors: int = 50          # distinct reflector sources toward one victim
    max_per_source_pps: float = 20.0  # every reflector stays under typical per-source thresholds
    min_total_pps: float = 200.0      # ...but together they are a flood
    name: str = "H1_low_rate_distributed_reflection"

    def evaluate(self, flows: Iterable[FlowRecord]) -> List[HuntFinding]:
        buckets: Dict[tuple, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for f in flows:
            if f.proto == 17 and f.sport in REFLECTOR_SPORTS:
                buckets[(f.dst, int(f.start // self.window_s))][f.src] += f.packets
        out = []
        for (victim, w), per_src in buckets.items():
            if len(per_src) < self.min_reflectors:
                continue
            rates = {s: n / self.window_s for s, n in per_src.items()}
            total = sum(rates.values())
            if total >= self.min_total_pps and max(rates.values()) <= self.max_per_source_pps:
                out.append(HuntFinding(self.name, victim, w * self.window_s, {
                    "reflectors": len(per_src), "total_pps": round(total, 1),
                    "max_per_source_pps": round(max(rates.values()), 2)}))
        return out


@dataclass
class SlowReadRule:
    min_duration_s: float = 20.0
    max_init_window: int = 1024       # tiny advertised receive window
    max_bwd_bytes_per_s: float = 200.0  # server -> client throughput starved by the client
    min_sources: int = 10
    name: str = "H2_distributed_slow_read"

    def evaluate(self, flows: Iterable[FlowRecord]) -> List[HuntFinding]:
        per_victim: Dict[str, set] = defaultdict(set)
        start: Dict[str, float] = {}
        for f in flows:
            dur = f.end - f.start
            if (f.proto == 6 and f.dport in HTTP_PORTS and dur >= self.min_duration_s
                    and f.init_fwd_win is not None and 0 < f.init_fwd_win <= self.max_init_window
                    and f.bwd_bytes / max(dur, 1e-6) <= self.max_bwd_bytes_per_s):
                per_victim[f.dst].add(f.src)
                start[f.dst] = min(start.get(f.dst, f.start), f.start)
        return [HuntFinding(self.name, v, start[v], {"sources": len(srcs)})
                for v, srcs in per_victim.items() if len(srcs) >= self.min_sources]


RULES = (LowRateReflectionRule(), SlowReadRule())


def run_hunts(flows: List[FlowRecord]) -> Dict[str, List[HuntFinding]]:
    return {r.name: r.evaluate(flows) for r in RULES}
