# -*- coding: utf-8 -*-
"""
Layer 7 low-and-slow attack detector (Slowloris / R.U.D.Y.).

Low-and-slow attacks generate NO volume anomaly: packet rate, pps and bandwidth
stay within normal ranges, so rate-based L1 detectors miss them. They instead hold
many concurrent connections open with trickled, often incomplete, HTTP headers/body.
This detector keys on application-level signals — connection duration, byte-rate
starvation, header completion, and concurrency against a single target — rather than
traffic volume.
"""
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Optional, Tuple


@dataclass
class LowSlowConfig:
    min_duration_sec: float = 10.0      # a connection is "slow" only once open this long
    max_bytes_per_sec: float = 50.0     # ...and starved below this forward byte-rate
    concurrent_threshold: int = 20      # this many concurrent slow conns to one target -> alert
    window_sec: float = 60.0            # expire slow connections not seen within this window


class LowSlowDetector:
    """Detect Slowloris / R.U.D.Y. from per-flow summaries (stateful, per target)."""

    def __init__(self, config: Optional[LowSlowConfig] = None):
        self.cfg = config or LowSlowConfig()
        # (dst_ip, dst_port) -> {connection_key: last_seen_ts}
        self._slow_conns: Dict[Tuple, Dict[Tuple, float]] = defaultdict(dict)

    def _is_slow(self, flow: dict) -> bool:
        duration = float(flow.get("duration_sec", 0.0))
        if duration < self.cfg.min_duration_sec:
            return False
        if flow.get("header_complete") is False:
            return True  # trickled / never-completed headers = classic Slowloris
        fwd_bytes = float(flow.get("fwd_bytes", 0.0))
        bytes_per_sec = fwd_bytes / duration if duration > 0 else fwd_bytes
        return bytes_per_sec <= self.cfg.max_bytes_per_sec

    def observe(self, flow: dict, now: Optional[float] = None) -> Optional[dict]:
        """Feed one flow summary. Returns an alert dict when the target crosses threshold."""
        now = time.time() if now is None else now
        target = (flow.get("dst_ip"), flow.get("dst_port"))
        conn_key = (flow.get("src_ip"), flow.get("src_port"), target[0], target[1])
        conns = self._slow_conns[target]

        if self._is_slow(flow):
            conns[conn_key] = now
        else:
            conns.pop(conn_key, None)

        cutoff = now - self.cfg.window_sec
        for stale in [k for k, seen in conns.items() if seen < cutoff]:
            del conns[stale]

        count = len(conns)
        if count >= self.cfg.concurrent_threshold:
            return {
                "alert": "LOW_AND_SLOW",
                "attack_hint": "Slowloris/RUDY",
                "dst_ip": target[0],
                "dst_port": target[1],
                "concurrent_slow_connections": count,
                "severity": "HIGH",
            }
        return None

    def active_slow_count(self, dst_ip, dst_port) -> int:
        return len(self._slow_conns.get((dst_ip, dst_port), {}))
