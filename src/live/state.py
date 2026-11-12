# -*- coding: utf-8 -*-
"""Server-side live state (v5.2.0): L1 on every 1 s window, alert episodes, OVS port rates.

Pure logic with an injectable clock, so it is unit-tested without the web stack. The router in
`src/api/live_router.py` wraps it with auth, validation, metrics and the /ws/live fan-out.

L1 here is the existing `RateThresholdDetector` applied to a whole window per victim (pps, SYN/s,
bps, new connections/s). An *episode* opens on the first window that crosses a threshold and closes
after `clear_after` consecutive normal windows. `opened_at` is the server's wall clock when the
alert was raised: that is what the real-time MTTD measures.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Callable, Deque, Dict, List, Optional

from src.features.threshold_detector import RateThresholdDetector

HISTORY_WINDOWS = 300   # per victim (5 min at 1 s)
SLOW_CONN_THRESHOLD = 20  # same as LowSlowConfig.concurrent_threshold
MAX_VICTIMS = 64
RECENT_EPISODES = 50
RECENT_FLOWS = 200


def traffic_hint(w: dict) -> str:
    """Short description of what dominates the window (shown next to the L1 verdict)."""
    mix, flags = w.get("proto_mix") or {}, w.get("tcp_flags") or {}
    if not mix:
        return "no traffic"
    proto, share = max(mix.items(), key=lambda kv: kv[1])
    text = f"{proto.upper()} {share:.0%}"
    if proto == "tcp" and flags:
        flag, fshare = max(flags.items(), key=lambda kv: kv[1])
        text += f", {flag.upper().replace('_', '-')} {fshare:.0%} of TCP"
    return text


class LiveState:
    def __init__(self, clock: Callable[[], float] = time.time, clear_after: int = 5,
                 detector: Optional[RateThresholdDetector] = None):
        self.clock, self.clear_after = clock, clear_after
        self.l1 = detector or RateThresholdDetector()
        from src.features.anomaly_detector import PerDestinationBaseline

        self.baselines = PerDestinationBaseline(warmup=20)  # per-victim adaptive baseline (EWMA)
        self._lock = threading.Lock()
        self.windows: Dict[str, Deque[dict]] = {}
        self.open: Dict[str, dict] = {}          # dst -> active episode
        self._normal_run: Dict[str, int] = {}
        self.episodes: Deque[dict] = deque(maxlen=RECENT_EPISODES)
        self.flows: Deque[dict] = deque(maxlen=RECENT_FLOWS)
        self.ovs_prev: Dict[str, dict] = {}       # "switch/port" -> last counters
        self.ovs_latest: Dict[str, dict] = {}     # "switch/port" -> latest rates
        self._seq = 0

    # ------------------------------------------------------------------ windows
    def ingest_window(self, w: dict, sensor: str) -> List[dict]:
        """Evaluate one window; returns the events to publish (window + alert open/clear)."""
        now = self.clock()
        r = self.l1.evaluate_rates(w["pps"], w.get("syn_rate", 0.0), w["bps"], w.get("conn_rate", 0.0),
                                   dst_ip=w["dst"])
        l1 = {"status": r.status, "violation": r.is_violation, "rules": r.triggered_rules[:4],
              "vector": r.vector_inference}
        slow = int(w.get("slow_conns") or 0)
        # v5.3.0 flash-crowd guard: a WARNING-level surge (CRITICAL never) is suppressed when the traffic looks
        # like real users (TCP conversations carrying data) or is normal for THIS destination's adaptive baseline.
        base = self.baselines.evaluate(w["dst"], w["pps"], w["bps"]) if self.baselines else None
        mix, flags = w.get("proto_mix") or {}, w.get("tcp_flags") or {}
        payload = w.get("tcp_payload")
        users = (mix.get("tcp", 0) >= 0.6 and payload is not None and payload >= 0.10 and flags.get("syn", 0) <= 0.30)
        normal_here = bool(base and not base["learning"] and not base["is_anomaly"])
        if l1["status"] == "WARNING" and (users or normal_here):
            why = "looks like real users (TCP with data)" if users else                 f"normal for this destination (baseline {base['baseline_metrics']['mean_pps']:.0f} pps)"
            l1.update(violation=False, status="WATCH", rules=[f"WATCH (not alerted): {why}"] + l1["rules"][:3])
        l1["baseline"] = base["baseline_metrics"] if base else None
        if slow >= SLOW_CONN_THRESHOLD:  # v5.3.0: the L1 low-and-slow rule on live connection state
            l1.update(violation=True, status="CRITICAL" if l1["status"] == "CRITICAL" else "WARNING",
                      vector=l1["vector"] or "Low-and-slow (L7)",
                      rules=[f"WARNING: {slow} established HTTP connections open >= 10 s at <= 50 B/s "
                             f">= {SLOW_CONN_THRESHOLD}"] + l1["rules"][:3])
        hint = traffic_hint(w)
        row = {**w, "sensor": sensor, "received_at": now, "l1": l1, "hint": hint}
        events = [{"type": "live.window", "window": row}]
        dst = w["dst"]
        with self._lock:
            if dst not in self.windows:
                if len(self.windows) >= MAX_VICTIMS:  # bounded memory: forget the quietest victim
                    quiet = min(self.windows, key=lambda d: self.windows[d][-1]["received_at"] if self.windows[d] else 0)
                    del self.windows[quiet]
                self.windows[dst] = deque(maxlen=HISTORY_WINDOWS)
            self.windows[dst].append(row)
            ep = self.open.get(dst)
            if l1["violation"]:
                self._normal_run[dst] = 0
                if ep is None:
                    self._seq += 1
                    ep = {"id": f"live-{self._seq}", "dst": dst, "opened_at": now, "window_start": w["start"],
                          "status": l1["status"], "vector": l1["vector"], "rules": l1["rules"], "hint": hint,
                          "peak_pps": w["pps"], "peak_bps": w["bps"], "top_talkers": w.get("top_talkers", [])[:5],
                          "closed_at": None, "sensor": sensor, "explanation": self._explain(row)}
                    self.open[dst] = ep
                    self.episodes.appendleft(ep)
                    events.append({"type": "live.alert", "episode": dict(ep)})
                else:
                    if l1["status"] == "CRITICAL":
                        ep["status"] = "CRITICAL"
                    if w["pps"] > ep["peak_pps"]:
                        ep.update(peak_pps=w["pps"], peak_bps=w["bps"], top_talkers=w.get("top_talkers", [])[:5],
                                  hint=hint, vector=r.vector_inference or ep["vector"], explanation=self._explain(row))
            elif ep is not None:
                self._normal_run[dst] = self._normal_run.get(dst, 0) + 1
                if self._normal_run[dst] >= self.clear_after:
                    ep["closed_at"] = now
                    del self.open[dst]
                    events.append({"type": "live.clear", "episode": dict(ep)})
        return events

    def _explain(self, row: dict) -> Optional[dict]:
        try:
            from src.agent.explain import explain_l1_window

            return explain_l1_window(row, row["l1"], self.l1.crit_pps, self.l1.warn_pps).model_dump()
        except Exception:  # never let an explanation break the live path
            return None

    # ------------------------------------------------------------------ flows (ML verdicts relayed by the sensor)
    def ingest_flow(self, f: dict, sensor: str) -> dict:
        row = {**f, "sensor": sensor, "received_at": self.clock()}
        with self._lock:
            self.flows.appendleft(row)
        return {"type": "live.flow", "flow": row}

    # ------------------------------------------------------------------ OVS port counters
    def ingest_ovs(self, switch: str, ts: float, ports: List[dict]) -> dict:
        rates = []
        with self._lock:
            for p in ports:
                key = f"{switch}/{p['port']}"
                prev = self.ovs_prev.get(key)
                cur = {**p, "ts": ts}
                self.ovs_prev[key] = cur
                rate = {"switch": switch, "port": p["port"], "host": p.get("host"), "ts": ts, "rx_packets": p["rx_packets"],
                        "tx_packets": p["tx_packets"], "rx_dropped": p.get("rx_dropped", 0),
                        "tx_dropped": p.get("tx_dropped", 0), "rx_pps": None, "tx_pps": None,
                        "rx_bps": None, "tx_bps": None}
                if prev is not None and ts > prev["ts"]:
                    dt = ts - prev["ts"]
                    d = {k: cur[k] - prev[k] for k in ("rx_packets", "tx_packets", "rx_bytes", "tx_bytes")}
                    if min(d.values()) >= 0:  # counters reset (switch restarted): skip one sample
                        rate.update(rx_pps=round(d["rx_packets"] / dt, 2), tx_pps=round(d["tx_packets"] / dt, 2),
                                    rx_bps=round(d["rx_bytes"] * 8 / dt, 2), tx_bps=round(d["tx_bytes"] * 8 / dt, 2))
                self.ovs_latest[key] = rate
                rates.append(rate)
        return {"type": "live.ovs", "switch": switch, "ts": ts, "ports": rates}

    # ------------------------------------------------------------------ read side
    def snapshot(self, last: int = 120) -> dict:
        with self._lock:
            return {
                "server_time": self.clock(),
                "victims": {d: list(q)[-last:] for d, q in self.windows.items()},
                "open_alerts": [dict(e) for e in self.open.values()],
                "episodes": [dict(e) for e in self.episodes],
                "flows": list(self.flows)[:50],
                "ovs": sorted(self.ovs_latest.values(), key=lambda r: (r["switch"], str(r["port"]))),
            }

    def reset(self) -> None:
        with self._lock:
            self.windows.clear()
            self.open.clear()
            self._normal_run.clear()
            self.episodes.clear()
            self.flows.clear()
            self.ovs_prev.clear()
            self.ovs_latest.clear()
            from src.features.anomaly_detector import PerDestinationBaseline

            self.baselines = PerDestinationBaseline(warmup=20)
