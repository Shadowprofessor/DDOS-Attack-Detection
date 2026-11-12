# -*- coding: utf-8 -*-
"""Windowed features (every 1 s, per destination) and live flow records with a short export interval.

Windows are keyed by pcap time. While packets keep arriving, a window closes only when the packet
clock passes its end: tcpdump's writes reach Windows over the shared disk in bursts 1-3 s late
(measured in live1), and closing by the wall clock then would send floods as empty windows.
Only when *no packet has arrived for `grace_s` wall seconds* (traffic really stopped) are windows
closed by the wall clock, shifted by the smallest (wall - packet time) gap seen, so a quiet victim
still gets zero-packet windows and the platform sees the attack end. Packets that still arrive for
an already-sent window are counted in `late_packets`, never silently re-binned.

Flows: a long flow (an ICMP flood is 20 flows lasting the whole scenario) is never "finished" while
the attack runs. So every `export_s` seconds each active flow is exported as a *snapshot* and keeps
accumulating. That lets L2/OOD score it during the attack; flow duration keeps growing, which the
low-and-slow rule needs. Flows idle for `idle_s` are exported one last time (final=True).
"""
from __future__ import annotations

import math
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Optional, Set

from src.features.flow_extractor import Flow, FlowExtractor, Packet

PROTO_NAMES = {6: "tcp", 17: "udp", 1: "icmp"}
F_FIN, F_SYN, F_RST, F_PSH, F_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def entropy(counts: Iterable[int]) -> float:
    c = [x for x in counts if x]
    n = sum(c)
    return -sum((x / n) * math.log2(x / n) for x in c) if n else 0.0


def _pct(sorted_vals: List[int], q: float) -> float:
    if not sorted_vals:
        return 0.0
    return float(sorted_vals[min(len(sorted_vals) - 1, int(q * (len(sorted_vals) - 1) + 0.5))])


@dataclass
class _Slot:
    packets: int = 0
    bytes: int = 0
    src: Counter = field(default_factory=Counter)
    proto: Counter = field(default_factory=Counter)
    flags: Counter = field(default_factory=Counter)
    ports: Counter = field(default_factory=Counter)
    sports: Counter = field(default_factory=Counter)
    sizes: List[int] = field(default_factory=list)
    land: int = 0
    tcp_payload: int = 0
    conns: Set[tuple] = field(default_factory=set)


class WindowAggregator:
    """Per-destination 1 s windows. `add()` packets, then `emit()` the windows that have closed."""

    def __init__(self, window_s: float = 1.0, grace_s: float = 2.0, idle_dst_s: float = 30.0,
                 min_packets: int = 1, clock: Callable[[], float] = time.time, top_n: int = 5):
        self.window_s, self.grace_s, self.idle_dst_s = window_s, grace_s, idle_dst_s
        self.min_packets, self.clock, self.top_n = min_packets, clock, top_n
        self._slots: Dict[float, Dict[str, _Slot]] = defaultdict(dict)
        self._last_seen: Dict[str, float] = {}  # dst -> last window start with traffic
        self._closed_until: Optional[float] = None  # every window starting before this is emitted
        self._latest_pkt = 0.0
        self.skew_s: Optional[float] = None  # min(wall - packet ts) observed
        self._last_arrival: Optional[float] = None  # wall time the latest packet was read
        self.late_packets = 0

    def _start(self, ts: float) -> float:
        return math.floor(ts / self.window_s) * self.window_s

    def add(self, pkt: Packet) -> None:
        start = self._start(pkt.timestamp)
        self._last_arrival = self.clock()
        if self._closed_until is not None and start < self._closed_until:
            self.late_packets += 1  # its window was already sent: counted, never re-sent
            return
        s = self._slots[start].setdefault(pkt.dst_ip, _Slot())
        size = pkt.header_len + pkt.payload_len
        s.packets += 1
        s.bytes += size
        s.src[pkt.src_ip] += 1
        s.proto[PROTO_NAMES.get(pkt.protocol, "other")] += 1
        s.sizes.append(size)
        if pkt.dst_port:
            s.ports[pkt.dst_port] += 1
        if pkt.src_port:
            s.sports[pkt.src_port] += 1
        if pkt.src_ip == pkt.dst_ip:
            s.land += 1
        if pkt.protocol == 6:
            if pkt.payload_len > 0:
                s.tcp_payload += 1
            f = pkt.tcp_flags
            if f & F_SYN and not f & F_ACK:
                s.flags["syn"] += 1
                s.conns.add((pkt.src_ip, pkt.src_port))
            if f & F_SYN and f & F_ACK:
                s.flags["synack"] += 1
            if f & F_ACK and not f & (F_SYN | F_RST | F_FIN | F_PSH):
                s.flags["ack_only"] += 1
            if f & F_RST:
                s.flags["rst"] += 1
            if f & F_FIN:
                s.flags["fin"] += 1
            if f & F_PSH:
                s.flags["psh"] += 1
        self._latest_pkt = max(self._latest_pkt, pkt.timestamp)
        gap = self.clock() - pkt.timestamp
        self.skew_s = gap if self.skew_s is None else min(self.skew_s, gap)

    def _window(self, start: float, dst: str, s: _Slot) -> dict:
        w = self.window_s
        tcp = s.proto.get("tcp", 0)
        sizes = sorted(s.sizes)
        return {
            "start": start, "end": start + w, "dst": dst, "packets": s.packets, "bytes": s.bytes,
            "pps": round(s.packets / w, 3), "bps": round(s.bytes * 8 / w, 3),
            "unique_src": len(s.src), "src_entropy": round(entropy(s.src.values()), 4),
            "proto_mix": {k: round(v / s.packets, 4) for k, v in s.proto.items()} if s.packets else {},
            "tcp_flags": {k: round(v / tcp, 4) for k, v in s.flags.items()} if tcp else {},
            "syn_rate": round(s.flags.get("syn", 0) / w, 3), "conn_rate": round(len(s.conns) / w, 3),
            "pkt_size": {"mean": round(sum(sizes) / len(sizes), 1) if sizes else 0.0,
                         "p50": _pct(sizes, 0.5), "p95": _pct(sizes, 0.95), "max": float(sizes[-1]) if sizes else 0.0},
            "top_talkers": [{"ip": ip, "packets": n} for ip, n in s.src.most_common(self.top_n)],
            "top_dst_ports": [{"port": p, "packets": n} for p, n in s.ports.most_common(self.top_n)],
            # v5.3.0 evidence for the L3 rules
            "top_src_ports": [{"port": p, "packets": n} for p, n in s.sports.most_common(self.top_n)],
            "land": s.land,
            "tcp_payload": round(s.tcp_payload / tcp, 4) if tcp else None,
        }

    def _quiet(self) -> bool:
        return self._last_arrival is None or self.clock() - self._last_arrival >= self.grace_s

    def now(self) -> float:
        """Current time on the packet clock: the latest packet while traffic flows; once it has been
        quiet for `grace_s`, the skew-corrected wall clock (if later)."""
        if not self._quiet():
            return self._latest_pkt
        return max(self._latest_pkt, self.clock() - (self.skew_s or 0.0))

    def emit(self) -> List[dict]:
        """Close every window whose end is behind the packet clock (or the wall clock once quiet)."""
        watermark = self._latest_pkt
        if self._quiet():
            watermark = max(watermark, self.clock() - (self.skew_s or 0.0) - self.grace_s)
        if self._latest_pkt == 0.0 and not self._slots:
            return []
        upto = self._start(watermark)  # windows starting before this have ended
        if self._closed_until is None:
            first = min(self._slots) if self._slots else upto
            self._closed_until = first
        out: List[dict] = []
        t = self._closed_until
        while t < upto:
            slot = self._slots.pop(t, {})
            for dst, s in slot.items():
                if s.packets >= self.min_packets:
                    out.append(self._window(t, dst, s))
                    self._last_seen[dst] = t
            for dst, seen in list(self._last_seen.items()):  # zero windows for recently active victims
                if dst in slot:
                    continue
                if t - seen > self.idle_dst_s:
                    del self._last_seen[dst]
                else:
                    out.append(self._window(t, dst, _Slot()))
            t += self.window_s
            if len(out) > 5000:  # after a long stall: skip ahead rather than flood the API
                t = upto
        self._closed_until = t
        for k in [k for k in self._slots if k < t]:
            del self._slots[k]
        return out


def flow_record(fl: Flow, final: bool) -> dict:
    """Same shape as `src.eval.lab_analysis.flows_from_pcap` rows (+ `final`), *without* features:
    computing 77 features for every flow of a SYN flood would stall the sensor. Call
    `with_features()` on the few records that are actually scored."""
    k = fl.flow_key  # endpoints sorted; recover direction from the first packet
    src, sport = fl.fwd_src_ip, fl.fwd_src_port
    dst, dport = (k[1], k[3]) if (k[0], k[2]) == (src, sport) else (k[0], k[2])
    return {"src": src, "dst": dst, "proto": fl.protocol, "sport": int(sport), "dport": int(dport),
            "packets": int(fl.fwd_packet_count + fl.bwd_packet_count), "start": fl.start_time,
            "end": fl.last_active_time, "final": final, "flow": fl}


def with_features(rec: dict) -> dict:
    """Adds the CICFlowMeter feature dict (and refreshes counts for a still-growing flow)."""
    fl = rec["flow"]
    payload = fl.to_flow_features()
    out = {k: v for k, v in rec.items() if k != "flow"}
    out.update(features=payload.get("features", payload), packets=int(fl.fwd_packet_count + fl.bwd_packet_count),
               end=fl.last_active_time)
    return out


class LiveFlows:
    """CICFlowMeter flows with periodic snapshots of active flows (see module docstring)."""

    def __init__(self, export_s: float = 5.0, idle_s: float = 15.0):
        self.export_s, self.idle_s = export_s, idle_s
        # active timeout disabled: long flows are exported as snapshots instead of being split
        self.ex = FlowExtractor(active_timeout=float("inf"), idle_timeout=idle_s)
        self._last_export: Dict[tuple, float] = {}
        self._clock = 0.0

    def add(self, pkt: Packet) -> List[dict]:
        self._clock = max(self._clock, pkt.timestamp)
        done = self.ex.process_packet(pkt)
        if done is None:
            return []
        self._last_export.pop(done.flow_key, None)
        return [flow_record(done, final=True)]

    def poll(self, now: Optional[float] = None) -> List[dict]:
        """Idle flows (final) + snapshots of flows not exported for `export_s` seconds."""
        now = self._clock if now is None else max(now, self._clock)
        out = []
        for fl in self.ex.expire_idle_flows(now):
            self._last_export.pop(fl.flow_key, None)
            out.append(flow_record(fl, final=True))
        for fl in self.ex.active_flows():
            last = self._last_export.get(fl.flow_key, fl.start_time)
            # only flows still growing: a finished 3-packet handshake waits for its idle export
            if now - last >= self.export_s and fl.last_active_time - last >= self.export_s:
                self._last_export[fl.flow_key] = now
                out.append(flow_record(fl, final=False))
        return out

    def slow_counts(self, now: float, min_duration_s: float = 10.0, max_bytes_per_s: float = 50.0,
                    ports=(80, 443)) -> Dict[str, int]:
        """v5.3.0: established (server answered, client sent bytes) HTTP connections that have been open
        >= `min_duration_s` while the client sends <= `max_bytes_per_s`: the low-and-slow signal,
        per victim. Same rule as `LowSlowDetector`, over ALL live flows (not the sampled ones)."""
        out: Dict[str, int] = defaultdict(int)
        for fl in self.ex.active_flows():
            if fl.protocol != 6 or fl.bwd_packet_count <= 0:
                continue
            k = fl.flow_key
            dst, dport = (k[1], k[3]) if (k[0], k[2]) == (fl.fwd_src_ip, fl.fwd_src_port) else (k[0], k[2])
            if dport not in ports or fl.fin_count or fl.rst_count:
                continue  # closed connections are not being held open
            dur = fl.last_active_time - fl.start_time  # active span (as LowSlowDetector's flow duration), not age
            sent = sum(fl.fwd_payload_lengths)
            if dur >= min_duration_s and sent > 0 and sent / dur <= max_bytes_per_s:
                out[dst] += 1
        return dict(out)

    def flush(self) -> List[dict]:
        self._last_export.clear()
        return [flow_record(fl, final=True) for fl in self.ex.flush_all()]
