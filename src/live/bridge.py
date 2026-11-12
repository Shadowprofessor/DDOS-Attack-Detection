# -*- coding: utf-8 -*-
"""Live bridge (v5.2.0): lab pcaps on disk -> the running platform, through its public API only.

Every `tick_s`:
1. read the new packets from every pcap in the run directory (tcpdump -U writes one per scenario);
2. close 1 s windows -> `POST /api/live/windows` (the server runs L1 on each one);
3. for each newly opened L1 alert -> `POST /api/incidents` with an aggregate, then
   `POST /api/incidents/{id}/analyze` (rule analyst, or Nemotron when the server has a key);
4. score a few live flows -> `POST /score/flow` (L2 + OOD), relay verdicts -> `POST /api/live/flows`;
5. forward new OVS port samples from `<run>/ovs_ports.jsonl` -> `POST /api/live/ovs`.

The bridge never sees scenario labels: ground truth is only joined afterwards by
`scripts/live_mttd.py`. Every request and response time is logged to a JSON-lines file.
"""
from __future__ import annotations

import json
import threading
import logging
import math
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any, Callable, Deque, Dict, List, Optional, Protocol

from src.live.pcap import PcapFormatError, PcapTail
from src.live.stream import LiveFlows, WindowAggregator, with_features

logger = logging.getLogger("live.bridge")
OVS_FIELDS = ("port", "host", "rx_packets", "tx_packets", "rx_bytes", "tx_bytes", "rx_dropped", "tx_dropped")


class Http(Protocol):
    def post(self, path: str, body: Optional[dict] = None) -> tuple:
        """POST JSON; returns (status, json body)."""


class RequestsHttp:
    """Small JSON client. Keys come from the environment (never from the repo)."""

    def __init__(self, base: str, key: str, timeout: float = 5.0):
        import requests

        self.base, self.timeout = base.rstrip("/"), timeout
        self.s = requests.Session()
        self.s.headers.update({"X-API-Key": key, "Content-Type": "application/json"})

    def post(self, path: str, body: Optional[dict] = None) -> tuple:
        try:
            r = self.s.post(self.base + path, data=json.dumps(body or {}), timeout=self.timeout)
        except Exception as e:  # server restarting, timeout: log and carry on
            return 0, {"error": type(e).__name__}
        try:
            return r.status_code, r.json() if r.content else {}
        except ValueError:
            return r.status_code, {}

    def get(self, path: str) -> tuple:
        try:
            r = self.s.get(self.base + path, timeout=self.timeout)
            return r.status_code, r.json() if r.content else {}
        except Exception as e:
            return 0, {"error": type(e).__name__}


def aggregate_from_windows(windows: List[dict], incident_id: str, ml: Optional[dict] = None) -> dict:
    """IncidentAggregate (dict) from the last few 1 s windows of one victim."""
    ws = [w for w in windows if w.get("packets")] or windows[-1:]
    n = max(1, len(ws))
    pk = sum(w["packets"] for w in ws) or 1
    talkers: Dict[str, int] = defaultdict(int)
    ports: Dict[str, int] = defaultdict(int)
    sports: Dict[str, int] = defaultdict(int)
    land = 0
    payload_num, payload_den = 0.0, 0.0
    proto: Dict[str, float] = defaultdict(float)
    flags: Dict[str, float] = defaultdict(float)
    for w in ws:
        for t in w.get("top_talkers", []):
            talkers[t["ip"]] += t["packets"]
        for p in w.get("top_dst_ports", []):
            ports[str(p["port"])] += p["packets"]
        for p in w.get("top_src_ports", []):
            sports[str(p["port"])] += p["packets"]
        land += w.get("land", 0) or 0
        if w.get("tcp_payload") is not None:
            tcp_n = (w.get("proto_mix") or {}).get("tcp", 0.0) * w["packets"]
            payload_num += w["tcp_payload"] * tcp_n
            payload_den += tcp_n
        for k, v in (w.get("proto_mix") or {}).items():
            proto[k] += v * w["packets"]
        tcp_pk = (w.get("proto_mix") or {}).get("tcp", 0.0) * w["packets"]
        for k, v in (w.get("tcp_flags") or {}).items():
            flags[k] += v * tcp_pk
    tcp_total = proto.get("tcp", 0.0) or 1.0
    port_total = sum(ports.values()) or 1
    agg = {
        "incident_id": incident_id, "window_start": ws[0]["start"], "window_seconds": max(1, int(round(n))),
        "pps": sum(w["pps"] for w in ws) / n, "bps": sum(w["bps"] for w in ws) / n,
        "flow_count": 0, "unique_src_ips": max(w.get("unique_src", 0) for w in ws),
        "src_ip_entropy": max(w.get("src_entropy", 0.0) for w in ws),
        "top_src_ips": [{"key": ip, "share": round(min(1.0, c / pk), 4)}
                        for ip, c in sorted(talkers.items(), key=lambda kv: -kv[1])[:10]],
        "dst_ips": [ws[-1]["dst"]],
        "dst_ports": [{"key": p, "share": round(c / port_total, 4)}
                      for p, c in sorted(ports.items(), key=lambda kv: -kv[1])[:10]],
        "protocol_mix": {k: round(v / pk, 4) for k, v in proto.items()},
        "tcp_flag_ratios": {k: round(min(1.0, v / tcp_total), 4) for k, v in flags.items()},
        "packet_size_p50": ws[-1].get("pkt_size", {}).get("p50", 0.0),
        "packet_size_p95": max(w.get("pkt_size", {}).get("p95", 0.0) for w in ws),
        "src_ports": [{"key": p, "share": round(min(1.0, c / pk), 4)}
                      for p, c in sorted(sports.items(), key=lambda kv: -kv[1])[:10]],
        "land_share": round(min(1.0, land / pk), 4),
        "tcp_payload_share": round(payload_num / payload_den, 4) if payload_den else None,
    }
    slow = max((w.get("slow_conns") or 0) for w in ws)
    if slow:
        agg["l7"] = {"http_rps": 0.0, "slow_connections": int(slow)}
    if ml:
        agg["ml"] = ml
    return agg


def _clean(text: str) -> str:
    return "".join(ch for ch in str(text) if ch.isalnum() or ch in " _./()-")[:64]


def _num(v: Any) -> Any:
    return v if not isinstance(v, float) or math.isfinite(v) else 0.0


class Bridge:
    def __init__(self, run_dir: Path, http: Http, sensor: str = "live-bridge", log_path: Optional[Path] = None,
                 flows_per_s: float = 1.5, from_start: bool = False, victims: Optional[set] = None,
                 clock: Callable[[], float] = time.time, export_s: float = 5.0, grace_s: float = 2.0,
                 open_incidents: bool = True, analyze: bool = True, analyze_http: Optional[Http] = None,
                 analyze_async: bool = False):
        self.run_dir, self.http, self.sensor, self.clock = Path(run_dir), http, sensor, clock
        # The L3 analysis can take tens of seconds with an LLM (live2: > 5 s on Lightning). It gets
        # its own client (longer timeout) and, live, its own thread, so the 1 s loop never waits.
        self.analyze_http = analyze_http or http
        self._pool = None
        if analyze_async:
            from concurrent.futures import ThreadPoolExecutor

            self._pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="l3-analyze")
        self._log_lock = threading.Lock()
        self.victims, self.open_incidents, self.analyze = victims, open_incidents, analyze
        self.agg = WindowAggregator(clock=clock, grace_s=grace_s)
        self.flows = LiveFlows(export_s=export_s)
        self.tails: Dict[Path, PcapTail] = {}
        self.ignored: set = set() if from_start else {p for p in self.run_dir.glob("*.pcap")}
        self.recent: Dict[str, Deque[dict]] = defaultdict(lambda: deque(maxlen=10))
        self.incidents: Dict[str, str] = {}  # live episode id -> incident id
        self.ml_latest: Dict[str, dict] = {}
        self.flow_budget, self.flows_per_s = 0.0, flows_per_s
        self.candidates: Deque[dict] = deque(maxlen=2000)
        self.ovs_path, self.ovs_offset = self.run_dir / "ovs_ports.jsonl", 0
        if not from_start and self.ovs_path.exists():
            self.ovs_offset = self.ovs_path.stat().st_size
        self.log_path = Path(log_path) if log_path else self.run_dir / "live_bridge.jsonl"
        self.stats = defaultdict(int)
        self._last_tick = None

    def log(self, event: str, **kw) -> None:
        rec = {"t": self.clock(), "event": event, **kw}
        with self._log_lock, self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")

    # ------------------------------------------------------------------ inputs
    def read_packets(self) -> int:
        n = 0
        for p in sorted(self.run_dir.glob("*.pcap"), key=lambda q: q.stat().st_mtime):
            if p in self.ignored:
                continue
            t = self.tails.get(p)
            if t is None:
                t = self.tails[p] = PcapTail(p)
                self.log("pcap_opened", pcap=p.name)
            try:
                pkts = t.read()
            except PcapFormatError as e:
                self.log("pcap_error", pcap=p.name, error=str(e))
                self.ignored.add(p)
                continue
            for pkt in pkts:
                self.agg.add(pkt)
                for rec in self.flows.add(pkt):
                    self._candidate(rec)
            n += len(pkts)
        self.stats["packets"] += n
        return n

    def _candidate(self, rec: dict) -> None:
        if self.victims is None or rec["dst"] in self.victims:
            self.candidates.append(rec)

    def read_ovs(self) -> List[dict]:
        if not self.ovs_path.exists():
            return []
        with self.ovs_path.open("rb") as fh:
            fh.seek(self.ovs_offset)
            chunk = fh.read()
        end = chunk.rfind(b"\n")
        if end < 0:
            return []  # only a partial line so far
        self.ovs_offset += end + 1
        out = []
        for line in chunk[:end].splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    # ------------------------------------------------------------------ outputs
    def push_windows(self) -> List[dict]:
        ws = [w for w in self.agg.emit() if self.victims is None or w["dst"] in self.victims]
        if ws:  # v5.3.0: low-and-slow needs connection state, which packet windows do not have
            slow = self.flows.slow_counts(self.agg.now())
            for w in ws:
                w["slow_conns"] = slow.get(w["dst"], 0)
        opened: List[dict] = []
        for i in range(0, len(ws), 200):
            batch = ws[i:i + 200]
            t0 = self.clock()
            status, body = self.http.post("/api/live/windows", {"sensor": self.sensor, "windows": batch})
            t1 = self.clock()
            self.stats["windows"] += len(batch)
            self.log("windows_posted", status=status, n=len(batch), sent_at=t0, ack_at=t1,
                     last_window_end=batch[-1]["end"], skew_s=self.agg.skew_s,
                     late_packets=self.agg.late_packets)
            for w in batch:
                self.recent[w["dst"]].append(w)
            if status == 200:
                for ep in body.get("alerts_opened", []):
                    self.log("alert", episode=ep, ack_at=t1)
                    opened.append(ep)
                for ep in body.get("alerts_cleared", []):
                    self.log("alert_cleared", episode=ep)
        for ep in opened:
            self.open_incident(ep)
        return opened

    def open_incident(self, ep: dict) -> Optional[str]:
        if not self.open_incidents:
            return None
        dst = ep["dst"]
        sev = 4 if ep.get("status") == "CRITICAL" else 3
        vector = ep.get("vector") or "rate anomaly"
        agg = aggregate_from_windows(list(self.recent[dst]), incident_id=ep["id"], ml=self.ml_latest.get(dst))
        ex = ep.get("explanation") or {}
        if ex.get("reason"):  # v5.3.0: the live L1 reason travels with the incident (page + PDF)
            agg["alert_history"] = [{"ts": ep["opened_at"], "layer": "L1", "rule": (ex.get("attack_type") or "rate")[:64],
                                     "detail": ex["reason"][:300]}]
        body = {"title": f"[LIVE] L1 {vector} toward {dst} ({ep.get('hint', '')})"[:200], "severity": sev,
                "aggregate": agg, "detected_at": ep["opened_at"], "source_alert_ids": [ep["id"]]}
        t0 = self.clock()
        status, inc = self.http.post("/api/incidents", body)
        self.log("incident_created", status=status, episode_id=ep["id"], dst=dst, sent_at=t0,
                 ack_at=self.clock(), incident_id=inc.get("id"), incident_created_at=inc.get("created_at"))
        if status != 201 or not inc.get("id"):
            return None
        self.incidents[ep["id"]] = inc["id"]
        if self.analyze:
            if self._pool is not None:
                self._pool.submit(self._analyze, inc["id"])
            else:
                self._analyze(inc["id"])
        return inc["id"]

    def _analyze(self, incident_id: str) -> None:
        t0 = self.clock()
        st, res = self.analyze_http.post(f"/api/incidents/{incident_id}/analyze")
        stored = (res.get("analysis") or {}) if isinstance(res, dict) else {}  # {"analysis": {...}, "source": ...}
        analysis = stored.get("analysis") or {}
        self.log("incident_analyzed", status=st, incident_id=incident_id, attack_type=analysis.get("attack_type"),
                 source=stored.get("source"), sent_at=t0, ack_at=self.clock())

    def close(self) -> None:
        """Wait for background analyses to finish (call before reading the log)."""
        if self._pool is not None:
            self._pool.shutdown(wait=True)

    def score_flows(self, dt: float) -> int:
        for rec in self.flows.poll(self.agg.now() if self.agg._latest_pkt else None):
            self._candidate(rec)
        self.flow_budget = min(self.flows_per_s * 3, self.flow_budget + self.flows_per_s * dt)
        sent, relay = 0, []
        while self.candidates and self.flow_budget >= 1.0:
            rec = with_features(self.candidates.pop())  # newest first: what is happening now
            self.flow_budget -= 1.0
            feats = {k: _num(v) for k, v in rec["features"].items()}
            feats.update({"src_ip": rec["src"], "dst_ip": rec["dst"],  # v5.3.0: CICFlowMeter features carry no ports
                          "Source Port": rec["sport"], "Destination Port": rec["dport"]})
            t0 = self.clock()
            status, body = self.http.post("/score/flow", {"features": feats})
            sent += 1
            if status != 200:
                self.log("flow_score_failed", status=status)
                continue
            r = body.get("result", {})
            label = str(r.get("attack_family") or ("Attack" if r.get("is_attack") else "Benign"))[:64]
            ood = (body.get("ood") or {}).get("ood_suspected")
            bd = r.get("per_model_breakdown") or {}
            basis = "multi_layer" if "MULTI_LAYER" in str(bd.get("consensus_tier") or "") else "ml"
            ml_raw = (bd.get("xgboost") or {}).get("label") if isinstance(bd.get("xgboost"), dict) else None
            v = {"src": rec["src"], "dst": rec["dst"], "proto": rec["proto"], "sport": rec["sport"],
                 "dport": rec["dport"], "packets": rec["packets"], "start": rec["start"], "end": rec["end"],
                 "final": rec["final"], "label": _clean(label) or "flow",
                 "is_attack": bool(r.get("is_attack")), "confidence": r.get("confidence"),
                 "ood_suspected": ood, "proposed_action_id": r.get("proposed_action_id"), "basis": basis,
                 "ml_label": _clean(ml_raw) if ml_raw else None}
            relay.append(v)
            if v["is_attack"] and basis == "ml":  # only a real ML verdict goes into the aggregate's `ml`
                self.ml_latest[rec["dst"]] = {"label": v["label"], "confidence": float(r.get("confidence") or 0.0)}
            self.log("flow_scored", sent_at=t0, ack_at=self.clock(), flow_end=rec["end"], dst=rec["dst"],
                     label=v["label"], is_attack=v["is_attack"], ood=ood, basis=basis, ml_label=v["ml_label"], proposed_action_id=v["proposed_action_id"])
        if relay:
            self.http.post("/api/live/flows", {"sensor": self.sensor, "flows": relay})
        self.stats["flows_scored"] += sent
        return sent

    def push_ovs(self) -> int:
        n = 0
        for sample in self.read_ovs():
            ports = [{k: p[k] for k in OVS_FIELDS if k in p} for p in sample.get("ports", []) if isinstance(p, dict)][:64]
            if not ports:
                continue
            body = {"sensor": self.sensor, "switch": str(sample.get("switch", "s1"))[:32],
                    "ts": float(sample.get("ts", 0.0)), "ports": ports}
            status, _ = self.http.post("/api/live/ovs", body)
            self.log("ovs_posted", status=status, ts=body["ts"], ports=len(ports))
            n += 1
        return n

    def tick(self) -> dict:
        now = self.clock()
        dt = 1.0 if self._last_tick is None else max(0.0, now - self._last_tick)
        self._last_tick = now
        pk = self.read_packets()
        opened = self.push_windows()
        scored = self.score_flows(dt)
        ovs = self.push_ovs()
        return {"packets": pk, "alerts": len(opened), "flows_scored": scored, "ovs": ovs}

    def run(self, tick_s: float = 0.5, duration_s: Optional[float] = None) -> None:  # pragma: no cover - loop
        end = None if duration_s is None else self.clock() + duration_s
        self.log("bridge_started", run_dir=str(self.run_dir), sensor=self.sensor)
        while end is None or self.clock() < end:
            t0 = time.monotonic()
            r = self.tick()
            if r["packets"] or r["alerts"]:
                logger.info("tick %s", r)
            time.sleep(max(0.0, tick_s - (time.monotonic() - t0)))
