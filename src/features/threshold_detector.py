# -*- coding: utf-8 -*-
"""
Layer 1 Rate-Based & Volumetric Threshold Detector (Phase H - H6).

Provides deterministic rate-based threshold detection grounded directly in the
observed benign Mininet baseline (data/pcaps/benign.pcap):
  - Benign Baseline Packet Rate: ~2.02 packets/sec
  - Benign Baseline SYN Rate: 0.0 SYN/sec
  - Benign Baseline Byte Rate: ~113.16 Bytes/sec

Thresholds:
  - Warning:  PPS > 100 (~50x benign)   OR SYN/s > 50   OR Conn/s > 20
  - Critical: PPS > 500 (~250x benign)  OR SYN/s > 200  OR Conn/s > 100

Supports both:
  1. Per-IP sliding-window tracking for packet streams.
  2. Direct flow evaluation from FlowExtractor/CICFlowMeter features.
"""

import time
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

# Grounded baseline constants from Mininet benign.pcap (29.69s duration, 60 packets)
BENIGN_BASELINE_PPS: float = 2.02
BENIGN_BASELINE_BPS: float = 113.16
BENIGN_BASELINE_SYN_RATE: float = 0.0

# Rate thresholds
WARN_PPS_THRESHOLD: float = 100.0
WARN_SYN_THRESHOLD: float = 50.0
WARN_CONN_THRESHOLD: float = 20.0

CRIT_PPS_THRESHOLD: float = 500.0
CRIT_SYN_THRESHOLD: float = 200.0
CRIT_CONN_THRESHOLD: float = 100.0


@dataclass
class RateDetectionResult:
    """Outcome of rate-based threshold evaluation."""
    status: str  # "NORMAL", "WARNING", "CRITICAL"
    is_violation: bool
    current_pps: float
    current_syn_rate: float
    current_bps: float
    current_conn_rate: float
    triggered_rules: List[str]
    vector_inference: Optional[str]
    baseline_comparison: Dict[str, Any]
    source_ip: Optional[str] = None
    target_ip: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "is_violation": self.is_violation,
            "current_pps": round(self.current_pps, 2),
            "current_syn_rate": round(self.current_syn_rate, 2),
            "current_bps": round(self.current_bps, 2),
            "current_conn_rate": round(self.current_conn_rate, 2),
            "triggered_rules": self.triggered_rules,
            "vector_inference": self.vector_inference,
            "baseline_comparison": self.baseline_comparison,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
        }


class RateThresholdDetector:
    """
    Deterministic rate-based threshold detector.
    
    Tracks sliding windows of packet events per (src_ip, dst_ip) and provides
    instant evaluation against the empirically measured Mininet baseline.
    """

    def __init__(
        self,
        window_seconds: float = 2.0,
        warn_pps: float = WARN_PPS_THRESHOLD,
        crit_pps: float = CRIT_PPS_THRESHOLD,
        warn_syn_rate: float = WARN_SYN_THRESHOLD,
        crit_syn_rate: float = CRIT_SYN_THRESHOLD,
        warn_conn_rate: float = WARN_CONN_THRESHOLD,
        crit_conn_rate: float = CRIT_CONN_THRESHOLD,
    ):
        self.window_seconds = window_seconds
        self.warn_pps = warn_pps
        self.crit_pps = crit_pps
        self.warn_syn_rate = warn_syn_rate
        self.crit_syn_rate = crit_syn_rate
        self.warn_conn_rate = warn_conn_rate
        self.crit_conn_rate = crit_conn_rate

        self._lock = threading.Lock()
        # IP -> deque of (timestamp, length, is_syn, dst_port)
        self._ip_windows: Dict[str, deque] = {}

    def _cleanup_old_events(self, dq: deque, now: float) -> None:
        cutoff = now - self.window_seconds
        while dq and dq[0][0] < cutoff:
            dq.popleft()

    def record_packet(
        self,
        src_ip: str,
        dst_ip: str,
        pkt_len: int,
        is_syn: bool = False,
        dst_port: Optional[int] = None,
        timestamp: Optional[float] = None,
    ) -> RateDetectionResult:
        """Record an incoming packet and evaluate current sliding window rates."""
        now = timestamp if timestamp is not None else time.time()

        with self._lock:
            if src_ip not in self._ip_windows:
                self._ip_windows[src_ip] = deque()
            dq = self._ip_windows[src_ip]
            dq.append((now, pkt_len, is_syn, dst_port))
            self._cleanup_old_events(dq, now)

            # Compute current metrics over window
            count = len(dq)
            # v5.3.0: rate = events in the window / window length. It used to be divided by the span between
            # the first and last event (min 0.05 s), so two benign flows 50 ms apart read as hundreds of pps.
            dt = self.window_seconds  # Avoid div by 0 for instantaneous bursts

            pps = count / dt
            total_bytes = sum(item[1] for item in dq)
            bps = total_bytes / dt
            syn_count = sum(1 for item in dq if item[2])
            syn_rate = syn_count / dt
            unique_ports = len(set(item[3] for item in dq if item[3] is not None))
            conn_rate = unique_ports / dt

        return self._evaluate_metrics(
            pps=pps,
            syn_rate=syn_rate,
            bps=bps,
            conn_rate=conn_rate,
            src_ip=src_ip,
            dst_ip=dst_ip,
        )

    def record_flow(
        self,
        features: Dict[str, Any],
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        timestamp: Optional[float] = None,
    ) -> RateDetectionResult:
        """
        Record a completed flow's packets into the sliding window and evaluate
        both per-source and aggregate per-destination rate thresholds.
        """
        now = timestamp if timestamp is not None else time.time()
        tot_pkts = int(features.get("Total Fwd Packets", 0) + features.get("Total Backward Packets", 0))
        if tot_pkts <= 0:
            tot_pkts = 1
        tot_bytes = float(features.get("Fwd Packets Length Total", 0.0) + features.get("Bwd Packets Length Total", 0.0))
        syn_count = int(features.get("SYN Flag Count", 0))
        dst_port = features.get("dst_port", features.get("Destination Port", None))

        with self._lock:
            # Track both per-source (DoS) and per-destination (DDoS victim aggregate)
            keys = []
            if src_ip:
                keys.append(src_ip)
            if dst_ip:
                keys.append(f"dst:{dst_ip}")
            keys.append("__global__")

            for k in keys:
                if k not in self._ip_windows:
                    self._ip_windows[k] = deque()
                dq = self._ip_windows[k]
                for i in range(tot_pkts):
                    is_syn = (i < syn_count)
                    dq.append((now, tot_bytes / tot_pkts, is_syn, dst_port))
                self._cleanup_old_events(dq, now)

            # Evaluate the aggregate destination window if available, else source or global
            eval_key = f"dst:{dst_ip}" if dst_ip and f"dst:{dst_ip}" in self._ip_windows else (src_ip if src_ip in self._ip_windows else "__global__")
            dq = self._ip_windows[eval_key]
            count = len(dq)
            # v5.3.0: rate = events in the window / window length. It used to be divided by the span between
            # the first and last event (min 0.05 s), so two benign flows 50 ms apart read as hundreds of pps.
            dt = self.window_seconds

            pps = count / dt
            total_bytes = sum(item[1] for item in dq)
            bps = total_bytes / dt
            syn_c = sum(1 for item in dq if item[2])
            syn_rate = syn_c / dt
            unique_ports = len(set(item[3] for item in dq if item[3] is not None))
            conn_rate = unique_ports / dt

        return self._evaluate_metrics(
            pps=pps,
            syn_rate=syn_rate,
            bps=bps,
            conn_rate=conn_rate,
            src_ip=src_ip,
            dst_ip=dst_ip,
        )

    def evaluate_flow_features(
        self,
        features: Dict[str, Any],
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
    ) -> RateDetectionResult:
        """
        Evaluate a completed flow feature dictionary against rate thresholds.
        Grounded in flow-level statistics (Flow Packets/s, SYN Flag Count, Flow Duration).
        """
        # Flow duration in microseconds in CICFlowMeter schema
        duration_us = float(features.get("Flow Duration", 0.0))
        duration_s = duration_us / 1_000_000.0 if duration_us > 0 else 0.001

        flow_pps = float(features.get("Flow Packets/s", 0.0))
        if flow_pps == 0.0 and duration_s > 0:
            tot_pkts = float(features.get("Total Fwd Packets", 0.0)) + float(features.get("Total Backward Packets", 0.0))
            flow_pps = tot_pkts / duration_s

        flow_bps = float(features.get("Flow Bytes/s", 0.0))
        syn_count = float(features.get("SYN Flag Count", 0.0))
        syn_rate = syn_count / duration_s if duration_s > 0 else syn_count

        # For single flows, conn rate is 1 / duration
        conn_rate = 1.0 / duration_s if duration_s > 0 else 1.0

        return self._evaluate_metrics(
            pps=flow_pps,
            syn_rate=syn_rate,
            bps=flow_bps,
            conn_rate=conn_rate,
            src_ip=src_ip,
            dst_ip=dst_ip,
        )

    def _evaluate_metrics(
        self,
        pps: float,
        syn_rate: float,
        bps: float,
        conn_rate: float,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
    ) -> RateDetectionResult:
        triggered: List[str] = []
        is_crit = False
        is_warn = False

        # 1. Packet rate checks
        if pps >= self.crit_pps:
            triggered.append(f"CRITICAL: Packet Rate {pps:.1f} pps >= {self.crit_pps:.1f} (Benign Baseline: {BENIGN_BASELINE_PPS:.2f} pps, {pps/BENIGN_BASELINE_PPS:.0f}x)")
            is_crit = True
        elif pps >= self.warn_pps:
            triggered.append(f"WARNING: Packet Rate {pps:.1f} pps >= {self.warn_pps:.1f} (Benign Baseline: {BENIGN_BASELINE_PPS:.2f} pps, {pps/BENIGN_BASELINE_PPS:.0f}x)")
            is_warn = True

        # 2. SYN rate checks
        if syn_rate >= self.crit_syn_rate:
            triggered.append(f"CRITICAL: SYN Rate {syn_rate:.1f} syn/s >= {self.crit_syn_rate:.1f} (Benign Baseline: {BENIGN_BASELINE_SYN_RATE:.1f} syn/s)")
            is_crit = True
        elif syn_rate >= self.warn_syn_rate:
            triggered.append(f"WARNING: SYN Rate {syn_rate:.1f} syn/s >= {self.warn_syn_rate:.1f} (Benign Baseline: {BENIGN_BASELINE_SYN_RATE:.1f} syn/s)")
            is_warn = True

        # 3. Connection / port sweep rate checks
        if conn_rate >= self.crit_conn_rate:
            triggered.append(f"CRITICAL: Connection Rate {conn_rate:.1f} conn/s >= {self.crit_conn_rate:.1f}")
            is_crit = True
        elif conn_rate >= self.warn_conn_rate:
            triggered.append(f"WARNING: Connection Rate {conn_rate:.1f} conn/s >= {self.warn_conn_rate:.1f}")
            is_warn = True

        status = "CRITICAL" if is_crit else ("WARNING" if is_warn else "NORMAL")
        is_violation = is_crit or is_warn

        vector = None
        if is_violation:
            if syn_rate >= self.warn_syn_rate:
                vector = "Rate-Based SYN Flood"
            elif conn_rate >= self.warn_conn_rate:
                vector = "Rate-Based Port/Host Sweep"
            else:
                vector = "Rate-Based Volumetric Flood"

        baseline_comp = {
            "benign_baseline_pps": BENIGN_BASELINE_PPS,
            "benign_baseline_bps": BENIGN_BASELINE_BPS,
            "benign_baseline_syn_rate": BENIGN_BASELINE_SYN_RATE,
            "fold_increase_pps": round(pps / BENIGN_BASELINE_PPS, 1) if BENIGN_BASELINE_PPS > 0 else 0.0,
        }

        return RateDetectionResult(
            status=status,
            is_violation=is_violation,
            current_pps=pps,
            current_syn_rate=syn_rate,
            current_bps=bps,
            current_conn_rate=conn_rate,
            triggered_rules=triggered,
            vector_inference=vector,
            baseline_comparison=baseline_comp,
            source_ip=src_ip,
            target_ip=dst_ip,
        )

    def evaluate_rates(self, pps: float, syn_rate: float, bps: float, conn_rate: float,
                       src_ip: Optional[str] = None, dst_ip: Optional[str] = None) -> RateDetectionResult:
        """Stateless check of already-aggregated rates (v5.2.0 live windows) against the thresholds."""
        return self._evaluate_metrics(pps, syn_rate, bps, conn_rate, src_ip=src_ip, dst_ip=dst_ip)

    def reset(self) -> None:
        """Clear all active sliding windows."""
        with self._lock:
            self._ip_windows.clear()


# Public alias matching H6 requirement
ThresholdDetector = RateThresholdDetector

