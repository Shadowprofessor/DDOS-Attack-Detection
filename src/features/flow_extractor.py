# -*- coding: utf-8 -*-
"""
Flow Feature Extractor — Layer 1 of the DDoS Detection Pipeline.

Extracts bidirectional CICFlowMeter-compatible flow statistics from:
  - Parsed packet streams (live or offline)
  - PCAP files (via scapy)

Output schema: 77 numeric features matching the CICDDoS2019 Kaggle dataset,
enabling direct inference against models trained on that dataset.

Design:
  - Flows are keyed by bidirectional 5-tuple: (src_ip, dst_ip, src_port, dst_port, protocol)
  - A sliding-window active/idle timeout mechanism expires stale flows.
  - Thread-safe: all mutable state is guarded by a Lock.
"""
import math
import time
import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Feature column names in the exact order produced by the CICDDoS2019 dataset
# (77 numeric features — excludes the 'Label' target column)
# ---------------------------------------------------------------------------
CICFLOWMETER_FEATURE_NAMES: List[str] = [
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packets Length Total",
    "Bwd Packets Length Total",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Packet Length Min",
    "Packet Length Max",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Avg Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init Fwd Win Bytes",
    "Init Bwd Win Bytes",
    "Fwd Act Data Packets",
    "Fwd Seg Size Min",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

# Number of features expected by the model
NUM_FEATURES = len(CICFLOWMETER_FEATURE_NAMES)  # 77

# TCP flag bit positions
_TCP_FIN = 0x01
_TCP_SYN = 0x02
_TCP_RST = 0x04
_TCP_PSH = 0x08
_TCP_ACK = 0x10
_TCP_URG = 0x20
_TCP_ECE = 0x40
_TCP_CWR = 0x80


def _safe_std(values: List[float]) -> float:
    """Population standard deviation, returns 0 for empty/single-element lists."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return math.sqrt(sum((x - mean) ** 2 for x in values) / n)


def _safe_mean(values: List[float]) -> float:
    """Mean, returns 0 for empty lists."""
    if not values:
        return 0.0
    return sum(values) / len(values)


# ---------------------------------------------------------------------------
# Packet — lightweight representation of a parsed network packet
# ---------------------------------------------------------------------------
@dataclass
class Packet:
    """Minimal packet representation for flow extraction.

    Attributes:
        timestamp: Epoch timestamp in seconds (float, microsecond precision OK).
        src_ip: Source IP address string (e.g. '192.168.1.1').
        dst_ip: Destination IP address string.
        src_port: Source port (0 for ICMP).
        dst_port: Destination port (0 for ICMP).
        protocol: IP protocol number (6=TCP, 17=UDP, 1=ICMP, etc.).
        payload_len: Length of the transport-layer payload in bytes.
        header_len: Length of the IP + transport header in bytes.
        tcp_flags: Integer bitmask of TCP flags (0 for non-TCP).
        tcp_window: TCP window size from the header (0 for non-TCP).
    """
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: int
    payload_len: int
    header_len: int = 0
    tcp_flags: int = 0
    tcp_window: int = 0


# ---------------------------------------------------------------------------
# Flow — accumulates per-direction statistics for a bidirectional flow
# ---------------------------------------------------------------------------
@dataclass
class Flow:
    """Bidirectional network flow accumulating CICFlowMeter-compatible statistics.

    Attributes:
        flow_key: Canonical (sorted) 5-tuple identifying this flow.
        start_time: Epoch time of the first packet in this flow.
        last_active_time: Epoch time of the most recent packet.
        fwd_src_ip: Source IP of the forward direction (the side that sent first).
    """

    flow_key: Tuple[str, str, int, int, int]
    start_time: float
    last_active_time: float
    fwd_src_ip: str

    # Protocol number
    protocol: int = 0

    # Per-direction packet counts
    fwd_packet_count: int = 0
    bwd_packet_count: int = 0

    # Per-direction payload lengths
    fwd_payload_lengths: List[float] = field(default_factory=list)
    bwd_payload_lengths: List[float] = field(default_factory=list)

    # Per-direction header lengths (cumulative)
    fwd_header_length: int = 0
    bwd_header_length: int = 0

    # Inter-arrival times (direction-specific)
    fwd_iats: List[float] = field(default_factory=list)
    bwd_iats: List[float] = field(default_factory=list)
    flow_iats: List[float] = field(default_factory=list)

    # Timestamps for IAT calculation (last packet time per direction)
    _last_fwd_time: Optional[float] = None
    _last_bwd_time: Optional[float] = None
    _last_pkt_time: Optional[float] = None

    # TCP flag counters (bidirectional)
    fin_count: int = 0
    syn_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    ack_count: int = 0
    urg_count: int = 0
    cwe_count: int = 0
    ece_count: int = 0

    # Per-direction flag counters
    fwd_psh_flags: int = 0
    bwd_psh_flags: int = 0
    fwd_urg_flags: int = 0
    bwd_urg_flags: int = 0

    # TCP window sizes (initial, forward and backward)
    init_fwd_win_bytes: int = -1
    init_bwd_win_bytes: int = -1

    # Forward data packets (non-zero payload)
    fwd_act_data_packets: int = 0

    # Minimum segment size forward
    fwd_seg_size_min: int = 0

    # Bulk transfer tracking (forward)
    _fwd_bulk_count: int = 0
    _fwd_bulk_total_bytes: int = 0
    _fwd_bulk_total_packets: int = 0
    _fwd_bulk_duration: float = 0.0
    _fwd_bulk_last_ts: float = 0.0
    _fwd_bulk_start_ts: float = 0.0
    _fwd_bulk_packet_count_in_bulk: int = 0

    # Bulk transfer tracking (backward)
    _bwd_bulk_count: int = 0
    _bwd_bulk_total_bytes: int = 0
    _bwd_bulk_total_packets: int = 0
    _bwd_bulk_duration: float = 0.0
    _bwd_bulk_last_ts: float = 0.0
    _bwd_bulk_start_ts: float = 0.0
    _bwd_bulk_packet_count_in_bulk: int = 0

    # Active/Idle time tracking
    _active_start: float = 0.0
    _active_times: List[float] = field(default_factory=list)
    _idle_times: List[float] = field(default_factory=list)

    # Subflow tracking
    _subflow_count: int = 1

    # Backend provenance & completeness tracking
    backend_type: str = "libpcap"
    feature_completeness: float = 1.0
    source_mode: Optional[str] = None

    # Threshold for bulk detection (seconds)
    _BULK_THRESHOLD: float = field(default=1.0, repr=False)
    # Threshold for active/idle (seconds)
    _ACTIVE_TIMEOUT: float = field(default=5.0, repr=False)

    def add_packet(self, pkt: Packet) -> None:
        """Add a parsed packet to this flow, updating all running statistics."""
        is_forward = (pkt.src_ip == self.fwd_src_ip)
        ts = pkt.timestamp

        # --- Flow-level IAT ---
        if self._last_pkt_time is not None:
            flow_iat = (ts - self._last_pkt_time) * 1e6  # microseconds
            self.flow_iats.append(flow_iat)

            # Active/idle tracking
            gap = ts - self._last_pkt_time
            if gap > self._ACTIVE_TIMEOUT:
                # End of active period, start of idle period
                if self._active_start > 0:
                    active_dur = (self._last_pkt_time - self._active_start) * 1e6
                    if active_dur > 0:
                        self._active_times.append(active_dur)
                self._idle_times.append(gap * 1e6)
                self._active_start = ts
                self._subflow_count += 1
            elif self._active_start == 0:
                self._active_start = ts
        else:
            self._active_start = ts
        self._last_pkt_time = ts
        self.last_active_time = ts

        # --- TCP flags ---
        if pkt.tcp_flags:
            if pkt.tcp_flags & _TCP_FIN:
                self.fin_count += 1
            if pkt.tcp_flags & _TCP_SYN:
                self.syn_count += 1
            if pkt.tcp_flags & _TCP_RST:
                self.rst_count += 1
            if pkt.tcp_flags & _TCP_PSH:
                self.psh_count += 1
            if pkt.tcp_flags & _TCP_ACK:
                self.ack_count += 1
            if pkt.tcp_flags & _TCP_URG:
                self.urg_count += 1
            if pkt.tcp_flags & _TCP_ECE:
                self.ece_count += 1
            if pkt.tcp_flags & _TCP_CWR:
                self.cwe_count += 1

        # --- Direction-specific stats ---
        if is_forward:
            self.fwd_packet_count += 1
            self.fwd_payload_lengths.append(float(pkt.payload_len))
            self.fwd_header_length += pkt.header_len

            if pkt.payload_len > 0:
                self.fwd_act_data_packets += 1
                if self.fwd_seg_size_min == 0 or pkt.payload_len < self.fwd_seg_size_min:
                    self.fwd_seg_size_min = pkt.payload_len

            if pkt.tcp_flags & _TCP_PSH:
                self.fwd_psh_flags += 1
            if pkt.tcp_flags & _TCP_URG:
                self.fwd_urg_flags += 1

            if self.init_fwd_win_bytes == -1:
                self.init_fwd_win_bytes = pkt.tcp_window

            # Forward IAT
            if self._last_fwd_time is not None:
                self.fwd_iats.append((ts - self._last_fwd_time) * 1e6)
            self._last_fwd_time = ts

            # Forward bulk tracking
            self._update_bulk_fwd(ts, pkt.payload_len)

        else:  # backward
            self.bwd_packet_count += 1
            self.bwd_payload_lengths.append(float(pkt.payload_len))
            self.bwd_header_length += pkt.header_len

            if pkt.tcp_flags & _TCP_PSH:
                self.bwd_psh_flags += 1
            if pkt.tcp_flags & _TCP_URG:
                self.bwd_urg_flags += 1

            if self.init_bwd_win_bytes == -1:
                self.init_bwd_win_bytes = pkt.tcp_window

            # Backward IAT
            if self._last_bwd_time is not None:
                self.bwd_iats.append((ts - self._last_bwd_time) * 1e6)
            self._last_bwd_time = ts

            # Backward bulk tracking
            self._update_bulk_bwd(ts, pkt.payload_len)

    def _update_bulk_fwd(self, ts: float, payload_len: int) -> None:
        """Track forward bulk transfers (>= 4 consecutive data packets within threshold)."""
        if payload_len <= 0:
            return
        if self._fwd_bulk_last_ts > 0 and (ts - self._fwd_bulk_last_ts) > self._BULK_THRESHOLD:
            # Reset current bulk
            self._fwd_bulk_packet_count_in_bulk = 0
        self._fwd_bulk_packet_count_in_bulk += 1
        if self._fwd_bulk_packet_count_in_bulk == 4:
            self._fwd_bulk_count += 1
            self._fwd_bulk_start_ts = ts
        if self._fwd_bulk_packet_count_in_bulk >= 4:
            self._fwd_bulk_total_bytes += payload_len
            self._fwd_bulk_total_packets += 1
            self._fwd_bulk_duration += ts - (self._fwd_bulk_last_ts if self._fwd_bulk_last_ts else ts)
        self._fwd_bulk_last_ts = ts

    def _update_bulk_bwd(self, ts: float, payload_len: int) -> None:
        """Track backward bulk transfers."""
        if payload_len <= 0:
            return
        if self._bwd_bulk_last_ts > 0 and (ts - self._bwd_bulk_last_ts) > self._BULK_THRESHOLD:
            self._bwd_bulk_packet_count_in_bulk = 0
        self._bwd_bulk_packet_count_in_bulk += 1
        if self._bwd_bulk_packet_count_in_bulk == 4:
            self._bwd_bulk_count += 1
            self._bwd_bulk_start_ts = ts
        if self._bwd_bulk_packet_count_in_bulk >= 4:
            self._bwd_bulk_total_bytes += payload_len
            self._bwd_bulk_total_packets += 1
            self._bwd_bulk_duration += ts - (self._bwd_bulk_last_ts if self._bwd_bulk_last_ts else ts)
        self._bwd_bulk_last_ts = ts

    def to_feature_vector(self) -> List[float]:
        """Export the flow's accumulated statistics as a 77-element feature vector.

        The order matches CICFLOWMETER_FEATURE_NAMES exactly, so the output
        can be fed directly to models trained on CICDDoS2019.
        """
        total_packets = self.fwd_packet_count + self.bwd_packet_count
        duration_us = (self.last_active_time - self.start_time) * 1e6  # microseconds
        if duration_us < 0:
            duration_us = 0.0
        duration_s = duration_us / 1e6

        fwd_total_bytes = sum(self.fwd_payload_lengths) if self.fwd_payload_lengths else 0.0
        bwd_total_bytes = sum(self.bwd_payload_lengths) if self.bwd_payload_lengths else 0.0
        total_bytes = fwd_total_bytes + bwd_total_bytes

        all_lengths = self.fwd_payload_lengths + self.bwd_payload_lengths

        # Rates
        flow_bytes_per_s = total_bytes / duration_s if duration_s > 0 else 0.0
        flow_pkts_per_s = total_packets / duration_s if duration_s > 0 else 0.0
        fwd_pkts_per_s = self.fwd_packet_count / duration_s if duration_s > 0 else 0.0
        bwd_pkts_per_s = self.bwd_packet_count / duration_s if duration_s > 0 else 0.0

        # Down/Up Ratio
        down_up = (self.bwd_packet_count / self.fwd_packet_count
                   if self.fwd_packet_count > 0 else 0.0)

        # Avg Packet Size
        avg_pkt_size = total_bytes / total_packets if total_packets > 0 else 0.0

        # Avg Fwd/Bwd Segment Size (same as payload mean per direction)
        avg_fwd_seg = _safe_mean(self.fwd_payload_lengths)
        avg_bwd_seg = _safe_mean(self.bwd_payload_lengths)

        # Bulk averages
        fwd_avg_bytes_bulk = (self._fwd_bulk_total_bytes / self._fwd_bulk_count
                              if self._fwd_bulk_count > 0 else 0.0)
        fwd_avg_pkts_bulk = (self._fwd_bulk_total_packets / self._fwd_bulk_count
                             if self._fwd_bulk_count > 0 else 0.0)
        fwd_avg_bulk_rate = (self._fwd_bulk_total_bytes / self._fwd_bulk_duration
                             if self._fwd_bulk_duration > 0 else 0.0)
        bwd_avg_bytes_bulk = (self._bwd_bulk_total_bytes / self._bwd_bulk_count
                              if self._bwd_bulk_count > 0 else 0.0)
        bwd_avg_pkts_bulk = (self._bwd_bulk_total_packets / self._bwd_bulk_count
                             if self._bwd_bulk_count > 0 else 0.0)
        bwd_avg_bulk_rate = (self._bwd_bulk_total_bytes / self._bwd_bulk_duration
                             if self._bwd_bulk_duration > 0 else 0.0)

        # Subflow stats
        subflow_fwd_pkts = self.fwd_packet_count / self._subflow_count
        subflow_fwd_bytes = fwd_total_bytes / self._subflow_count
        subflow_bwd_pkts = self.bwd_packet_count / self._subflow_count
        subflow_bwd_bytes = bwd_total_bytes / self._subflow_count

        # Finalize active/idle (close any open active period)
        active_times = list(self._active_times)
        if self._active_start > 0 and self._last_pkt_time and self._last_pkt_time > self._active_start:
            active_dur = (self._last_pkt_time - self._active_start) * 1e6
            if active_dur > 0:
                active_times.append(active_dur)

        idle_times = list(self._idle_times)

        # Init window sizes: -1 means "not set" — use 0 for the feature
        init_fwd_win = max(self.init_fwd_win_bytes, 0)
        init_bwd_win = max(self.init_bwd_win_bytes, 0)

        # Packet length variance
        pkt_len_std = _safe_std(all_lengths)

        return [
            float(self.protocol),                                # Protocol
            duration_us,                                         # Flow Duration
            float(self.fwd_packet_count),                        # Total Fwd Packets
            float(self.bwd_packet_count),                        # Total Backward Packets
            fwd_total_bytes,                                     # Fwd Packets Length Total
            bwd_total_bytes,                                     # Bwd Packets Length Total
            max(self.fwd_payload_lengths) if self.fwd_payload_lengths else 0.0,  # Fwd Packet Length Max
            min(self.fwd_payload_lengths) if self.fwd_payload_lengths else 0.0,  # Fwd Packet Length Min
            avg_fwd_seg,                                         # Fwd Packet Length Mean
            _safe_std(self.fwd_payload_lengths),                 # Fwd Packet Length Std
            max(self.bwd_payload_lengths) if self.bwd_payload_lengths else 0.0,  # Bwd Packet Length Max
            min(self.bwd_payload_lengths) if self.bwd_payload_lengths else 0.0,  # Bwd Packet Length Min
            avg_bwd_seg,                                         # Bwd Packet Length Mean
            _safe_std(self.bwd_payload_lengths),                 # Bwd Packet Length Std
            flow_bytes_per_s,                                    # Flow Bytes/s
            flow_pkts_per_s,                                     # Flow Packets/s
            _safe_mean(self.flow_iats),                          # Flow IAT Mean
            _safe_std(self.flow_iats),                           # Flow IAT Std
            max(self.flow_iats) if self.flow_iats else 0.0,      # Flow IAT Max
            min(self.flow_iats) if self.flow_iats else 0.0,      # Flow IAT Min
            sum(self.fwd_iats) if self.fwd_iats else 0.0,        # Fwd IAT Total
            _safe_mean(self.fwd_iats),                           # Fwd IAT Mean
            _safe_std(self.fwd_iats),                            # Fwd IAT Std
            max(self.fwd_iats) if self.fwd_iats else 0.0,        # Fwd IAT Max
            min(self.fwd_iats) if self.fwd_iats else 0.0,        # Fwd IAT Min
            sum(self.bwd_iats) if self.bwd_iats else 0.0,        # Bwd IAT Total
            _safe_mean(self.bwd_iats),                           # Bwd IAT Mean
            _safe_std(self.bwd_iats),                            # Bwd IAT Std
            max(self.bwd_iats) if self.bwd_iats else 0.0,        # Bwd IAT Max
            min(self.bwd_iats) if self.bwd_iats else 0.0,        # Bwd IAT Min
            float(self.fwd_psh_flags),                           # Fwd PSH Flags
            float(self.bwd_psh_flags),                           # Bwd PSH Flags
            float(self.fwd_urg_flags),                           # Fwd URG Flags
            float(self.bwd_urg_flags),                           # Bwd URG Flags
            float(self.fwd_header_length),                       # Fwd Header Length
            float(self.bwd_header_length),                       # Bwd Header Length
            fwd_pkts_per_s,                                      # Fwd Packets/s
            bwd_pkts_per_s,                                      # Bwd Packets/s
            min(all_lengths) if all_lengths else 0.0,             # Packet Length Min
            max(all_lengths) if all_lengths else 0.0,             # Packet Length Max
            _safe_mean(all_lengths),                             # Packet Length Mean
            pkt_len_std,                                         # Packet Length Std
            pkt_len_std ** 2,                                    # Packet Length Variance
            float(self.fin_count),                               # FIN Flag Count
            float(self.syn_count),                               # SYN Flag Count
            float(self.rst_count),                               # RST Flag Count
            float(self.psh_count),                               # PSH Flag Count
            float(self.ack_count),                               # ACK Flag Count
            float(self.urg_count),                               # URG Flag Count
            float(self.cwe_count),                               # CWE Flag Count
            float(self.ece_count),                               # ECE Flag Count
            down_up,                                             # Down/Up Ratio
            avg_pkt_size,                                        # Avg Packet Size
            avg_fwd_seg,                                         # Avg Fwd Segment Size
            avg_bwd_seg,                                         # Avg Bwd Segment Size
            fwd_avg_bytes_bulk,                                  # Fwd Avg Bytes/Bulk
            fwd_avg_pkts_bulk,                                   # Fwd Avg Packets/Bulk
            fwd_avg_bulk_rate,                                   # Fwd Avg Bulk Rate
            bwd_avg_bytes_bulk,                                  # Bwd Avg Bytes/Bulk
            bwd_avg_pkts_bulk,                                   # Bwd Avg Packets/Bulk
            bwd_avg_bulk_rate,                                   # Bwd Avg Bulk Rate
            subflow_fwd_pkts,                                    # Subflow Fwd Packets
            subflow_fwd_bytes,                                   # Subflow Fwd Bytes
            subflow_bwd_pkts,                                    # Subflow Bwd Packets
            subflow_bwd_bytes,                                   # Subflow Bwd Bytes
            float(init_fwd_win),                                 # Init Fwd Win Bytes
            float(init_bwd_win),                                 # Init Bwd Win Bytes
            float(self.fwd_act_data_packets),                    # Fwd Act Data Packets
            float(self.fwd_seg_size_min),                        # Fwd Seg Size Min
            _safe_mean(active_times),                            # Active Mean
            _safe_std(active_times),                             # Active Std
            max(active_times) if active_times else 0.0,          # Active Max
            min(active_times) if active_times else 0.0,          # Active Min
            _safe_mean(idle_times),                              # Idle Mean
            _safe_std(idle_times),                               # Idle Std
            max(idle_times) if idle_times else 0.0,              # Idle Max
            min(idle_times) if idle_times else 0.0,              # Idle Min
        ]

    def to_feature_dict(self) -> Dict[str, float]:
        """Export as a dict mapping feature name → value."""
        vec = self.to_feature_vector()
        return dict(zip(CICFLOWMETER_FEATURE_NAMES, vec))

    def to_flow_features(self, backend: Optional[Any] = None) -> Dict[str, Any]:
        """Export flow as payload dictionary for FastAPI /score/flow FlowFeatures schema.

        Resolves feature_completeness and source_mode directly from the active
        CaptureBackend instance or flow provenance, bridging Layer 1 telemetry to Layer 2 scoring.
        """
        active_backend = backend
        comp = getattr(active_backend, "feature_completeness", None) if active_backend else None
        if comp is None:
            comp = getattr(self, "feature_completeness", 1.0)

        mode = (
            getattr(active_backend, "deployment_mode", None)
            or getattr(active_backend, "backend_type", None)
            if active_backend
            else None
        )
        if mode is None:
            mode = getattr(self, "source_mode", None) or getattr(self, "backend_type", None)

        return {
            "features": self.to_feature_dict(),
            "feature_completeness": float(comp),
            "source_mode": str(mode) if mode else None,
        }


# ---------------------------------------------------------------------------
# FlowExtractor — manages a table of active flows
# ---------------------------------------------------------------------------
class FlowExtractor:
    """Extracts CICFlowMeter-compatible flow features from a packet stream.

    Args:
        active_timeout: Seconds before an active flow is forcibly expired (default 120).
        idle_timeout: Seconds of inactivity before a flow is expired (default 60).
    """

    def __init__(
        self,
        active_timeout: float = 120.0,
        idle_timeout: float = 60.0,
        backend: Optional[Any] = None,
    ):
        self.active_timeout = active_timeout
        self.idle_timeout = idle_timeout
        self.backend = backend
        self._flows: Dict[Tuple[str, str, int, int, int], Flow] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _make_flow_key(src_ip: str, dst_ip: str,
                       src_port: int, dst_port: int,
                       protocol: int) -> Tuple[str, str, int, int, int]:
        """Create a canonical bidirectional flow key (sorted endpoints)."""
        if (src_ip, src_port) <= (dst_ip, dst_port):
            return (src_ip, dst_ip, src_port, dst_port, protocol)
        return (dst_ip, src_ip, dst_port, src_port, protocol)

    def process_packet(self, pkt: Packet) -> Optional[Flow]:
        """Add a packet to its flow. Returns the Flow if it was just expired, else None.

        Expired flows are those that exceed ``active_timeout`` since their first
        packet or ``idle_timeout`` since their last packet.
        """
        key = self._make_flow_key(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol)
        expired_flow = None

        with self._lock:
            flow = self._flows.get(key)

            if flow is not None:
                age = pkt.timestamp - flow.start_time
                idle = pkt.timestamp - flow.last_active_time

                if age > self.active_timeout or idle > self.idle_timeout:
                    # Expire the old flow and start a new one
                    expired_flow = flow
                    flow = None  # will be re-created below

            if flow is None:
                backend_type = getattr(self.backend, "backend_type", "libpcap") if self.backend else "libpcap"
                completeness = getattr(self.backend, "feature_completeness", 1.0) if self.backend else 1.0
                source_mode = (
                    getattr(self.backend, "deployment_mode", None)
                    or getattr(self.backend, "backend_type", None)
                    if self.backend
                    else "libpcap"
                )
                flow = Flow(
                    flow_key=key,
                    start_time=pkt.timestamp,
                    last_active_time=pkt.timestamp,
                    fwd_src_ip=pkt.src_ip,
                    protocol=pkt.protocol,
                    backend_type=backend_type,
                    feature_completeness=completeness,
                    source_mode=source_mode,
                )
                self._flows[key] = flow

            flow.add_packet(pkt)

        return expired_flow

    def expire_idle_flows(self, now: Optional[float] = None) -> List[Flow]:
        """Sweep and return all flows idle longer than ``idle_timeout``.

        Args:
            now: Current epoch time. Defaults to ``time.time()``.

        Returns:
            List of expired Flow objects (removed from the active table).
        """
        if now is None:
            now = time.time()
        expired = []
        with self._lock:
            keys_to_remove = []
            for key, flow in self._flows.items():
                if now - flow.last_active_time > self.idle_timeout:
                    expired.append(flow)
                    keys_to_remove.append(key)
            for key in keys_to_remove:
                del self._flows[key]
        return expired

    def flush_all(self) -> List[Flow]:
        """Expire and return ALL active flows (e.g. at end of pcap)."""
        with self._lock:
            flows = list(self._flows.values())
            self._flows.clear()
        return flows

    @property
    def active_flow_count(self) -> int:
        """Number of currently tracked flows."""
        with self._lock:
            return len(self._flows)

    # -----------------------------------------------------------------------
    # Convenience: process a scapy PacketList or pcap file
    # -----------------------------------------------------------------------
    def process_pcap(self, pcap_path: str) -> List[Flow]:
        """Parse a PCAP file via scapy and return all completed flows.

        Requires ``scapy`` to be installed (optional dependency).

        Args:
            pcap_path: Path to a .pcap or .pcapng file.

        Returns:
            List of Flow objects (all flushed at EOF).
        """
        try:
            from scapy.all import rdpcap, IP, TCP, UDP  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "scapy is required for PCAP processing. Install it with: pip install scapy"
            ) from exc

        packets = rdpcap(pcap_path)
        completed: List[Flow] = []

        for raw_pkt in packets:
            if not raw_pkt.haslayer(IP):
                continue
            ip = raw_pkt[IP]
            protocol = ip.proto
            payload_len = len(ip.payload.payload) if ip.payload else 0
            header_len = ip.ihl * 4

            src_port = dst_port = 0
            tcp_flags = 0
            tcp_window = 0

            if raw_pkt.haslayer(TCP):
                tcp = raw_pkt[TCP]
                src_port = tcp.sport
                dst_port = tcp.dport
                tcp_flags = int(tcp.flags)
                tcp_window = tcp.window
                header_len += tcp.dataofs * 4
                payload_len = max(0, len(tcp.payload))
            elif raw_pkt.haslayer(UDP):
                udp = raw_pkt[UDP]
                src_port = udp.sport
                dst_port = udp.dport
                header_len += 8  # UDP header is fixed 8 bytes
                payload_len = max(0, len(udp.payload))

            pkt = Packet(
                timestamp=float(raw_pkt.time),
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                payload_len=payload_len,
                header_len=header_len,
                tcp_flags=tcp_flags,
                tcp_window=tcp_window,
            )

            expired = self.process_packet(pkt)
            if expired is not None:
                completed.append(expired)

        # Flush remaining flows
        completed.extend(self.flush_all())
        return completed

    def extract_from_backend(self, backend: Optional[Any] = None) -> List[Flow]:
        """Extract flows by streaming packets from a pluggable CaptureBackend.

        Args:
            backend: Optional CaptureBackend instance. Defaults to self.backend.

        Returns:
            List of completed Flow objects (including flows flushed at EOF).
        """
        active_backend = backend or self.backend
        if active_backend is None:
            raise ValueError("No CaptureBackend provided to extract_from_backend()")

        completed: List[Flow] = []
        b_type = getattr(active_backend, "backend_type", "libpcap")
        b_comp = getattr(active_backend, "feature_completeness", 1.0)
        b_mode = getattr(active_backend, "deployment_mode", None) or b_type

        with active_backend:
            for pkt in active_backend.stream_packets():
                expired = self.process_packet(pkt)
                if expired is not None:
                    expired.backend_type = b_type
                    expired.feature_completeness = b_comp
                    expired.source_mode = b_mode
                    completed.append(expired)

        # Flush remaining active flows at end of stream
        flushed = self.flush_all()
        for f in flushed:
            f.backend_type = b_type
            f.feature_completeness = b_comp
            f.source_mode = b_mode
            completed.append(f)

        return completed

    def to_flow_features(self, flow: Flow) -> Dict[str, Any]:
        """Convert a Flow into an outgoing FlowFeatures payload dictionary using active backend telemetry."""
        return flow.to_flow_features(backend=self.backend)


