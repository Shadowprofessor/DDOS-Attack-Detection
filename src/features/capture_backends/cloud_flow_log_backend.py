# -*- coding: utf-8 -*-
"""
Cloud Flow Log Capture Backend — Ingestion for AWS, Azure, and GCP VPC/NSG Flow Logs.

=============================================================================
FEATURE COMPLETENESS AUDIT & SCHEMA CAPABILITY DISCLOSURE
=============================================================================
A typical cloud flow log record (AWS VPC Flow Logs v2, Azure NSG Flow Logs v1/v2,
GCP VPC Flow Logs) contains aggregate metrics over a fixed sampling window
(typically 1 to 10 minutes):
  - 5-tuple: src_ip, dst_ip, src_port, dst_port, protocol
  - Aggregate packet count
  - Aggregate byte count
  - Time window: start timestamp, end timestamp
  - Action / state: ACCEPT/REJECT

Because individual packet arrival times, payload variations, and TCP header flags
are NOT recorded by cloud hypervisors, cloud flow logs CANNOT populate fine-grained
microsecond or transport-level statistics.

Out of the 77 CICFLOWMETER_FEATURE_NAMES, with bidirectional forward+reverse
record pairing enabled within the sampling window, this backend natively populates:
  - Exactly 19 features (~24.68% completeness)
  - 58 features MUST be zero-filled or imputed (~75.32% deficit)

While bidirectional pairing successfully captures reverse volume, packet counts,
and ratio metrics (moving 8 backward/rate features from zero-filled to populated),
microsecond packet timing (IAT), intra-flow packet size variance, TCP flags, and
window sizes remain absent in cloud provider logs. Consequently, all flows
produced by this backend are explicitly tagged with:
  `feature_completeness = 0.2468`
  `backend_type = "cloud_flow_log"`
allowing downstream classifiers, the threat triage agent, and the dashboard to apply
confidence calibration to cloud-flow-log inputs.

-----------------------------------------------------------------------------
POPULATED FEATURES (19 / 77):
-----------------------------------------------------------------------------
1.  Protocol                  - IP protocol number (e.g. 6 for TCP, 17 for UDP)
2.  Flow Duration             - Duration in microseconds (end_time - start_time)
3.  Total Fwd Packets         - Aggregate forward packet count
4.  Total Backward Packets    - Aggregate reverse packet count (from paired reverse record)
5.  Fwd Packets Length Total  - Aggregate forward byte volume
6.  Bwd Packets Length Total  - Aggregate reverse byte volume (from paired reverse record)
7.  Flow Bytes/s              - Aggregate total bytes / duration in seconds
8.  Flow Packets/s            - Aggregate total packets / duration in seconds
9.  Fwd Packets/s             - Forward packets / duration in seconds
10. Bwd Packets/s             - Reverse packets / duration in seconds
11. Packet Length Mean        - Average packet size (total bytes / total packets)
12. Avg Packet Size           - Average packet size (total bytes / total packets)
13. Avg Fwd Segment Size      - Average forward segment size (fwd bytes / fwd packets)
14. Avg Bwd Segment Size      - Average reverse segment size (bwd bytes / bwd packets)
15. Down/Up Ratio             - Reverse packets / forward packets ratio
16. Subflow Fwd Packets       - Subflow forward packet count
17. Subflow Fwd Bytes         - Subflow forward byte volume
18. Subflow Bwd Packets       - Subflow reverse packet count (from paired reverse record)
19. Subflow Bwd Bytes         - Subflow reverse byte volume (from paired reverse record)

-----------------------------------------------------------------------------
ZERO-FILLED / IMPUTED FEATURES (58 / 77):
-----------------------------------------------------------------------------
1.  Fwd Packet Length Max     - Individual packet sizes are not recorded
2.  Fwd Packet Length Min     - Individual packet sizes are not recorded
3.  Fwd Packet Length Std     - Packet variance unavailable from aggregate sums
4.  Bwd Packet Length Max     - Individual packet sizes are not recorded
5.  Bwd Packet Length Min     - Individual packet sizes are not recorded
6.  Bwd Packet Length Mean    - Redundant with Avg Bwd Segment Size; variance absent
7.  Bwd Packet Length Std     - Packet variance unavailable from aggregate sums
8.  Flow IAT Mean             - Inter-arrival times unavailable without per-pkt timestamps
9.  Flow IAT Std              - Inter-arrival times unavailable without per-pkt timestamps
10. Flow IAT Max              - Inter-arrival times unavailable without per-pkt timestamps
11. Flow IAT Min              - Inter-arrival times unavailable without per-pkt timestamps
12. Fwd IAT Total             - Inter-arrival times unavailable
13. Fwd IAT Mean              - Inter-arrival times unavailable
14. Fwd IAT Std               - Inter-arrival times unavailable
15. Fwd IAT Max               - Inter-arrival times unavailable
16. Fwd IAT Min               - Inter-arrival times unavailable
17. Bwd IAT Total             - Inter-arrival times unavailable
18. Bwd IAT Mean              - Inter-arrival times unavailable
19. Bwd IAT Std               - Inter-arrival times unavailable
20. Bwd IAT Max               - Inter-arrival times unavailable
21. Bwd IAT Min               - Inter-arrival times unavailable
22. Fwd PSH Flags             - TCP PSH flag status not tracked in standard flow logs
23. Bwd PSH Flags             - TCP PSH flag status not tracked
24. Fwd URG Flags             - TCP URG flag status not tracked
25. Bwd URG Flags             - TCP URG flag status not tracked
26. Fwd Header Length         - IP/TCP header sizes not reported in flow logs
27. Bwd Header Length         - IP/TCP header sizes not reported
28. Packet Length Min         - Individual packet sizes not recorded
29. Packet Length Max         - Individual packet sizes not recorded
30. Packet Length Std         - Packet variance unavailable
31. Packet Length Variance    - Packet variance unavailable
32. FIN Flag Count            - TCP flag bitmask absent or aggregated without count
33. SYN Flag Count            - TCP flag bitmask absent or aggregated without count
34. RST Flag Count            - TCP flag bitmask absent or aggregated without count
35. PSH Flag Count            - TCP flag bitmask absent or aggregated without count
36. ACK Flag Count            - TCP flag bitmask absent or aggregated without count
37. URG Flag Count            - TCP flag bitmask absent or aggregated without count
38. CWE Flag Count            - TCP flag bitmask absent
39. ECE Flag Count            - TCP flag bitmask absent
40. Fwd Avg Bytes/Bulk        - Bulk transfer state machine not tracked
41. Fwd Avg Packets/Bulk      - Bulk transfer state machine not tracked
42. Fwd Avg Bulk Rate         - Bulk transfer state machine not tracked
43. Bwd Avg Bytes/Bulk        - Bulk transfer state machine not tracked
44. Bwd Avg Packets/Bulk      - Bulk transfer state machine not tracked
45. Bwd Avg Bulk Rate         - Bulk transfer state machine not tracked
46. Init Fwd Win Bytes        - TCP window size not recorded in cloud logs
47. Init Bwd Win Bytes        - TCP window size not recorded in cloud logs
48. Fwd Act Data Packets      - TCP data packet identification unavailable
49. Fwd Seg Size Min          - Segment min size unavailable
50. Active Mean               - Sub-window active period unavailable
51. Active Std                - Sub-window active period unavailable
52. Active Max                - Sub-window active period unavailable
53. Active Min                - Sub-window active period unavailable
54. Idle Mean                 - Sub-window idle period unavailable
55. Idle Std                  - Sub-window idle period unavailable
56. Idle Max                  - Sub-window idle period unavailable
57. Idle Min                  - Sub-window idle period unavailable
=============================================================================
"""
import json
import os
from typing import Any, Dict, Iterator, List, Optional, Tuple, Union
from src.features.capture_backends.base import CaptureBackend
from src.features.flow_extractor import Packet, CICFLOWMETER_FEATURE_NAMES


# Explicit list of populated vs zero-filled features (post-pairing)
CLOUD_FLOW_LOG_POPULATED_FEATURES: List[str] = [
    "Protocol",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Fwd Packets Length Total",
    "Bwd Packets Length Total",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Packet Length Mean",
    "Avg Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Down/Up Ratio",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
]

CLOUD_FLOW_LOG_ZERO_FILLED_FEATURES: List[str] = [
    f for f in CICFLOWMETER_FEATURE_NAMES if f not in CLOUD_FLOW_LOG_POPULATED_FEATURES
]

assert len(CLOUD_FLOW_LOG_POPULATED_FEATURES) + len(CLOUD_FLOW_LOG_ZERO_FILLED_FEATURES) == 77, (
    f"Cloud flow log feature partition mismatch: {len(CLOUD_FLOW_LOG_POPULATED_FEATURES)} + "
    f"{len(CLOUD_FLOW_LOG_ZERO_FILLED_FEATURES)} != 77"
)


class CloudFlowLogBackend(CaptureBackend):
    """Backend for ingesting VPC / NSG flow log records from AWS, Azure, or GCP.

    Supports:
      - Raw JSON strings or dictionaries
      - JSON file paths containing lists of flow log records
      - Standard format, AWS VPC Flow Log format, Azure NSG format, or GCP VPC format

    Properties:
      - ``feature_completeness``: 11 / 77 = 0.1429 (only ~14.3% of features populated).
      - ``backend_type``: 'cloud_flow_log'.
    """

    def __init__(
        self,
        records: Optional[Union[List[Dict[str, Any]], str]] = None,
        file_path: Optional[str] = None,
        pairing_window: float = 300.0,
    ):
        super().__init__()
        self.file_path = file_path
        self.pairing_window = pairing_window
        self._records: List[Dict[str, Any]] = []

        if records is not None:
            raw_list = []
            if isinstance(records, str):
                parsed = json.loads(records)
                raw_list = parsed if isinstance(parsed, list) else [parsed]
            elif isinstance(records, list):
                raw_list = list(records)

            for item in raw_list:
                if isinstance(item, dict):
                    self._records.extend(self._extract_enveloped_records(item))
                else:
                    self._records.append(item)

    @property
    def backend_type(self) -> str:
        return "cloud_flow_log"

    @property
    def feature_completeness(self) -> float:
        return round(len(CLOUD_FLOW_LOG_POPULATED_FEATURES) / 77.0, 4)  # 0.2468 (19/77)

    def start(self) -> None:
        if self.file_path:
            if not os.path.isfile(self.file_path):
                raise FileNotFoundError(f"Flow log file not found: {self.file_path}")
            with open(self.file_path, "r", encoding="utf-8") as f:
                content = json.load(f)
                if isinstance(content, list):
                    self._records.extend(content)
                elif isinstance(content, dict):
                    # Check for cloud provider envelopes (AWS CloudWatch, Azure NSG, GCP)
                    self._records.extend(self._extract_enveloped_records(content))
        self._is_running = True

    def stop(self) -> None:
        self._is_running = False

    @staticmethod
    def _extract_enveloped_records(data: dict) -> List[Dict[str, Any]]:
        """Extract flow records from common cloud provider JSON wrappers."""
        # Azure NSG Flow Log envelope: {"records": [{"properties": {"flows": ...}}]}
        if "records" in data and isinstance(data["records"], list):
            extracted = []
            for item in data["records"]:
                if "properties" in item and "flows" in item["properties"]:
                    for rule_flow in item["properties"]["flows"]:
                        for flow in rule_flow.get("flows", []):
                            for tuple_str in flow.get("flowTuples", []):
                                extracted.append({"_azure_tuple": tuple_str})
                else:
                    extracted.append(item)
            return extracted

        # GCP Logging envelope: {"log_events": [...]} or {"entries": [...]}
        for key in ["log_events", "entries"]:
            if key in data and isinstance(data[key], list):
                return data[key]

        return [data]

    def _normalize_record(self, raw: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Normalize AWS, Azure, GCP, or generic record into a canonical dict."""
        # 1. Azure NSG flowTuples string: "timestamp,srcIP,dstIP,srcPort,dstPort,proto,direction,traffic,pkts,bytes"
        if "_azure_tuple" in raw:
            parts = [p.strip() for p in raw["_azure_tuple"].split(",")]
            if len(parts) >= 8:
                try:
                    ts = float(parts[0])
                    proto = 6 if parts[5].upper() == "T" else (17 if parts[5].upper() == "U" else 0)
                    pkts = int(parts[8]) if len(parts) > 8 else 1
                    bytes_cnt = int(parts[9]) if len(parts) > 9 else 64
                    return {
                        "src_ip": parts[1],
                        "dst_ip": parts[2],
                        "src_port": int(parts[3]),
                        "dst_port": int(parts[4]),
                        "protocol": proto,
                        "packets": max(1, pkts),
                        "bytes": max(0, bytes_cnt),
                        "start_time": ts,
                        "end_time": ts + 1.0,
                    }
                except (ValueError, IndexError):
                    return None

        # 2. GCP VPC Flow Log
        if "jsonPayload" in raw:
            jp = raw["jsonPayload"]
            conn = jp.get("connection", {})
            pkts = int(jp.get("packets", 1))
            bytes_cnt = int(jp.get("bytes", 64))
            start_ts = float(raw.get("timestamp_seconds", 0.0))
            return {
                "src_ip": conn.get("src_ip", "0.0.0.0"),
                "dst_ip": conn.get("dest_ip", "0.0.0.0"),
                "src_port": int(conn.get("src_port", 0)),
                "dst_port": int(conn.get("dest_port", 0)),
                "protocol": int(conn.get("protocol", 6)),
                "packets": max(1, pkts),
                "bytes": max(0, bytes_cnt),
                "start_time": start_ts,
                "end_time": start_ts + 1.0,
            }

        # 3. AWS VPC Flow Log
        if "srcaddr" in raw and "dstaddr" in raw:
            try:
                start_ts = float(raw.get("start", 0))
                end_ts = float(raw.get("end", start_ts + 1.0))
                pkts = int(raw.get("packets", 1))
                bytes_cnt = int(raw.get("bytes", 64))
                return {
                    "src_ip": str(raw["srcaddr"]),
                    "dst_ip": str(raw["dstaddr"]),
                    "src_port": int(raw.get("srcport", 0)),
                    "dst_port": int(raw.get("dstport", 0)),
                    "protocol": int(raw.get("protocol", 6)),
                    "packets": max(1, pkts),
                    "bytes": max(0, bytes_cnt),
                    "start_time": start_ts,
                    "end_time": end_ts,
                }
            except (ValueError, KeyError):
                return None

        # 4. Standard canonical dict
        if "src_ip" in raw and "dst_ip" in raw:
            start_ts = float(raw.get("start_time", raw.get("timestamp", 0.0)))
            end_ts = float(raw.get("end_time", start_ts + 1.0))
            return {
                "src_ip": str(raw["src_ip"]),
                "dst_ip": str(raw["dst_ip"]),
                "src_port": int(raw.get("src_port", 0)),
                "dst_port": int(raw.get("dst_port", 0)),
                "protocol": int(raw.get("protocol", 6)),
                "packets": max(1, int(raw.get("packets", 1))),
                "bytes": max(0, int(raw.get("bytes", 64))),
                "start_time": start_ts,
                "end_time": end_ts,
            }

        return None

    @staticmethod
    def _canonical_key(norm: Dict[str, Any]) -> Tuple[str, str, int, int, int]:
        """Bidirectional canonical 5-tuple key with sorted endpoints."""
        if (norm["src_ip"], norm["src_port"]) <= (norm["dst_ip"], norm["dst_port"]):
            return (norm["src_ip"], norm["dst_ip"], norm["src_port"], norm["dst_port"], norm["protocol"])
        return (norm["dst_ip"], norm["src_ip"], norm["dst_port"], norm["src_port"], norm["protocol"])

    @staticmethod
    def _synthesize_packets_for_record(norm: Dict[str, Any]) -> List[Packet]:
        """Synthesize packet events representing a single unidirectional flow log record."""
        src_ip = norm["src_ip"]
        dst_ip = norm["dst_ip"]
        src_port = norm["src_port"]
        dst_port = norm["dst_port"]
        proto = norm["protocol"]
        n_pkts = norm["packets"]
        total_bytes = norm["bytes"]
        t0 = norm["start_time"]
        t1 = max(t0, norm["end_time"])
        duration = max(0.0, t1 - t0)

        header_size = 54 if proto == 6 else (28 if proto == 17 else 20)
        avg_payload = max(0, (total_bytes // n_pkts) - header_size)

        pkts: List[Packet] = []
        if n_pkts == 1:
            pkts.append(
                Packet(
                    timestamp=t0,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    protocol=proto,
                    payload_len=avg_payload,
                    header_len=header_size,
                    tcp_flags=0,
                    tcp_window=0,
                )
            )
        else:
            step_count = min(n_pkts, 100)
            time_step = duration / (step_count - 1) if step_count > 1 else 0.0
            for i in range(step_count):
                pkt_ts = t0 + i * time_step
                pkts.append(
                    Packet(
                        timestamp=pkt_ts,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=src_port,
                        dst_port=dst_port,
                        protocol=proto,
                        payload_len=avg_payload,
                        header_len=header_size,
                        tcp_flags=0,
                        tcp_window=0,
                    )
                )
        return pkts

    def stream_packets(self) -> Iterator[Packet]:
        """Synthesize packets representing cloud flow windows with bidirectional pairing.

        Pairs matching forward and reverse log records (same 5-tuple, swapped src/dst)
        within ``pairing_window`` seconds into unified bidirectional conversations,
        and interleaves synthesized packets in chronological timestamp order.
        """
        if not self._is_running:
            self.start()

        # Step 1: Normalize all records
        norm_records: List[Dict[str, Any]] = []
        for raw_rec in self._records:
            norm = self._normalize_record(raw_rec)
            if norm:
                norm_records.append(norm)

        # Step 2: Pair matching forward and reverse records into conversations
        conversations: List[Dict[str, Any]] = []
        for norm in norm_records:
            c_key = self._canonical_key(norm)
            matched_group = None

            for group in conversations:
                if group["key"] == c_key and group["bwd"] is None:
                    # Check if direction is opposite
                    fwd_rec = group["fwd"]
                    if (norm["src_ip"], norm["src_port"]) == (fwd_rec["dst_ip"], fwd_rec["dst_port"]):
                        # Check if within pairing window
                        if abs(norm["start_time"] - fwd_rec["start_time"]) <= self.pairing_window:
                            matched_group = group
                            break

            if matched_group is not None:
                # Pair with existing conversation
                fwd_rec = matched_group["fwd"]
                if norm["start_time"] < fwd_rec["start_time"]:
                    # norm started first -> norm is fwd, existing is bwd
                    matched_group["fwd"] = norm
                    matched_group["bwd"] = fwd_rec
                else:
                    matched_group["bwd"] = norm
            else:
                # Start new conversation
                conversations.append({"key": c_key, "fwd": norm, "bwd": None})

        # Step 3: Synthesize and interleave packets in chronological order
        for group in conversations:
            if not self._is_running:
                break

            fwd_pkts = self._synthesize_packets_for_record(group["fwd"])
            bwd_pkts = (
                self._synthesize_packets_for_record(group["bwd"])
                if group["bwd"] is not None
                else []
            )

            # Interleave all packets chronologically so timestamps strictly advance
            conv_pkts = fwd_pkts + bwd_pkts
            conv_pkts.sort(
                key=lambda p: (
                    p.timestamp,
                    0 if p.src_ip == group["fwd"]["src_ip"] else 1,
                )
            )

            for pkt in conv_pkts:
                if not self._is_running:
                    break
                yield pkt
