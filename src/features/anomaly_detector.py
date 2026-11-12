# -*- coding: utf-8 -*-
"""
Layer 1/2 Historical Baseline & Statistical Anomaly Detector (Phase H - H9).

Tracks rolling statistical baselines (EWMA and variance) for:
  - Volumetric metrics: PPS, BPS
  - Protocol mix: TCP, UDP, ICMP proportions
  - Flow dynamics: SYN ratio, Source IP Shannon entropy

Computes Z-scores and multidimensional divergence to flag statistical anomalies
that deviate from learned/grounded network baselines, even when specific signatures
or model thresholds are not triggered.

Grounded Initial Baseline (from Mininet benign.pcap):
  - Mean PPS: 2.02 pps, Std: 1.0
  - Mean BPS: 113.16 B/s, Std: 50.0
  - Normal Protocol Mix: TCP ~80%, UDP ~15%, ICMP ~5%
"""

import math
import os
import time
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger("AnomalyDetector")

# Grounded benign default parameters
DEFAULT_BENIGN_PPS: float = 2.02
DEFAULT_BENIGN_BPS: float = 113.16


@dataclass
class AnomalyEvaluationResult:
    """Outcome of statistical anomaly evaluation."""
    is_anomaly: bool
    anomaly_score: float  # 0.0 to 100.0
    severity: str         # "NORMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    z_scores: Dict[str, float]
    protocol_distribution: Dict[str, float]
    baseline_metrics: Dict[str, float]
    entropy_stats: Dict[str, float]
    anomaly_reasons: List[str]
    analyst_notes: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_anomaly": self.is_anomaly,
            "anomaly_score": round(self.anomaly_score, 1),
            "severity": self.severity,
            "z_scores": {k: round(v, 2) for k, v in self.z_scores.items()},
            "protocol_distribution": {k: round(v, 3) for k, v in self.protocol_distribution.items()},
            "baseline_metrics": {k: round(v, 2) for k, v in self.baseline_metrics.items()},
            "entropy_stats": {k: round(v, 3) for k, v in self.entropy_stats.items()},
            "anomaly_reasons": self.anomaly_reasons,
            "analyst_notes": self.analyst_notes,
        }


def compute_shannon_entropy(frequencies: Dict[str, int]) -> float:
    """Compute Shannon entropy H = -sum(p * log2(p)) for an IP/port distribution."""
    total = sum(frequencies.values())
    if total <= 1:
        return 0.0
    entropy = 0.0
    for count in frequencies.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


class RollingAnomalyDetector:
    """
    Online statistical anomaly detector with Exponential Weighted Moving Average (EWMA).
    """

    def __init__(
        self,
        alpha: float = 0.05,
        z_warn_threshold: float = 3.0,
        z_crit_threshold: float = 5.0,
        initial_mean_pps: float = DEFAULT_BENIGN_PPS,
        initial_std_pps: float = 1.0,
        initial_mean_bps: float = DEFAULT_BENIGN_BPS,
        initial_std_bps: float = 50.0,
        baseline_pcap: Optional[str] = None,
    ):
        self.alpha = alpha
        self.z_warn = z_warn_threshold
        self.z_crit = z_crit_threshold

        # Rolling state
        self.mean_pps = initial_mean_pps
        self.var_pps = initial_std_pps ** 2
        self.mean_bps = initial_mean_bps
        self.var_bps = initial_std_bps ** 2

        # Protocol baseline
        self.proto_mix = {"tcp": 0.80, "udp": 0.15, "icmp": 0.05}
        self.mean_entropy = 2.5
        self.observation_count = 0

        if baseline_pcap and os.path.exists(baseline_pcap):
            self.fit_from_pcap(baseline_pcap)

    @property
    def std_pps(self) -> float:
        return math.sqrt(max(self.var_pps, 0.01))

    @property
    def std_bps(self) -> float:
        return math.sqrt(max(self.var_bps, 1.0))

    def fit_from_pcap(self, pcap_path: str) -> None:
        """
        Calibrate baseline statistics exclusively from a clean Benign PCAP capture.
        Strictly zero attack flows are used.
        """
        if not os.path.exists(pcap_path):
            logger.warning("Benign PCAP %s not found; keeping default baseline.", pcap_path)
            return

        try:
            from scapy.all import rdpcap, IP, TCP, UDP, ICMP
            packets = rdpcap(pcap_path)
            if not packets:
                return

            duration = float(packets[-1].time - packets[0].time) if len(packets) > 1 else 1.0
            duration = max(duration, 0.1)
            total_bytes = sum(len(p) for p in packets)

            observed_pps = len(packets) / duration
            observed_bps = total_bytes / duration

            proto_counts = {"tcp": 0, "udp": 0, "icmp": 0}
            for p in packets:
                if IP in p:
                    if TCP in p:
                        proto_counts["tcp"] += 1
                    elif UDP in p:
                        proto_counts["udp"] += 1
                    elif ICMP in p:
                        proto_counts["icmp"] += 1

            self.mean_pps = observed_pps
            self.var_pps = max(1.0, (observed_pps * 0.2) ** 2)
            self.mean_bps = observed_bps
            self.var_bps = max(25.0, (observed_bps * 0.2) ** 2)

            tot = sum(proto_counts.values())
            if tot > 0:
                for k in ["tcp", "udp", "icmp"]:
                    self.proto_mix[k] = proto_counts[k] / tot
            self.observation_count += len(packets)
            logger.info("Successfully calibrated baseline from clean Benign PCAP: PPS=%.2f, BPS=%.2f, proto=%s",
                        self.mean_pps, self.mean_bps, self.proto_mix)
        except Exception as e:
            logger.warning("Failed to fit baseline from PCAP: %s", e)

    def update_baseline(
        self,
        observed_pps: float,
        observed_bps: float,
        proto_counts: Optional[Dict[str, int]] = None,
    ) -> None:
        """Update rolling EWMA mean and variance using clean baseline observations."""
        self.observation_count += 1
        a = self.alpha

        # Update PPS
        diff_pps = observed_pps - self.mean_pps
        self.mean_pps += a * diff_pps
        self.var_pps = (1 - a) * (self.var_pps + a * (diff_pps ** 2))

        # Update BPS
        diff_bps = observed_bps - self.mean_bps
        self.mean_bps += a * diff_bps
        self.var_bps = (1 - a) * (self.var_bps + a * (diff_bps ** 2))

        # Update protocol mix if provided
        if proto_counts:
            tot = sum(proto_counts.values())
            if tot > 0:
                for k in ["tcp", "udp", "icmp"]:
                    cur_ratio = proto_counts.get(k, 0) / tot
                    self.proto_mix[k] = (1 - a) * self.proto_mix[k] + a * cur_ratio

    def evaluate_traffic(
        self,
        current_pps: float,
        current_bps: float,
        proto_counts: Optional[Dict[str, int]] = None,
        ip_frequencies: Optional[Dict[str, int]] = None,
        generate_ai_notes: bool = True,
    ) -> AnomalyEvaluationResult:
        """
        Evaluate current traffic window against the learned historical baseline.
        """
        reasons = []

        # 1. Z-Score for Packet Rate
        z_pps = (current_pps - self.mean_pps) / self.std_pps
        if z_pps >= self.z_crit:
            reasons.append(f"Critical PPS Surge: {current_pps:.1f} pps is +{z_pps:.1f}σ above baseline (mean={self.mean_pps:.1f})")
        elif z_pps >= self.z_warn:
            reasons.append(f"Warning PPS Surge: {current_pps:.1f} pps is +{z_pps:.1f}σ above baseline (mean={self.mean_pps:.1f})")

        # 2. Z-Score for Byte Rate
        z_bps = (current_bps - self.mean_bps) / self.std_bps
        if z_bps >= self.z_crit:
            reasons.append(f"Critical Bandwidth Surge: {current_bps:.1f} B/s is +{z_bps:.1f}σ above baseline (mean={self.mean_bps:.1f})")

        # 3. Protocol Distribution Skew
        current_mix = {"tcp": 0.0, "udp": 0.0, "icmp": 0.0}
        max_proto_skew = 0.0
        skew_proto = None
        if proto_counts:
            tot = sum(proto_counts.values())
            if tot > 0:
                for k in ["tcp", "udp", "icmp"]:
                    ratio = proto_counts.get(k, 0) / tot
                    current_mix[k] = ratio
                    baseline_ratio = self.proto_mix.get(k, 0.0)
                    skew = abs(ratio - baseline_ratio)
                    if skew > max_proto_skew:
                        max_proto_skew = skew
                        skew_proto = k
                if max_proto_skew > 0.50:
                    reasons.append(
                        f"Protocol Shift: {skew_proto.upper()} comprises {current_mix[skew_proto]*100:.1f}% "
                        f"of traffic (baseline: {self.proto_mix[skew_proto]*100:.1f}%)"
                    )

        # 4. Source IP Entropy Analysis
        current_entropy = 0.0
        entropy_reasons = {}
        if ip_frequencies and len(ip_frequencies) > 0:
            current_entropy = compute_shannon_entropy(ip_frequencies)
            entropy_stats = {
                "current_entropy": current_entropy,
                "unique_ips": len(ip_frequencies),
            }
            if len(ip_frequencies) > 5 and current_entropy < 1.0:
                reasons.append(f"Entropy Collapse: Low IP entropy ({current_entropy:.2f}) indicates focused spoofing")
        else:
            entropy_stats = {"current_entropy": 0.0, "unique_ips": 0}

        # 5. Multidimensional Anomaly Score Calculation (0 - 100)
        # Scaled non-linearly with Z-score saturation
        pps_component = min(60.0, max(0.0, (z_pps / self.z_crit) * 60.0))
        bps_component = min(20.0, max(0.0, (z_bps / self.z_crit) * 20.0))
        proto_component = min(10.0, max_proto_skew * 10.0)
        entropy_component = 10.0 if (len(entropy_stats) > 0 and current_entropy < 1.0 and entropy_stats.get("unique_ips", 0) > 3) else 0.0

        anomaly_score = min(100.0, pps_component + bps_component + proto_component + entropy_component)
        is_anomaly = (anomaly_score >= 50.0) or (z_pps >= self.z_crit)

        if anomaly_score >= 80.0 or z_pps >= (self.z_crit * 2):
            severity = "CRITICAL"
        elif anomaly_score >= 45.0 or z_pps >= self.z_crit:
            severity = "HIGH"
        elif anomaly_score >= 30.0:
            severity = "MEDIUM"
        elif anomaly_score >= 15.0:
            severity = "LOW"
        else:
            severity = "NORMAL"

        z_scores = {"z_pps": z_pps, "z_bps": z_bps, "max_proto_skew": max_proto_skew}
        baselines = {"mean_pps": self.mean_pps, "std_pps": self.std_pps, "mean_bps": self.mean_bps}

        res = AnomalyEvaluationResult(
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
            severity=severity,
            z_scores=z_scores,
            protocol_distribution=current_mix,
            baseline_metrics=baselines,
            entropy_stats=entropy_stats,
            anomaly_reasons=reasons,
        )

        if generate_ai_notes:
            res.analyst_notes = self.generate_anomaly_notes(res)

        return res

    def generate_anomaly_notes(self, evaluation: AnomalyEvaluationResult) -> Dict[str, Any]:
        """
        Generate contextual AI Threat Analyst Notes for statistical anomaly.
        Uses NVIDIA NIM / OpenRouter if configured, otherwise deterministic expert heuristic.
        """
        nim_key = os.environ.get("NVIDIA_API_KEY") or os.environ.get("OPENROUTER_API_KEY")
        if nim_key:
            try:
                from src.agent.nemotron_agent import NemotronAgent
                agent = NemotronAgent()
                prompt = (
                    f"Statistical Anomaly Evaluation Request:\n"
                    f"- Anomaly Score: {evaluation.anomaly_score:.1f}/100 ({evaluation.severity})\n"
                    f"- Volumetric Deviation: PPS Z-Score = +{evaluation.z_scores.get('z_pps', 0):.2f}σ\n"
                    f"- Protocol Skew: {evaluation.protocol_distribution}\n"
                    f"- Triggered Observations: {evaluation.anomaly_reasons}\n"
                    f"Provide a 2-sentence expert blue-team interpretation of whether this anomaly "
                    f"indicates an operational traffic spike vs an active DDoS attack, and advise the operator."
                )
                res, _ = agent._call_nemotron_api(prompt)
                if res and isinstance(res, dict):
                    return {
                        "source": f"Nemotron ({getattr(agent, 'model', 'LLM')})",
                        "assessment": res.get("explanation", "Statistical traffic anomaly detected."),
                        "severity": evaluation.severity,
                        "confidence": "HIGH" if evaluation.anomaly_score > 70 else "MEDIUM",
                        "recommended_mitigation_scope": res.get("proposed_action", "Investigate protocol skew and rate limit anomalous source pool"),
                    }
            except Exception as e:
                logger.debug("Nemotron call failed for anomaly notes: %s", e)

        # Deterministic Expert Blue-Team Fallback Notes
        if evaluation.severity in ("CRITICAL", "HIGH"):
            z_pps = evaluation.z_scores.get("z_pps", 0.0)
            assessment = (
                f"Severe Statistical Outlier: Volumetric burst at +{z_pps:.1f}σ exceeds normal distribution "
                f"variance (p < 0.001). Coupled with protocol skew, this deviates definitively from legitimate "
                f"traffic baseline."
            )
            rec = "Enforce temporary dynamic rate-limiting on anomalous protocol ingress"
        elif evaluation.severity == "MEDIUM":
            assessment = (
                f"Moderate Traffic Drift: +{evaluation.z_scores.get('z_pps', 0.0):.1f}σ deviation observed. "
                f"May represent legitimate transient burst or early attack ramping."
            )
            rec = "Monitor endpoint telemetry and verify application transaction latency"
        else:
            assessment = "Telemetry conforms to expected Poisson process network baseline."
            rec = "No mitigation required"

        return {
            "source": "Deterministic Blue-Team Expert (Heuristic Baseline)",
            "assessment": assessment,
            "severity": evaluation.severity,
            "confidence": "HIGH" if evaluation.is_anomaly else "NORMAL",
            "recommended_mitigation_scope": rec,
        }

    def evaluate(self, payload: Any, generate_ai_notes: bool = True) -> Dict[str, Any]:
        """
        Evaluate traffic payload (feature dict from flow_extractor or direct metrics).
        Returns dictionary matching AnomalyEvaluationResult.to_dict().
        """
        features = payload.get("features", payload) if isinstance(payload, dict) else {}

        current_pps = float(features.get("Flow Packets/s", features.get("pps", 0.0)))
        current_bps = float(features.get("Flow Bytes/s", features.get("bps", 0.0)))

        dur = float(features.get("Flow Duration", 0.0)) / 1_000_000.0
        total_pkts = float(features.get("Total Fwd Packets", 0)) + float(features.get("Total Backward Packets", 0))
        if current_pps <= 0.0 and dur > 0 and total_pkts > 0:
            current_pps = total_pkts / dur
            total_bytes = float(features.get("Fwd Packets Length Total", 0)) + float(features.get("Bwd Packets Length Total", 0))
            current_bps = total_bytes / dur

        raw_proto = features.get("Protocol", features.get("protocol", None))
        proto_counts = {"tcp": 0, "udp": 0, "icmp": 0}
        if raw_proto is not None:
            try:
                p_int = int(raw_proto)
                if p_int == 1:
                    proto_counts["icmp"] = int(total_pkts) if total_pkts > 0 else 100
                elif p_int == 6:
                    proto_counts["tcp"] = int(total_pkts) if total_pkts > 0 else 100
                elif p_int == 17:
                    proto_counts["udp"] = int(total_pkts) if total_pkts > 0 else 100
            except (ValueError, TypeError):
                pass

        ip_frequencies = features.get("ip_frequencies", None)

        res = self.evaluate_traffic(
            current_pps=current_pps,
            current_bps=current_bps,
            proto_counts=proto_counts if sum(proto_counts.values()) > 0 else None,
            ip_frequencies=ip_frequencies,
            generate_ai_notes=generate_ai_notes,
        )
        return res.to_dict()


# Public alias matching H9 requirement
AnomalyDetector = RollingAnomalyDetector



class PerDestinationBaseline:
    """v5.3.0 adaptive H9: one EWMA baseline of packet/byte rate *per destination*.

    The old H9 compared every destination against one fixed baseline (a 60-packet benign capture,
    ~2 pkt/s, std 1), so ordinary traffic to any busy server scored "HIGH". Here each destination
    learns its own normal rate:

    * **warm-up:** the first `warmup` observations of a destination only train the baseline and
      are reported as `LEARNING` (never an anomaly);
    * afterwards an observation is an anomaly when its z-score is >= `z_crit`; the std has a floor
      of `rel_std_floor` x mean (and 1), so a very steady baseline does not turn small wobbles into
      huge z-scores;
    * the baseline only learns from observations that were *not* anomalous, so a flood does not
      teach the detector that floods are normal.

    Caveat: traffic that is already an attack during the warm-up becomes that destination's
    baseline. H6 (fixed rate thresholds) still covers that case.
    """

    def __init__(self, warmup: int = 20, alpha: float = 0.05, z_warn: float = 3.0, z_crit: float = 5.0,
                 rel_std_floor: float = 0.25, max_destinations: int = 4096):
        self.warmup, self.alpha, self.z_warn, self.z_crit = warmup, alpha, z_warn, z_crit
        self.rel_std_floor, self.max_destinations = rel_std_floor, max_destinations
        self._state: Dict[str, Dict[str, float]] = {}

    def _std(self, var: float, mean: float) -> float:
        return max(math.sqrt(max(var, 0.0)), self.rel_std_floor * abs(mean), 1.0)

    def evaluate(self, dst: str, pps: float, bps: float) -> Dict[str, Any]:
        st = self._state.get(dst)
        if st is None:
            if len(self._state) >= self.max_destinations:
                self._state.pop(next(iter(self._state)))  # bounded memory: forget the oldest
            st = self._state[dst] = {"n": 0, "mean_pps": pps, "var_pps": 0.0, "mean_bps": bps, "var_bps": 0.0}
        learning = st["n"] < self.warmup
        z_pps = (pps - st["mean_pps"]) / self._std(st["var_pps"], st["mean_pps"])
        z_bps = (bps - st["mean_bps"]) / self._std(st["var_bps"], st["mean_bps"])
        is_anomaly = (not learning) and z_pps >= self.z_crit
        if learning:
            severity = "LEARNING"
        elif z_pps >= 2 * self.z_crit:
            severity = "CRITICAL"
        elif z_pps >= self.z_crit:
            severity = "HIGH"
        elif z_pps >= self.z_warn:
            severity = "MEDIUM"
        else:
            severity = "NORMAL"
        reasons = []
        if is_anomaly:
            reasons.append(f"{pps:.1f} pps to {dst} is +{z_pps:.1f} sigma above its own baseline "
                           f"(mean {st['mean_pps']:.1f} pps over {int(st['n'])} observations)")
        baseline = {"mean_pps": round(st["mean_pps"], 2), "std_pps": round(self._std(st["var_pps"], st["mean_pps"]), 2),
                    "mean_bps": round(st["mean_bps"], 2), "observations": int(st["n"])}
        if not is_anomaly:  # learn only from normal-looking traffic
            a = self.alpha if not learning else 1.0 / (st["n"] + 1)  # warm-up: plain running mean
            for k, x in (("pps", pps), ("bps", bps)):
                d = x - st[f"mean_{k}"]
                st[f"mean_{k}"] += a * d
                st[f"var_{k}"] = (1 - a) * (st[f"var_{k}"] + a * d * d)
            st["n"] += 1
        return {"is_anomaly": is_anomaly, "severity": severity, "learning": learning,
                "anomaly_score": round(min(100.0, max(0.0, z_pps / self.z_crit * 60.0)), 1),
                "z_scores": {"z_pps": round(z_pps, 2), "z_bps": round(z_bps, 2)},
                "baseline_metrics": baseline, "anomaly_reasons": reasons, "destination": dst}
