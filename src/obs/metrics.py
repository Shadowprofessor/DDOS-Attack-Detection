# -*- coding: utf-8 -*-
"""
Zero-dependency, Prometheus-compatible metrics registry.

Renders the Prometheus text exposition format (v0.0.4) without requiring the
`prometheus_client` package, so the `/metrics` endpoint works out of the box on
any environment. If richer histograms/exemplars are needed later, this can be
swapped for `prometheus_client` behind the same call sites.
"""
import threading
from typing import Dict, Optional, Tuple

_LOCK = threading.Lock()

LabelKey = Tuple[Tuple[str, str], ...]


def _escape(v: str) -> str:
    return v.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _fmt_labels(labels: Dict[str, str]) -> str:
    if not labels:
        return ""
    inner = ",".join(f'{k}="{_escape(str(v))}"' for k, v in sorted(labels.items()))
    return "{" + inner + "}"


class _Metric:
    def __init__(self, name: str, help_text: str, mtype: str):
        self.name = name
        self.help = help_text
        self.type = mtype
        self.samples: Dict[LabelKey, float] = {}

    @staticmethod
    def _key(labels: Optional[Dict[str, str]]) -> LabelKey:
        return tuple(sorted((labels or {}).items()))


class Counter(_Metric):
    def __init__(self, name: str, help_text: str):
        super().__init__(name, help_text, "counter")

    def inc(self, amount: float = 1.0, **labels: str) -> None:
        k = self._key(labels)
        with _LOCK:
            self.samples[k] = self.samples.get(k, 0.0) + amount


class Gauge(_Metric):
    def __init__(self, name: str, help_text: str):
        super().__init__(name, help_text, "gauge")

    def set(self, value: float, **labels: str) -> None:
        k = self._key(labels)
        with _LOCK:
            self.samples[k] = float(value)

    def remove(self, **labels: str) -> None:
        with _LOCK:
            self.samples.pop(self._key(labels), None)


class Histogram(_Metric):
    """Cumulative-bucket histogram (Prometheus semantics), no labels."""

    def __init__(self, name: str, help_text: str, buckets: Tuple[float, ...]):
        super().__init__(name, help_text, "histogram")
        self.buckets = tuple(sorted(buckets))
        self.counts = [0] * len(self.buckets)
        self.total = 0.0
        self.n = 0

    def observe(self, value: float) -> None:
        with _LOCK:
            for i, b in enumerate(self.buckets):
                if value <= b:
                    self.counts[i] += 1
            self.total += float(value)
            self.n += 1

    def lines(self) -> list:
        out = [f'{self.name}_bucket{{le="{b:g}"}} {c}' for b, c in zip(self.buckets, self.counts)]
        out.append(f'{self.name}_bucket{{le="+Inf"}} {self.n}')
        out.append(f"{self.name}_sum {self.total}")
        out.append(f"{self.name}_count {self.n}")
        return out


class Registry:
    def __init__(self) -> None:
        self._metrics: Dict[str, _Metric] = {}

    def counter(self, name: str, help_text: str) -> Counter:
        m = self._metrics.get(name)
        if m is None:
            m = Counter(name, help_text)
            self._metrics[name] = m
        return m  # type: ignore[return-value]

    def gauge(self, name: str, help_text: str) -> Gauge:
        m = self._metrics.get(name)
        if m is None:
            m = Gauge(name, help_text)
            self._metrics[name] = m
        return m  # type: ignore[return-value]

    def histogram(self, name: str, help_text: str, buckets: Tuple[float, ...]) -> Histogram:
        m = self._metrics.get(name)
        if m is None:
            m = Histogram(name, help_text, buckets)
            self._metrics[name] = m
        return m  # type: ignore[return-value]

    def render(self) -> str:
        lines = []
        with _LOCK:
            for m in self._metrics.values():
                lines.append(f"# HELP {m.name} {m.help}")
                lines.append(f"# TYPE {m.name} {m.type}")
                if isinstance(m, Histogram):
                    lines.extend(m.lines())
                    continue
                if not m.samples:
                    lines.append(f"{m.name} 0")
                    continue
                for key, val in m.samples.items():
                    lines.append(f"{m.name}{_fmt_labels(dict(key))} {val}")
        return "\n".join(lines) + "\n"


# Default registry + pre-declared application metrics.
REGISTRY = Registry()
HTTP_REQUESTS = REGISTRY.counter("ddos_http_requests_total", "HTTP requests by endpoint and status.")
FLOWS_SCORED = REGISTRY.counter("ddos_flows_scored_total", "Flows scored by the service.")
ALERTS = REGISTRY.counter("ddos_alerts_total", "Detection alerts emitted, by severity.")
PENDING_ACTIONS = REGISTRY.gauge("ddos_pending_actions", "Current count of PENDING mitigation actions.")
SCORE_LATENCY = REGISTRY.gauge("ddos_request_latency_seconds", "Last observed HTTP request latency (seconds).")

# Layer-3 LLM analyst (cost / latency / reliability / safety)
LLM_REQUESTS = REGISTRY.counter("ddos_llm_requests_total", "LLM calls by model and outcome.")
LLM_LATENCY_SUM = REGISTRY.counter("ddos_llm_latency_seconds_sum", "Total LLM call latency (seconds).")
LLM_LATENCY_COUNT = REGISTRY.counter("ddos_llm_latency_seconds_count", "Number of timed LLM calls.")
LLM_TOKENS = REGISTRY.counter("ddos_llm_tokens_total", "LLM tokens by model and kind (prompt/completion).")
LLM_COST = REGISTRY.counter("ddos_llm_cost_usd_total", "Estimated LLM spend (USD; 0 on free tier).")
ANALYST_CACHE = REGISTRY.counter("ddos_analyst_cache_total", "Analyst cache lookups by result.")
ANALYST_FALLBACK = REGISTRY.counter("ddos_analyst_fallback_total", "Rule-based fallbacks by reason.")
ANALYST_POLICY = REGISTRY.counter("ddos_analyst_policy_violations_total", "Output-policy corrections by kind.")
ANALYST_SUSPICIOUS = REGISTRY.counter("ddos_analyst_suspicious_telemetry_total", "Instruction-like strings seen in telemetry.")

# Incident response (M3)
_IR_BUCKETS = (10, 30, 60, 120, 300, 600, 1800, 3600, 21600)
INCIDENTS_BY_STATE = REGISTRY.gauge("ddos_incidents", "Incidents by lifecycle state (excludes replays).")
INCIDENT_MTTD = REGISTRY.histogram("ddos_incident_mttd_seconds", "Time from attack window start to detection.", _IR_BUCKETS)
INCIDENT_MTTC = REGISTRY.histogram("ddos_incident_mttc_seconds", "Time from detection to containment.", _IR_BUCKETS)
ROLLBACKS = REGISTRY.counter("ddos_rollbacks_total", "Auto-rollbacks of approved blocks, by result.")
CERT_IN_REMAINING = REGISTRY.gauge("ddos_cert_in_seconds_remaining", "Seconds left before the CERT-In 6 h reporting deadline.")


def render_latest() -> str:
    """Return the current metrics in Prometheus text exposition format."""
    return REGISTRY.render()
