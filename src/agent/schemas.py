# -*- coding: utf-8 -*-
"""
Pydantic contracts for the Layer-3 Nemotron threat analyst.

* ``IncidentAggregate`` — the ONLY input the LLM ever sees: aggregated, bounded telemetry for a
  single incident window. Lists are length-capped so raw packet data or unbounded log dumps
  cannot be smuggled into a prompt.
* ``IncidentAnalysis`` — the strict output schema the LLM must return via tool-calling.
* ``AnalysisResult`` — the analysis plus provenance added by our code (never by the LLM).
"""
from __future__ import annotations

import re
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

MITRE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# --------------------------------------------------------------------------- input


class SourceShare(BaseModel):
    key: str = Field(..., max_length=128, description="IP, ASN, country code or port")
    label: Optional[str] = Field(None, max_length=128, description="e.g. ASN name (untrusted)")
    share: float = Field(..., ge=0.0, le=1.0)


class AlertEvent(BaseModel):
    ts: float
    layer: str = Field(..., max_length=32)
    rule: str = Field(..., max_length=64)
    detail: str = Field("", max_length=300, description="untrusted free text")


class L7Summary(BaseModel):
    http_rps: float = 0.0
    top_user_agents: List[str] = Field(default_factory=list, max_length=5)
    top_hosts: List[str] = Field(default_factory=list, max_length=5)
    top_uris: List[str] = Field(default_factory=list, max_length=5)
    slow_connections: int = 0


class DnsSummary(BaseModel):
    qps: float = 0.0
    top_qnames: List[str] = Field(default_factory=list, max_length=5)


class MLVerdict(BaseModel):
    label: str = Field(..., max_length=64)
    confidence: float = Field(..., ge=0.0, le=1.0)
    ood_score: Optional[float] = Field(None, ge=0.0, le=1.0)


class IncidentAggregate(BaseModel):
    """Aggregated telemetry for one incident window (no raw packets/payloads)."""

    model_config = ConfigDict(extra="forbid")

    incident_id: str = Field(..., max_length=64, pattern=r"^[A-Za-z0-9_.:-]+$")
    window_start: float
    window_seconds: int = Field(60, ge=1, le=3600)
    pps: float = Field(0.0, ge=0.0)
    bps: float = Field(0.0, ge=0.0)
    flow_count: int = Field(0, ge=0)
    unique_src_ips: int = Field(0, ge=0)
    src_ip_entropy: float = Field(0.0, ge=0.0)
    top_src_ips: List[SourceShare] = Field(default_factory=list, max_length=10)
    top_src_asns: List[SourceShare] = Field(default_factory=list, max_length=10)
    top_src_countries: List[SourceShare] = Field(default_factory=list, max_length=10)
    dst_ips: List[str] = Field(default_factory=list, max_length=10)
    dst_ports: List[SourceShare] = Field(default_factory=list, max_length=10)
    protocol_mix: Dict[str, float] = Field(default_factory=dict)
    tcp_flag_ratios: Dict[str, float] = Field(default_factory=dict)
    packet_size_p50: float = 0.0
    packet_size_p95: float = 0.0
    l7: Optional[L7Summary] = None
    dns: Optional[DnsSummary] = None
    ml: Optional[MLVerdict] = None
    alert_history: List[AlertEvent] = Field(default_factory=list, max_length=20)

    def observed_ips(self) -> set:
        """Every IP that legitimately appears in this incident (sources + destinations)."""
        return {s.key for s in self.top_src_ips} | set(self.dst_ips)


# --------------------------------------------------------------------------- output


class RecommendedAction(BaseModel):
    action: str = Field(..., min_length=3, max_length=300)
    blast_radius: Literal["low", "medium", "high"]
    reversible: bool
    requires_human: bool


class IncidentAnalysis(BaseModel):
    """Strict schema the LLM must satisfy (via the submit_incident_analysis tool)."""

    incident_id: str = Field(..., max_length=64)
    attack_type: str = Field(..., min_length=2, max_length=120)
    mitre_ids: List[str] = Field(default_factory=list, max_length=8)
    severity: int = Field(..., ge=1, le=5)
    confidence: float = Field(..., ge=0.0, le=1.0)
    evidence: List[str] = Field(..., min_length=1, max_length=12)
    false_positive_assessment: str = Field(..., min_length=3, max_length=800)
    recommended_actions: List[RecommendedAction] = Field(default_factory=list, max_length=8)
    next_queries: List[str] = Field(default_factory=list, max_length=8)
    report_summary: str = Field(..., min_length=10, max_length=1500)

    @field_validator("mitre_ids")
    @classmethod
    def _valid_mitre(cls, v: List[str]) -> List[str]:
        bad = [m for m in v if not MITRE_ID_RE.match(m)]
        if bad:
            raise ValueError(f"invalid MITRE ATT&CK ids: {bad}")
        return v


class AnalysisResult(BaseModel):
    """Analysis + provenance. Provenance fields are set by our code, never by the model."""

    analysis: IncidentAnalysis
    source: str = Field(..., description="'llm:<model>' or 'rules'")
    prompt_version: str
    degraded: bool = False
    degraded_reason: Optional[str] = None
    policy_violations: List[str] = Field(default_factory=list)
    suspicious_telemetry: int = Field(0, description="instruction-like strings found in telemetry")
    cached: bool = False
    latency_ms: Optional[float] = None
