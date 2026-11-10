# -*- coding: utf-8 -*-
"""Scenario library schema + loader (lab/scenarios/*.yaml). Descriptive only: no tool commands."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class ScenarioError(ValueError):
    pass


class Profile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol: Literal["tcp_syn", "udp", "udp_reflection", "dns_reflection", "http", "http_slow", "mixed"]
    rate_pps: int = Field(..., gt=0)
    duration_s: int = Field(..., gt=0)
    sources: int = Field(..., ge=1, le=254)
    source_role: Literal["attacker", "client", "reflector"]
    target_role: Literal["victim"] = "victim"
    dst_port: Optional[int] = Field(None, ge=1, le=65535)
    packet_size: int = Field(64, ge=40, le=1500)
    slow_connections: int = Field(0, ge=0)


class Expected(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident: bool
    family: Optional[Literal["syn_flood", "udp_reflection_amplification", "l7_low_and_slow",
                             "dns_amplification", "zero_day_ood", "other"]] = None
    layers: List[Literal["L1", "L2", "OOD", "L3"]] = Field(default_factory=list)
    max_mttd_s: Optional[int] = Field(None, gt=0)

    @model_validator(mode="after")
    def _consistent(self) -> "Expected":
        if self.incident and not (self.family and self.layers):
            raise ValueError("an attack scenario needs an expected family and layers")
        if not self.incident and (self.family or self.layers):
            raise ValueError("a benign scenario must not expect a family or detection layers")
        return self


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(..., pattern=r"^[a-z0-9_]{3,40}$")
    name: str = Field(..., min_length=3, max_length=120)
    attack: bool
    mitre: List[str] = Field(default_factory=list)
    description: str = Field(..., min_length=10, max_length=1000)
    profile: Profile
    expected: Expected

    @model_validator(mode="after")
    def _check(self) -> "Scenario":
        bad = [m for m in self.mitre if not MITRE_RE.match(m)]
        if bad:
            raise ValueError(f"invalid MITRE ATT&CK ids: {bad}")
        if self.attack != self.expected.incident:
            raise ValueError("attack flag and expected.incident disagree")
        if self.attack and not self.mitre:
            raise ValueError("attack scenarios must map to ATT&CK")
        return self


def parse_scenario(text: str, source: str = "<string>") -> Scenario:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise ScenarioError(f"{source}: malformed YAML: {e}") from e
    if not isinstance(data, dict):
        raise ScenarioError(f"{source}: scenario must be a mapping")
    try:
        return Scenario.model_validate(data)
    except ValidationError as e:
        msgs = "; ".join(f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in e.errors()[:5])
        raise ScenarioError(f"{source}: invalid scenario: {msgs}") from e


def load_scenarios(directory: Path = SCENARIO_DIR) -> Dict[str, Scenario]:
    out: Dict[str, Scenario] = {}
    for p in sorted(Path(directory).glob("*.yaml")):
        sc = parse_scenario(p.read_text(encoding="utf-8"), p.name)
        if sc.id != p.stem:
            raise ScenarioError(f"{p.name}: id '{sc.id}' must match the file name")
        out[sc.id] = sc
    return out
