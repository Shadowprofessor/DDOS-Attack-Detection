# -*- coding: utf-8 -*-
"""
YAML incident-response playbooks: loader, schema validation and step runner.

Validation uses a strict pydantic model (`Playbook.model_json_schema()` is the published JSON
Schema). A `propose_action` step ONLY calls `PendingActionManager.propose()`: the action lands
as PENDING and still needs an admin's `approve()`. Nothing here executes mitigation.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

PLAYBOOK_DIR = Path(__file__).resolve().parent.parent.parent / "playbooks"
ID_RE = r"^[a-z0-9][a-z0-9_]{1,63}$"

FAMILIES = ("syn_flood", "udp_reflection_amplification", "l7_low_and_slow", "dns_amplification",
            "zero_day_ood", "other")


def family_from_text(text: Optional[str]) -> str:
    """Map a free-text attack label (ML class / analyst attack_type) to a playbook family."""
    t = (text or "").lower()
    if "syn" in t:
        return "syn_flood"
    if "dns" in t:
        return "dns_amplification"
    if any(k in t for k in ("slow", "l7", "http")):
        return "l7_low_and_slow"
    if any(k in t for k in ("zero-day", "zero_day", "ood", "novel", "out-of-distribution")):
        return "zero_day_ood"
    if any(k in t for k in ("reflect", "amplif", "udp", "ntp", "ldap", "ssdp", "memcache", "chargen",
                            "snmp", "mssql", "netbios", "portmap", "tftp")):
        return "udp_reflection_amplification"
    return "other"


class PlaybookError(ValueError):
    pass


class ActionTemplate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_type: Literal["BLOCK", "RATE_LIMIT", "OPENFLOW_DROP", "cloudflare_scrub"]
    target: Literal["top_src_ip", "victim_ip"] = "top_src_ip"
    reason: str = Field(..., min_length=5, max_length=300)
    ttl_s: Optional[int] = Field(None, ge=30, le=86400)


class Step(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(..., pattern=ID_RE)
    title: str = Field(..., min_length=3, max_length=200)
    kind: Literal["check", "propose_action", "notify", "document"]
    requires_role: Literal["analyst", "admin"] = "analyst"
    description: str = Field("", max_length=1000)
    action: Optional[ActionTemplate] = None

    @model_validator(mode="after")
    def _action_only_for_propose(self) -> "Step":
        if self.kind == "propose_action" and self.action is None:
            raise ValueError(f"step '{self.id}': propose_action requires an 'action' template")
        if self.kind != "propose_action" and self.action is not None:
            raise ValueError(f"step '{self.id}': only propose_action steps may define 'action'")
        return self


class Playbook(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(..., pattern=ID_RE)
    name: str = Field(..., min_length=3, max_length=120)
    version: str = Field(..., pattern=r"^\d+\.\d+(\.\d+)?$")
    attack_families: List[Literal[FAMILIES]] = Field(..., min_length=1)  # type: ignore[valid-type]
    mitre: List[str] = Field(default_factory=list)
    steps: List[Step] = Field(..., min_length=1, max_length=50)

    @model_validator(mode="after")
    def _unique_steps(self) -> "Playbook":
        ids = [s.id for s in self.steps]
        dup = {i for i in ids if ids.count(i) > 1}
        if dup:
            raise ValueError(f"duplicate step ids: {sorted(dup)}")
        bad = [m for m in self.mitre if not re.match(r"^T\d{4}(\.\d{3})?$", m)]
        if bad:
            raise ValueError(f"invalid MITRE ATT&CK ids: {bad}")
        return self

    def step(self, step_id: str) -> Step:
        for s in self.steps:
            if s.id == step_id:
                return s
        raise KeyError(step_id)


def parse_playbook(text: str, source: str = "<string>") -> Playbook:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise PlaybookError(f"{source}: malformed YAML: {e}") from e
    if not isinstance(data, dict):
        raise PlaybookError(f"{source}: playbook must be a YAML mapping")
    try:
        return Playbook.model_validate(data)
    except ValidationError as e:
        msgs = "; ".join(f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in e.errors()[:5])
        raise PlaybookError(f"{source}: invalid playbook: {msgs}") from e


def load_playbooks(directory: Path = PLAYBOOK_DIR) -> Dict[str, Playbook]:
    out: Dict[str, Playbook] = {}
    for p in sorted(Path(directory).glob("*.yaml")):
        pb = parse_playbook(p.read_text(encoding="utf-8"), source=p.name)
        if pb.id in out:
            raise PlaybookError(f"{p.name}: duplicate playbook id '{pb.id}'")
        out[pb.id] = pb
    return out


def playbooks_for_family(playbooks: Dict[str, Playbook], family: str) -> List[str]:
    return [pid for pid, pb in playbooks.items() if family in pb.attack_families]


ROLE_RANK = {"analyst": 1, "admin": 2}


def _resolve_target(target: str, incident: dict) -> Optional[str]:
    agg = incident.get("aggregate") or {}
    if target == "top_src_ip":
        srcs = agg.get("top_src_ips") or []
        return srcs[0].get("key") if srcs else None
    dsts = agg.get("dst_ips") or []
    return dsts[0] if dsts else None


def run_step(service, incident_id: str, playbook: Playbook, step_id: str, actor: str, role: str,
             note: Optional[str] = None) -> dict:
    """Run one playbook step for an incident. Raises PermissionError if the role is too low."""
    from src.ir.lifecycle import IllegalTransition, NotFound, ValidationFailed

    try:
        step = playbook.step(step_id)
    except KeyError:
        raise NotFound(f"step '{step_id}' not in playbook '{playbook.id}'")
    if ROLE_RANK.get(role, 0) < ROLE_RANK[step.requires_role]:
        raise PermissionError(f"step '{step_id}' requires role '{step.requires_role}'")
    incident = service.get(incident_id)
    if incident["status"] in ("closed", "false_positive"):
        raise IllegalTransition(f"incident {incident_id} is {incident['status']}; playbooks cannot run")

    result: dict = {"kind": step.kind, "title": step.title}
    if note:
        result["note"] = note.strip()[:2000]
    if step.kind == "propose_action":
        tpl = step.action
        target = _resolve_target(tpl.target, incident)
        if not target:
            raise ValidationFailed(f"incident has no '{tpl.target}' in its aggregate; cannot propose action")
        victim = _resolve_target("victim_ip", incident) or "unknown"
        with service.db.session() as s:
            from src.ir.models import Incident
            mgr = service.manager_for(s.get(Incident, incident_id))
        action_id = mgr.propose(
            tpl.action_type, attacker_ip=target, victim_ip=victim,
            reason=f"[{incident_id}] {tpl.reason}", source=f"playbook:{playbook.id}:{step.id}",
        )
        service.link_action(incident_id, action_id, actor=actor, ttl_s=tpl.ttl_s)
        result.update({"action_id": action_id, "action_status": "PENDING", "requires_approval": True})
    return service.record_playbook_run(incident_id, playbook.id, step.id, "done", actor, result)
