# -*- coding: utf-8 -*-
"""
Incident-response REST + WebSocket API (M3).

Every route needs a key (see `src/api/rbac.py`); admin-only routes return 403 to analysts.
No route here can approve or execute mitigation: approval stays at `/actions/approve/{id}`
(PendingActionManager.approve). Playbook `propose_action` steps only *propose*.
Handlers are sync so DB / PDF work runs in FastAPI's threadpool.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field, model_validator

from src.agent.schemas import IncidentAggregate
from src.api.rbac import ANALYST_TRANSITIONS, Principal, principal_for_key, require_admin, require_analyst
from src.ir.lifecycle import STATES, IRError
from src.ir.playbooks import PlaybookError, playbooks_for_family, run_step
from src.ir.runtime import get_ir_runtime
from src.obs.logging import log_safe

logger = logging.getLogger("ir.api")
router = APIRouter(tags=["incident-response"])

ID_PATTERN = r"^[A-Za-z0-9_.:-]{1,64}$"


def _fail(e: Exception) -> HTTPException:
    """Map domain errors to HTTP. Messages are our own (no stack traces / internals)."""
    if isinstance(e, PermissionError):
        return HTTPException(status_code=403, detail="Insufficient privileges for this playbook step.")
    if isinstance(e, IRError):
        return HTTPException(status_code=e.status, detail=str(e.args[0]) if e.args else "request failed")
    if isinstance(e, PlaybookError):
        return HTTPException(status_code=400, detail="Invalid playbook.")
    logger.error("IR API error: %s", log_safe(type(e).__name__))
    return HTTPException(status_code=500, detail="Internal error; see server logs.")


# ----------------------------------------------------------------------------- bodies
class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class IncidentCreate(_Strict):
    title: str = Field(..., min_length=3, max_length=200)
    severity: int = Field(..., ge=1, le=5)
    attack_family: Optional[Literal["syn_flood", "udp_reflection_amplification", "l7_low_and_slow",
                                    "dns_amplification", "zero_day_ood", "other"]] = None
    source_alert_ids: List[str] = Field(default_factory=list, max_length=50)
    aggregate: Optional[IncidentAggregate] = None
    detected_at: Optional[float] = Field(None, ge=0)


class TransitionBody(_Strict):
    to: Literal[STATES]  # type: ignore[valid-type]
    justification: Optional[str] = Field(None, max_length=2000)


class NoteBody(_Strict):
    text: str = Field(..., min_length=1, max_length=4000)


class StepBody(_Strict):
    note: Optional[str] = Field(None, max_length=2000)


class LinkBody(_Strict):
    action_id: str = Field(..., pattern=ID_PATTERN)
    ttl_s: Optional[int] = Field(None, ge=30, le=86400)


class ExtendBody(_Strict):
    reason: str = Field(..., min_length=5, max_length=500)
    seconds: Optional[int] = Field(None, ge=1, le=7 * 86400)
    permanent: bool = False


class CertInReportedBody(_Strict):
    reference: str = Field(..., min_length=3, max_length=200)


class ReplayBody(_Strict):
    scenario: Optional[str] = Field(None, pattern=r"^[a-z0-9_]{1,64}$")
    aggregate: Optional[IncidentAggregate] = None
    speed: float = Field(60.0, ge=1.0, le=10000.0)

    @model_validator(mode="after")
    def _one_source(self) -> "ReplayBody":
        if (self.scenario is None) == (self.aggregate is None):
            raise ValueError("give exactly one of 'scenario' or 'aggregate'")
        return self


# ----------------------------------------------------------------------------- incidents
@router.get("/api/incidents")
def list_incidents(status: Optional[Literal[STATES]] = None,  # type: ignore[valid-type]
                   include_replay: bool = True,
                   limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
                   sort: Literal["created_desc", "created_asc", "severity_desc", "severity_asc"] = "created_desc",
                   min_severity: Optional[int] = Query(None, ge=1, le=5),
                   p: Principal = Depends(require_analyst)):
    return get_ir_runtime().service.list(status=status, include_replay=include_replay, limit=limit,
                                         offset=offset, sort=sort, min_severity=min_severity)


@router.post("/api/incidents", status_code=201)
def create_incident(body: IncidentCreate, p: Principal = Depends(require_analyst)):
    try:
        return get_ir_runtime().service.create_incident(
            title=body.title, severity=body.severity, actor=p.actor, attack_family=body.attack_family,
            aggregate=body.aggregate.model_dump() if body.aggregate else None,
            source_alert_ids=body.source_alert_ids, detected_at=body.detected_at)
    except Exception as e:
        raise _fail(e)


@router.get("/api/incidents/{incident_id}")
def get_incident(incident_id: str = Path(..., pattern=ID_PATTERN), p: Principal = Depends(require_analyst)):
    rt = get_ir_runtime()
    try:
        inc = rt.service.get(incident_id)
    except Exception as e:
        raise _fail(e)
    inc["suggested_playbooks"] = playbooks_for_family(rt.playbooks, inc["attack_family"])
    return inc


@router.post("/api/incidents/{incident_id}/transition")
def transition_incident(body: TransitionBody, incident_id: str = Path(..., pattern=ID_PATTERN),
                        p: Principal = Depends(require_analyst)):
    if body.to not in ANALYST_TRANSITIONS and not p.has("admin"):
        raise HTTPException(status_code=403, detail=f"Insufficient privileges: '{body.to}' requires admin.")
    try:
        return get_ir_runtime().service.transition(incident_id, body.to, actor=p.actor,
                                                   justification=body.justification)
    except Exception as e:
        raise _fail(e)


@router.post("/api/incidents/{incident_id}/notes", status_code=201)
def add_note(body: NoteBody, incident_id: str = Path(..., pattern=ID_PATTERN),
             p: Principal = Depends(require_analyst)):
    try:
        return get_ir_runtime().service.add_note(incident_id, p.actor, body.text)
    except Exception as e:
        raise _fail(e)


@router.post("/api/incidents/{incident_id}/actions", status_code=201)
def link_action(body: LinkBody, incident_id: str = Path(..., pattern=ID_PATTERN),
                p: Principal = Depends(require_analyst)):
    """Attach an existing proposed action (e.g. from /score/flow) to an incident."""
    try:
        return get_ir_runtime().service.link_action(incident_id, body.action_id, p.actor, ttl_s=body.ttl_s)
    except Exception as e:
        raise _fail(e)


@router.post("/api/incidents/{incident_id}/playbook/{playbook_id}/step/{step_id}")
def run_playbook_step(body: Optional[StepBody] = None,
                      incident_id: str = Path(..., pattern=ID_PATTERN),
                      playbook_id: str = Path(..., pattern=r"^[a-z0-9_]{1,64}$"),
                      step_id: str = Path(..., pattern=r"^[a-z0-9_]{1,64}$"),
                      p: Principal = Depends(require_analyst)):
    rt = get_ir_runtime()
    pb = rt.playbooks.get(playbook_id)
    if pb is None:
        raise HTTPException(status_code=404, detail="Playbook not found.")
    try:
        return run_step(rt.service, incident_id, pb, step_id, actor=p.actor, role=p.role,
                        note=body.note if body else None)
    except Exception as e:
        raise _fail(e)


@router.get("/api/incidents/{incident_id}/export")
def export_incident(incident_id: str = Path(..., pattern=ID_PATTERN),
                    format: Literal["md", "pdf"] = "md", p: Principal = Depends(require_analyst)):
    from src.ir.export import to_markdown, to_pdf

    try:
        inc = get_ir_runtime().service.get(incident_id)
    except Exception as e:
        raise _fail(e)
    safe_id = inc["id"]  # from our DB: INC-YYYYMMDD-xxxx
    if format == "pdf":
        return Response(to_pdf(inc), media_type="application/pdf",
                        headers={"Content-Disposition": f'attachment; filename="{safe_id}.pdf"'})
    return Response(to_markdown(inc), media_type="text/markdown; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{safe_id}.md"'})


@router.get("/api/incidents/{incident_id}/cert-in/draft")
def cert_in_draft(incident_id: str = Path(..., pattern=ID_PATTERN), p: Principal = Depends(require_admin)):
    from src.ir.cert_in import build_draft

    rt = get_ir_runtime()
    try:
        inc = rt.service.get(incident_id)
    except Exception as e:
        raise _fail(e)
    if inc.get("cert_in_deadline") is None:
        raise HTTPException(status_code=409, detail="Incident is below the CERT-In reporting threshold.")
    return build_draft(inc, rt.settings.cert_in, rt.service.clock())


@router.post("/api/incidents/{incident_id}/cert-in/reported")
def cert_in_reported(body: CertInReportedBody, incident_id: str = Path(..., pattern=ID_PATTERN),
                     p: Principal = Depends(require_admin)):
    """Record that a human submitted the report to CERT-In (stops the timer)."""
    from src.ir.cert_in import mark_reported

    try:
        return mark_reported(get_ir_runtime().service, incident_id, p.actor, body.reference)
    except Exception as e:
        raise _fail(e)


# ----------------------------------------------------------------------------- playbooks / replay
@router.get("/api/playbooks")
def list_playbooks(p: Principal = Depends(require_analyst)):
    return {pid: pb.model_dump() for pid, pb in get_ir_runtime().playbooks.items()}


@router.post("/api/replay", status_code=201)
def replay(body: ReplayBody, p: Principal = Depends(require_analyst)):
    from src.ir.replay import list_scenarios, load_scenario

    rt = get_ir_runtime()
    if body.scenario is not None:
        if body.scenario not in list_scenarios():
            raise HTTPException(status_code=404, detail="Unknown replay scenario.")
        agg = load_scenario(body.scenario)
    else:
        agg = body.aggregate
    try:
        return rt.replay.replay(agg, speed=body.speed, actor=p.actor, scenario=body.scenario)
    except Exception as e:
        raise _fail(e)


@router.get("/api/replay/scenarios")
def replay_scenarios(p: Principal = Depends(require_analyst)):
    from src.ir.replay import list_scenarios

    return {"scenarios": list_scenarios()}


# ----------------------------------------------------------------------------- rollback
@router.get("/api/actions/{action_id}/rollback")
def rollback_status(action_id: str = Path(..., pattern=ID_PATTERN), p: Principal = Depends(require_analyst)):
    try:
        return get_ir_runtime().rollback.status(action_id)
    except Exception as e:
        raise _fail(e)


@router.post("/api/actions/{action_id}/extend")
def extend_rollback(body: ExtendBody, action_id: str = Path(..., pattern=ID_PATTERN),
                    p: Principal = Depends(require_admin)):
    try:
        return get_ir_runtime().rollback.extend(action_id, p.actor, body.reason, seconds=body.seconds,
                                                permanent=body.permanent)
    except Exception as e:
        raise _fail(e)


# ----------------------------------------------------------------------------- analysis / approvals
@router.post("/api/incidents/{incident_id}/analyze")
def analyze_incident(incident_id: str = Path(..., pattern=ID_PATTERN), p: Principal = Depends(require_analyst)):
    """Run the Layer-3 analyst on the incident's stored aggregate. Recommendation only: the result
    is stored on the incident; nothing is proposed or executed. Replays always use the rule analyst."""
    from src.api.analyst_router import analyst_rate_limiter
    from src.agent.threat_analyst import get_threat_analyst, rule_based_analysis

    rt = get_ir_runtime()
    try:
        inc = rt.service.get(incident_id)
    except Exception as e:
        raise _fail(e)
    if not inc.get("aggregate"):
        raise HTTPException(status_code=409, detail="Incident has no telemetry aggregate to analyse.")
    if not analyst_rate_limiter.allow(p.actor):
        raise HTTPException(status_code=429, detail="Analyst rate limit exceeded; retry later.")
    try:
        agg = IncidentAggregate.model_validate(inc["aggregate"])
    except Exception:
        raise HTTPException(status_code=409, detail="Stored aggregate is not valid for analysis.")
    if inc["is_replay"]:
        result = {"analysis": rule_based_analysis(agg).model_dump(), "source": "rules",
                  "prompt_version": "replay", "degraded": True,
                  "degraded_reason": "replay incidents use the rule-based analyst"}
    else:
        result = get_threat_analyst().analyze(agg).model_dump()
    return rt.service.set_analysis(incident_id, p.actor, result)


_BLAST = {"RATE_LIMIT": "low", "BLOCK": "medium", "OPENFLOW_DROP": "medium", "cloudflare_scrub": "high"}
_ACTION_FIELDS = ("action_id", "action_type", "attacker_ip", "victim_ip", "reason", "confidence", "source",
                  "status", "proposed_at", "approved_at", "approver", "consensus_tier", "proposed_commands")


@router.get("/api/approvals")
def approvals(p: Principal = Depends(require_analyst)):
    """Pending actions (awaiting an admin) and active time-boxed blocks, with incident links.
    Read-only: approving still goes through POST /actions/approve/{id} (admin)."""
    rt = get_ir_runtime()
    mgr = rt.service.default_manager()
    links = {a["action_id"]: a for a in rt.service.action_links() if not a["action_id"].startswith("dry-")}
    now = rt.service.clock()

    def view(a: dict) -> dict:
        d = {k: a.get(k) for k in _ACTION_FIELDS}
        link = links.get(a["action_id"])
        d["incident_id"] = link["incident_id"] if link else None
        d["blast_radius"] = _BLAST.get(a.get("action_type"), "medium")
        d["reversible"] = True
        d["rollback_ttl_s"] = (link.get("ttl_s") if link else None) or (rt.settings.rollback_ttl_s if link else None)
        if link:
            d["rollback_state"] = link["rollback_state"]
            d["rollback_at"] = link["rollback_at"]
            scheduled = link["rollback_state"] == "scheduled" and link["rollback_at"]
            d["seconds_until_rollback"] = (link["rollback_at"] - now) if scheduled else None
        return d

    pending = [view(a) for a in mgr.get_pending().values()]
    active = []
    for aid, link in links.items():
        if link["rollback_state"] in ("scheduled", "permanent", "failed"):
            a = mgr.get_action(aid)
            if a:
                active.append(view(a))
    pending.sort(key=lambda d: d.get("proposed_at") or 0, reverse=True)
    return {"pending": pending, "active": active, "role": p.role, "default_ttl_s": rt.settings.rollback_ttl_s}


# ----------------------------------------------------------------------------- websocket
def _ws_session_key(websocket: WebSocket) -> Optional[str]:
    """Session-cookie auth for the SOC app. Cookie handshakes must be same-origin (Origin host ==
    Host) so another site cannot ride the cookie (cross-site WebSocket hijacking)."""
    from urllib.parse import urlparse

    from src.api.rbac import role_for_key
    from src.web.session import COOKIE_NAME, get_session_store

    sid = websocket.cookies.get(COOKIE_NAME)
    if not sid:
        return None
    origin = websocket.headers.get("origin")
    host = websocket.headers.get("host")
    if not origin or not host or urlparse(origin).netloc != host:
        return None
    s = get_session_store().get(sid)
    if s is None or role_for_key(s.key) is None:
        return None
    return s.key


@router.websocket("/ws/incidents")
async def ws_incidents(websocket: WebSocket):
    """Server->client incident events. Auth: X-API-Key/X-Admin-Key header on the handshake, the
    SOC web-app session cookie (same-origin handshakes only), or a first message
    {"type": "auth", "key": "..."} within 5 s. Inbound messages are ignored."""
    await websocket.accept()
    key = websocket.headers.get("x-admin-key") or websocket.headers.get("x-api-key")
    if not key:
        key = _ws_session_key(websocket)
    if not key:
        try:
            data = json.loads(await asyncio.wait_for(websocket.receive_text(), timeout=5.0))
            key = data.get("key") if isinstance(data, dict) and data.get("type") == "auth" else None
        except Exception:
            key = None
    principal = principal_for_key(key if isinstance(key, str) else None)
    if principal is None:
        await websocket.close(code=1008)
        return
    hub = get_ir_runtime().hub
    hub.add(websocket, asyncio.get_running_loop())
    try:
        await websocket.send_text(json.dumps({"type": "auth_ok", "role": principal.role}))
        while True:
            await websocket.receive_text()  # server->client only: inbound ignored
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.debug("ws/incidents error: %s", log_safe(type(e).__name__))
    finally:
        hub.remove(websocket)
