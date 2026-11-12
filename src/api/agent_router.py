# -*- coding: utf-8 -*-
"""Agentic analyst API (v5.4.0).

* ``POST /api/incidents/{id}/agent`` - run the read-only agent; the plan is stored on the incident.
* ``POST /api/incidents/{id}/agent/propose/{rank}`` - an analyst turns ONE lab step of that plan into
  a PENDING proposal (linked to the incident). Only an admin's ``/actions/approve/{id}``
  (`PendingActionManager.approve()`) can enforce it. Advice steps cannot be proposed.
Nothing here approves or executes anything.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Path

from src.api.ir_router import ID_PATTERN, _fail, require_analyst_write
from src.api.rbac import Principal
from src.ir.runtime import get_ir_runtime

router = APIRouter(tags=["agent"])


@router.post("/api/incidents/{incident_id}/agent")
def run_agent(incident_id: str = Path(..., pattern=ID_PATTERN), p: Principal = Depends(require_analyst_write)):
    from src.agent.agent_analyst import AgentAnalyst, AgentTools
    from src.api.analyst_router import analyst_rate_limiter
    from src.api.live_router import get_live_state

    rt = get_ir_runtime()
    try:
        inc = rt.service.get(incident_id)
    except Exception as e:
        raise _fail(e)
    if not inc.get("aggregate"):
        raise HTTPException(status_code=409, detail="Incident has no telemetry aggregate to analyse.")
    if not analyst_rate_limiter.allow(p.actor):
        raise HTTPException(status_code=429, detail="Analyst rate limit exceeded; retry later.")
    tools = AgentTools(inc, live_state=get_live_state(), ir_service=rt.service, playbooks=rt.playbooks)
    plan = AgentAnalyst().run(tools)
    return rt.service.set_agent_plan(incident_id, p.actor, plan)


@router.post("/api/incidents/{incident_id}/agent/propose/{rank}", status_code=201)
def propose_step(incident_id: str = Path(..., pattern=ID_PATTERN), rank: int = Path(..., ge=1, le=10),
                 p: Principal = Depends(require_analyst_write)):
    from src.mitigation.lab_containment import is_lab_type

    rt = get_ir_runtime()
    try:
        inc = rt.service.get(incident_id)
    except Exception as e:
        raise _fail(e)
    plan = ((inc.get("analysis") or {}).get("agent") or {})
    step = next((s for s in plan.get("plan") or [] if s.get("rank") == rank), None)
    if step is None:
        raise HTTPException(status_code=404, detail="No such plan step; run the agent first.")
    if not is_lab_type(step.get("action")):
        raise HTTPException(status_code=400, detail="This step is advice only; nothing to propose.")
    if inc.get("is_replay"):
        raise HTTPException(status_code=400, detail="Replay incidents cannot propose real lab containment.")
    victim = ((inc.get("aggregate") or {}).get("dst_ips") or [None])[0]
    mgr = rt.service.live_manager()
    try:
        aid = mgr.propose(step["action"], step["target"], victim or "unknown",
                          reason=f"[agent plan {incident_id} step {rank}] {step.get('rationale', '')}"[:500],
                          confidence=plan.get("confidence"), source=f"agent_plan:{plan.get('source')}",
                          ttl_s=step.get("ttl_s"))
    except ValueError as e:  # target refused by lab/containment.py
        raise HTTPException(status_code=422, detail=str(e))
    try:
        rt.service.link_action(incident_id, aid, p.actor, ttl_s=step.get("ttl_s"))
    except Exception as e:
        raise _fail(e)
    return {"action_id": aid, "status": "PENDING", "requires": "admin approval on the Approvals page",
            "action": mgr.get_action(aid)}
