# -*- coding: utf-8 -*-
"""Lab enforcer hand-off (v5.4.0). LAB-ONLY.

* ``GET  /api/lab/enforcement/queue``  - approved lab containment actions still to apply/remove;
* ``POST /api/lab/enforcement/report`` - the enforcer reports what it did (applied / refused / failed /
  expired / removed). Recording a fact can never create, approve or extend a block.

Only actions that a human admin already approved via ``/actions/approve/{id}``
(``PendingActionManager.approve()``) ever appear in the queue. The bridge relays both directions
through files on the shared disk, so the WSL2 enforcer needs no network path to this API.
"""
from __future__ import annotations

from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from src.api.live_router import hub as live_hub
from src.api.live_router import require_live_write
from src.api.rbac import Principal, require_analyst
from src.mitigation.manager import get_manager
from src.obs import metrics as m

router = APIRouter(tags=["lab-enforcement"])
LAB_REPORTS = m.REGISTRY.counter("ddos_lab_enforcement_reports_total", "Lab enforcer reports, by state.")


class Report(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_id: str = Field(..., pattern=r"^[A-Za-z0-9_-]{1,64}$")
    state: Literal["applied", "refused", "failed", "expired", "removed"]
    detail: str = Field("", max_length=300)
    ts: Optional[float] = Field(None, ge=0)


@router.get("/api/lab/enforcement/queue")
def queue(p: Principal = Depends(require_analyst)):
    return {"queue": get_manager().lab_queue()}


@router.post("/api/lab/enforcement/report")
def report(body: Report, p: Principal = Depends(require_live_write)):
    ok, msg = get_manager().record_lab_enforcement(body.action_id, body.state, body.detail, body.ts)
    if not ok:
        raise HTTPException(status_code=409, detail=msg)
    LAB_REPORTS.inc(state=body.state)
    a = get_manager().get_action(body.action_id) or {}
    live_hub.publish({"type": "live.enforcement", "action_id": body.action_id, "state": body.state,
                      "target": a.get("attacker_ip"), "action_type": a.get("action_type"),
                      "victim_ip": a.get("victim_ip"), "ts": body.ts, "detail": body.detail,
                      "approved_at": a.get("approved_at")})
    return {"ok": True, "state": body.state}
