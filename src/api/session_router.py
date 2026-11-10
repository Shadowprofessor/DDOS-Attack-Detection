# -*- coding: utf-8 -*-
"""
SOC web-app session + overview API (v4.3.0).

* POST /api/session/login   {api_key}  -> sets the session cookie, returns {role, csrf_token}
* GET  /api/session                     -> {role, csrf_token} for the current session (401 if none)
* POST /api/session/logout              -> requires the CSRF token; clears the session
* GET  /api/overview                    -> SOC overview KPIs (analyst+)

The cookie is HttpOnly + Secure + SameSite=Strict, Path=/. Login is rate-limited per client.
"""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field

from src.api.rbac import Principal, principal_for_key, principal_from_session, require_analyst
from src.web.session import COOKIE_NAME, get_session_store

router = APIRouter(tags=["soc-session"])

LOGIN_PER_MIN = int(os.environ.get("DDOS_LOGIN_RATE_PER_MIN", "10"))


class _LoginLimiter:
    def __init__(self):
        self._hits: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, who: str) -> bool:
        now = time.monotonic()
        with self._lock:
            self._hits[who] = [t for t in self._hits[who] if t > now - 60]
            if len(self._hits[who]) >= LOGIN_PER_MIN:
                return False
            self._hits[who].append(now)
            return True

    def clear(self) -> None:
        with self._lock:
            self._hits.clear()


login_limiter = _LoginLimiter()


class LoginBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    api_key: str = Field(..., min_length=8, max_length=256)


def _set_cookie(resp: Response, sid: str, max_age: int) -> None:
    resp.set_cookie(COOKIE_NAME, sid, max_age=max_age, path="/", httponly=True, secure=True,
                    samesite="strict")


@router.post("/api/session/login")
def login(body: LoginBody, request: Request, response: Response):
    who = request.client.host if request.client else "unknown"
    if not login_limiter.allow(who):
        raise HTTPException(status_code=429, detail="Too many login attempts; retry later.")
    p = principal_for_key(body.api_key)
    if p is None:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    store = get_session_store()
    s = store.create(body.api_key, replace_sid=request.cookies.get(COOKIE_NAME))  # rotate on login
    _set_cookie(response, s.sid, int(store.absolute_s))
    response.headers["Cache-Control"] = "no-store"
    return {"role": p.role, "actor": p.actor, "csrf_token": s.csrf}


@router.get("/api/session")
def whoami(request: Request, response: Response):
    p = principal_from_session(request)
    if p is None:
        raise HTTPException(status_code=401, detail="No active session.")
    s = get_session_store().get(request.cookies.get(COOKIE_NAME))
    response.headers["Cache-Control"] = "no-store"
    return {"role": p.role, "actor": p.actor, "csrf_token": s.csrf if s else None}


@router.post("/api/session/logout", status_code=204)
def logout(request: Request):
    if principal_from_session(request) is None:  # enforces CSRF for a live session
        raise HTTPException(status_code=401, detail="No active session.")
    get_session_store().delete(request.cookies.get(COOKIE_NAME))
    resp = Response(status_code=204)
    resp.delete_cookie(COOKIE_NAME, path="/", secure=True, httponly=True, samesite="strict")
    return resp


@router.get("/api/overview")
def overview(p: Principal = Depends(require_analyst)):
    from src.ir.lifecycle import OPEN_STATES
    from src.ir.runtime import get_ir_runtime

    rt = get_ir_runtime()
    svc = rt.service
    items = svc.list(include_replay=False, limit=200)["items"]
    now = svc.clock()
    open_items = [i for i in items if i["status"] in OPEN_STATES]
    by_sev = {str(k): 0 for k in range(1, 6)}
    by_status: Dict[str, int] = {}
    for i in items:
        by_status[i["status"]] = by_status.get(i["status"], 0) + 1
    for i in open_items:
        by_sev[str(i["severity"])] += 1
    mttc = [i["contained_at"] - i["detected_at"] for i in items if i["contained_at"]]
    decided = by_status.get("false_positive", 0) + sum(1 for i in items if i["contained_at"])
    timers = sorted(
        ({"incident_id": i["id"], "title": i["title"], "severity": i["severity"],
          "seconds_remaining": i["cert_in_deadline"] - now}
         for i in open_items if i["cert_in_deadline"] and not i["cert_in_reported_at"]),
        key=lambda t: t["seconds_remaining"])
    try:
        from src.mitigation.manager import get_manager
        pending = len(get_manager().get_pending())
    except Exception:
        pending = None
    try:
        from src.api.scoring_service import registry
        models_loaded = bool(registry._loaded)
    except Exception:
        models_loaded = False
    try:
        from src.agent.threat_analyst import get_threat_analyst
        a = get_threat_analyst()
        llm = {"configured": bool(getattr(a.client.config, "api_key", None)),
               "models": list(getattr(a.client.config, "models", []) or [])}
    except Exception:
        llm = {"configured": False, "models": []}
    return {
        "generated_at": now,
        "incidents": {"open": len(open_items), "by_severity_open": by_sev, "by_status": by_status,
                      "recent": items[:5], "sample_size": len(items)},
        "kpis": {"mttc_seconds_avg": (sum(mttc) / len(mttc)) if mttc else None,
                 "false_positive_rate": (by_status.get("false_positive", 0) / decided) if decided else None},
        "cert_in_timers": timers,
        "pending_actions": pending,
        "health": {"models_loaded": models_loaded, "llm": llm, "ws_clients": rt.hub.count()},
        "role": p.role,
    }
