# -*- coding: utf-8 -*-
"""
Layer-3 analyst API.

* ``POST /api/analyst/analyze`` — analyse ONE aggregated incident (``IncidentAggregate``) and
  return a validated, policy-enforced ``AnalysisResult``. Recommendations only: this router has
  no path to ``PendingActionManager`` or any enforcer.
* ``GET  /api/analyst/config`` — non-secret analyst configuration (model chain, prompt version).

Both require an API key. Analysis is rate-limited per key (``DDOS_ANALYST_RATE_PER_MIN``).
Handlers are sync ``def`` so the (tens-of-seconds) LLM call runs in FastAPI's threadpool and
never blocks the event loop.
"""
from __future__ import annotations

import os
import threading
import time
from collections import defaultdict
from typing import Dict, List

from fastapi import APIRouter, Depends, HTTPException, Request

from src.agent.schemas import AnalysisResult, IncidentAggregate

router = APIRouter(prefix="/api/analyst", tags=["analyst"])


class _KeyRateLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self._hits: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            self._hits[key] = [t for t in self._hits[key] if t > now - 60]
            if len(self._hits[key]) >= self.per_minute:
                return False
            self._hits[key].append(now)
            return True


analyst_rate_limiter = _KeyRateLimiter(int(os.environ.get("DDOS_ANALYST_RATE_PER_MIN", "30")))


def require_key(request: Request) -> str:
    """API or admin key. Lazy import avoids a circular import with scoring_service."""
    from src.api.scoring_service import _get_valid_admin_keys, _get_valid_api_keys

    from src.api.rbac import key_from_request
    key = key_from_request(request)  # header key, or SOC web-app session (+CSRF on POST)
    if not key or key not in (_get_valid_api_keys() | _get_valid_admin_keys()):
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return key


@router.post("/analyze", response_model=AnalysisResult)
def analyze_incident(body: IncidentAggregate, key: str = Depends(require_key)) -> AnalysisResult:
    if not analyst_rate_limiter.allow(key):
        raise HTTPException(status_code=429, detail="Analyst rate limit exceeded; retry later.")
    from src.agent.threat_analyst import get_threat_analyst

    return get_threat_analyst().analyze(body)


@router.get("/config")
def analyst_config(key: str = Depends(require_key)) -> dict:
    from src.agent.threat_analyst import get_threat_analyst

    a = get_threat_analyst()
    return {"prompt_version": a.prompt_version, "hash_ips": a.hash_ips,
            "rate_per_min": analyst_rate_limiter.per_minute, **a.client.config.public_view()}
