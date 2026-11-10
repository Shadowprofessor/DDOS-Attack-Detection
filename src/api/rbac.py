# -*- coding: utf-8 -*-
"""
Role-based access for the IR API. Deny by default.

* `DDOS_API_KEYS`   -> role `analyst`
* `DDOS_ADMIN_KEYS` -> role `admin` (superset of analyst)

Missing/unknown key -> 401. Known key with too little privilege -> 403.
Actors are recorded as `<role>:<pbkdf2(key)[:8]>` so no key material lands in timelines/exports.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from functools import lru_cache
from typing import Optional

from fastapi import Depends, HTTPException, Request

ROLE_RANK = {"analyst": 1, "admin": 2}

# Lifecycle targets an analyst may move an incident to; everything else needs admin.
ANALYST_TRANSITIONS = frozenset({"triage", "investigating"})


@dataclass(frozen=True)
class Principal:
    role: str
    fingerprint: str

    @property
    def actor(self) -> str:
        return f"{self.role}:{self.fingerprint}"

    def has(self, role: str) -> bool:
        return ROLE_RANK.get(self.role, 0) >= ROLE_RANK[role]


def role_for_key(key: Optional[str]) -> Optional[str]:
    if not key:
        return None
    from src.api.scoring_service import _get_valid_admin_keys, _get_valid_api_keys  # lazy: avoid cycle

    if key in _get_valid_admin_keys():
        return "admin"
    if key in _get_valid_api_keys():
        return "analyst"
    return None


def principal_for_key(key: Optional[str]) -> Optional[Principal]:
    role = role_for_key(key)
    if role is None:
        return None
    return Principal(role=role, fingerprint=key_fingerprint(key))


@lru_cache(maxsize=256)
def key_fingerprint(key: str) -> str:
    """Stable, non-reversible 8-hex-char actor id for a key (PBKDF2, cached per key)."""
    return hashlib.pbkdf2_hmac("sha256", key.encode("utf-8"), b"ddos-actor-fingerprint-v1", 100_000).hex()[:8]


def current_principal(request: Request) -> Principal:
    key = request.headers.get("X-Admin-Key") or request.headers.get("X-API-Key")
    if not key:
        raise HTTPException(status_code=401, detail="Missing API credentials.")
    p = principal_for_key(key)
    if p is None:
        raise HTTPException(status_code=401, detail="Invalid API key.")
    return p


def require_analyst(p: Principal = Depends(current_principal)) -> Principal:
    return p


def require_admin(p: Principal = Depends(current_principal)) -> Principal:
    if not p.has("admin"):
        raise HTTPException(status_code=403, detail="Insufficient privileges: admin role required.")
    return p
