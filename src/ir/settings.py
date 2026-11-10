# -*- coding: utf-8 -*-
"""Typed view of the `ir:` config block (values may arrive as strings from ${VAR:-default})."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


def _b(v: Any, default: bool) -> bool:
    if v is None or v == "":
        return default
    if isinstance(v, bool):
        return v
    return str(v).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class CertInSettings:
    severity_threshold: int = 4
    deadline_hours: float = 6.0
    hash_iocs: bool = False
    org_name: str = "<organisation name>"
    contact_name: str = "<point of contact>"
    contact_email: str = "<contact email>"
    contact_phone: str = "<contact phone>"


@dataclass
class IRSettings:
    database_url: Optional[str] = None
    rollback_ttl_s: int = 600
    rollback_max_attempts: int = 5
    rollback_backoff_s: float = 10.0
    scheduler_interval_s: float = 5.0
    cert_in: CertInSettings = field(default_factory=CertInSettings)

    @classmethod
    def from_config(cls, config: Optional[Dict[str, Any]]) -> "IRSettings":
        ir = dict((config or {}).get("ir") or {})
        ci = dict(ir.get("cert_in") or {})
        d = CertInSettings()
        return cls(
            database_url=ir.get("database_url") or None,
            rollback_ttl_s=int(ir.get("rollback_ttl_s") or 600),
            rollback_max_attempts=int(ir.get("rollback_max_attempts") or 5),
            rollback_backoff_s=float(ir.get("rollback_backoff_s") or 10.0),
            scheduler_interval_s=float(ir.get("scheduler_interval_s") or 5.0),
            cert_in=CertInSettings(
                severity_threshold=int(ci.get("severity_threshold") or d.severity_threshold),
                deadline_hours=float(ci.get("deadline_hours") or d.deadline_hours),
                hash_iocs=_b(ci.get("hash_iocs"), d.hash_iocs),
                org_name=str(ci.get("org_name") or d.org_name),
                contact_name=str(ci.get("contact_name") or d.contact_name),
                contact_email=str(ci.get("contact_email") or d.contact_email),
                contact_phone=str(ci.get("contact_phone") or d.contact_phone),
            ),
        )
