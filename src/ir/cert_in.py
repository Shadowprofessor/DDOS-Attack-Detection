# -*- coding: utf-8 -*-
"""
CERT-In 6-hour reporting timer and report-draft generator.

Source: CERT-In Directions under section 70B(6) of the IT Act, 2000, No. 20(3)/2022-CERT-In,
28 April 2022 — https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf
(incidents listed in Annexure I, which includes DoS/DDoS attacks, must be reported within
6 hours of noticing them).

The draft is a DRAFT. Nothing here ever submits to CERT-In; a human reviews and sends it.
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from sqlalchemy import select

from src.ir.models import Incident
from src.ir.settings import CertInSettings
from src.obs import metrics as obs_metrics

logger = logging.getLogger("ir.cert_in")

CERT_IN_SOURCE_URL = "https://www.cert-in.org.in/PDF/CERT-In_Directions_70B_28.04.2022.pdf"
# (label, seconds-remaining threshold). "breach" fires at <= 0.
WARNINGS = (("1h", 3600.0), ("15m", 900.0), ("breach", 0.0))


def compute_deadline(severity: int, detected_at: float, cfg: CertInSettings) -> Optional[float]:
    if severity < cfg.severity_threshold:
        return None
    return detected_at + cfg.deadline_hours * 3600.0


def _iso(ts: Optional[float]) -> Optional[str]:
    return None if ts is None else datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


class CertInMonitor:
    """Call `check()` periodically. Fires each warning once per incident (persisted)."""

    def __init__(self, service, publish: Optional[Callable[[dict], None]] = None):
        self.service = service
        self._publish = publish or service.publish

    def check(self) -> List[dict]:
        now = self.service.clock()
        fired: List[dict] = []
        with self.service._lock, self.service.db.session() as s:
            rows = s.scalars(select(Incident).where(Incident.cert_in_deadline.is_not(None))).all()
            for inc in rows:
                done = inc.cert_in_reported_at is not None or inc.status in ("closed", "false_positive")
                if done:
                    obs_metrics.CERT_IN_REMAINING.remove(incident=inc.id)
                    continue
                remaining = inc.cert_in_deadline - now
                obs_metrics.CERT_IN_REMAINING.set(remaining, incident=inc.id)
                already = list(inc.cert_in_warnings or [])
                for label, threshold in WARNINGS:
                    if remaining <= threshold and label not in already:
                        already.append(label)
                        detail = {"warning": label, "seconds_remaining": round(remaining, 1),
                                  "deadline": _iso(inc.cert_in_deadline)}
                        self.service._append(s, inc, "system:cert_in", "cert_in_warning", detail)
                        fired.append({"type": "cert_in.warning", "incident_id": inc.id, **detail})
                inc.cert_in_warnings = already
            s.commit()
        for ev in fired:
            try:
                self._publish(ev)
            except Exception as e:
                logger.debug("CERT-In warning subscriber failed: %s", type(e).__name__)
        return fired


def mark_reported(service, incident_id: str, actor: str, reference: str) -> dict:
    from src.ir.lifecycle import ValidationFailed
    ref = (reference or "").strip()
    if len(ref) < 3:
        raise ValidationFailed("a CERT-In acknowledgement / reference is required")
    with service._lock, service.db.session() as s:
        inc = service._load(s, incident_id)
        if inc.cert_in_deadline is None:
            raise ValidationFailed("incident is below the CERT-In reporting threshold")
        inc.cert_in_reported_at = service.clock()
        service._append(s, inc, actor, "cert_in_reported", {"reference": ref})
        s.commit()
    obs_metrics.CERT_IN_REMAINING.remove(incident=incident_id)
    return service.get(incident_id, full=False)


def _ioc(value: str, hash_iocs: bool) -> str:
    if not hash_iocs:
        return value
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def build_draft(incident: Dict[str, Any], cfg: CertInSettings, now: float) -> Dict[str, Any]:
    """Fill the CERT-In incident-report fields from an incident dict (service.get(full=True))."""
    agg = incident.get("aggregate") or {}
    analysis = ((incident.get("analysis") or {}).get("analysis")) or {}
    iocs = [_ioc(s.get("key", ""), cfg.hash_iocs) for s in (agg.get("top_src_ips") or []) if s.get("key")]
    actions = []
    for a in incident.get("actions") or []:
        actions.append({"action_id": a["action_id"], "rollback_state": a["rollback_state"],
                        "approved_at": _iso(a.get("approved_at"))})
    taken = [e for e in incident.get("events") or [] if e["kind"] in ("transition", "playbook_step")]
    deadline = incident.get("cert_in_deadline")
    return {
        "draft": True,
        "notice": "DRAFT for human review. Not submitted to CERT-In. Verify every field before sending.",
        "legal_basis": "CERT-In Directions u/s 70B(6) IT Act 2000, No. 20(3)/2022-CERT-In, 28.04.2022",
        "source_url": CERT_IN_SOURCE_URL,
        "reporting_deadline": _iso(deadline),
        "seconds_remaining": None if deadline is None else round(deadline - now, 1),
        "reporting_entity": {"organisation": cfg.org_name, "contact_name": cfg.contact_name,
                             "contact_email": cfg.contact_email, "contact_phone": cfg.contact_phone},
        "incident": {
            "internal_id": incident["id"],
            "title": incident["title"],
            "type_of_incident": "Denial of Service (DoS) / Distributed Denial of Service (DDoS) attack",
            "attack_vector": analysis.get("attack_type") or incident.get("attack_family"),
            "mitre_attack": analysis.get("mitre_ids") or [],
            "severity_internal_1_to_5": incident["severity"],
            "time_of_detection": incident.get("detected_at_iso"),
            "time_of_occurrence": _iso(agg.get("window_start")) if agg.get("window_start") else None,
            "current_status": incident["status"],
        },
        "affected_systems": {"ip_addresses": list(agg.get("dst_ips") or []),
                             "ports": [p.get("key") for p in agg.get("dst_ports") or []]},
        "indicators_of_compromise": {"source_ips": iocs, "hashed": cfg.hash_iocs,
                                     "peak_pps": agg.get("pps"), "peak_bps": agg.get("bps"),
                                     "unique_sources": agg.get("unique_src_ips")},
        "actions_taken": {"mitigations": actions, "timeline": taken},
        "description": analysis.get("report_summary") or incident["title"],
        "ai_generated_fields": ["attack_vector", "mitre_attack", "description"] if analysis else [],
    }
