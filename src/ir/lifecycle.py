# -*- coding: utf-8 -*-
"""
NIST SP 800-61r3 incident lifecycle + tamper-evident timeline.

States: new -> triage -> investigating -> contained -> eradicated -> recovered -> closed,
plus false_positive (-> closed). Transitions are an explicit table; anything else raises
IllegalTransition and writes nothing. Every change appends a hash-chained IncidentEvent.

This module never executes mitigation. Action links only *reference* PendingActionManager IDs.
"""
from __future__ import annotations

import hashlib
import json
import logging
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional

from sqlalchemy import func, select

from src.ir.db import IRDatabase
from src.ir.models import Incident, IncidentAction, IncidentEvent, PlaybookRun
from src.ir.settings import IRSettings
from src.obs import metrics as obs_metrics

STATES = ("new", "triage", "investigating", "contained", "eradicated", "recovered", "closed", "false_positive")

TRANSITIONS: Dict[str, frozenset] = {
    "new": frozenset({"triage", "false_positive"}),
    "triage": frozenset({"investigating", "false_positive"}),
    "investigating": frozenset({"contained", "false_positive"}),
    "contained": frozenset({"eradicated"}),
    "eradicated": frozenset({"recovered"}),
    "recovered": frozenset({"closed"}),
    "false_positive": frozenset({"closed"}),
    "closed": frozenset(),
}

# CSF 2.0 function each state belongs to (documented in docs/IR.md).
CSF_FUNCTION = {
    "new": "Detect", "triage": "Detect", "investigating": "Respond", "contained": "Respond",
    "eradicated": "Respond", "recovered": "Recover", "closed": "Recover", "false_positive": "Detect",
}

logger = logging.getLogger("ir.lifecycle")

OPEN_STATES = frozenset(STATES) - {"closed", "false_positive"}
GENESIS_HASH = "0" * 64
MIN_JUSTIFICATION = 10
# Manager statuses that prove a human approved a mitigation for this incident.
APPROVED_STATUSES = frozenset({"EXECUTED", "ROLLED_BACK"})


class IRError(Exception):
    """Base class; `.status` is the HTTP status the API maps it to."""
    status = 400


class NotFound(IRError):
    status = 404


class IllegalTransition(IRError):
    status = 409


class ValidationFailed(IRError):
    status = 400


def event_hash(incident_id: str, seq: int, ts: float, actor: str, kind: str, detail: Any, prev_hash: str) -> str:
    body = json.dumps(
        {"incident_id": incident_id, "seq": seq, "ts": ts, "actor": actor, "kind": kind,
         "detail": detail, "prev_hash": prev_hash},
        sort_keys=True, separators=(",", ":"), default=str,
    )
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def verify_events(events: Iterable[IncidentEvent]) -> Dict[str, Any]:
    prev = GENESIS_HASH
    n = 0
    for n, ev in enumerate(events, start=1):
        expected = event_hash(ev.incident_id, ev.seq, ev.ts, ev.actor, ev.kind, ev.detail, prev)
        if ev.prev_hash != prev or ev.hash != expected or ev.seq != n:
            return {"ok": False, "events": n, "broken_at": ev.seq}
        prev = ev.hash
    return {"ok": True, "events": n, "broken_at": None}


def _iso(ts: Optional[float]) -> Optional[str]:
    return None if ts is None else datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


class IncidentService:
    def __init__(self, db: IRDatabase, settings: Optional[IRSettings] = None,
                 clock: Callable[[], float] = time.time,
                 publish: Optional[Callable[[dict], None]] = None,
                 manager_factory: Optional[Callable[[], Any]] = None):
        self.db = db
        self.settings = settings or IRSettings()
        self.clock = clock
        self._publish = publish
        self._manager_factory = manager_factory
        self._lock = threading.RLock()

    # ------------------------------------------------------------------ helpers
    def manager_for(self, inc: Incident):
        """Replay incidents get an isolated dry-run manager; never the real queue."""
        if inc.is_replay:
            from src.ir.replay import get_dry_run_manager
            return get_dry_run_manager()
        if self._manager_factory:
            return self._manager_factory()
        from src.mitigation.manager import get_manager
        return get_manager()

    def publish(self, event: dict) -> None:
        if self._publish:
            try:
                self._publish(event)
            except Exception as e:  # a broken subscriber must never break IR writes
                logger.debug("IR event subscriber failed: %s", type(e).__name__)

    def _new_id(self, s, now: float) -> str:
        day = datetime.fromtimestamp(now, tz=timezone.utc).strftime("%Y%m%d")
        for _ in range(20):
            cand = f"INC-{day}-{secrets.token_hex(2)}"
            if s.get(Incident, cand) is None:
                return cand
        raise IRError("could not allocate a unique incident id")

    def _append(self, s, inc: Incident, actor: str, kind: str, detail: Any) -> IncidentEvent:
        last = s.scalar(select(IncidentEvent).where(IncidentEvent.incident_id == inc.id)
                        .order_by(IncidentEvent.seq.desc()).limit(1))
        seq = (last.seq + 1) if last else 1
        prev = last.hash if last else GENESIS_HASH
        ts = self.clock()
        ev = IncidentEvent(incident_id=inc.id, seq=seq, ts=ts, actor=actor, kind=kind, detail=detail,
                           prev_hash=prev, hash=event_hash(inc.id, seq, ts, actor, kind, detail, prev))
        s.add(ev)
        return ev

    def _load(self, s, incident_id: str) -> Incident:
        inc = s.get(Incident, incident_id)
        if inc is None:
            raise NotFound(f"incident {incident_id} not found")
        return inc

    def refresh_state_gauge(self) -> None:
        with self.db.session() as s:
            rows = dict(s.execute(select(Incident.status, func.count()).where(Incident.is_replay.is_(False))
                                  .group_by(Incident.status)).all())
        for st in STATES:
            obs_metrics.INCIDENTS_BY_STATE.set(float(rows.get(st, 0)), state=st)

    # ------------------------------------------------------------------ commands
    def create_incident(self, *, title: str, severity: int, actor: str, attack_family: Optional[str] = None,
                        aggregate: Optional[dict] = None, analysis: Optional[dict] = None,
                        source_alert_ids: Iterable[str] = (), detected_at: Optional[float] = None,
                        is_replay: bool = False) -> dict:
        from src.ir.cert_in import compute_deadline
        from src.ir.playbooks import family_from_text

        if not 1 <= int(severity) <= 5:
            raise ValidationFailed("severity must be 1-5")
        now = self.clock()
        if attack_family is None:
            hint = (analysis or {}).get("analysis", {}).get("attack_type") or \
                   ((aggregate or {}).get("ml") or {}).get("label") or title
            attack_family = family_from_text(hint)
        with self._lock, self.db.session() as s:
            det = float(detected_at) if detected_at is not None else now
            inc = Incident(
                id=self._new_id(s, now), title=title, attack_family=attack_family, severity=int(severity),
                status="new", created_at=now, detected_at=det, source_alert_ids=list(source_alert_ids),
                aggregate_json=aggregate, analysis_json=analysis, is_replay=is_replay,
                cert_in_deadline=None if is_replay else compute_deadline(int(severity), det, self.settings.cert_in),
                cert_in_warnings=[],
            )
            s.add(inc)
            s.flush()
            self._append(s, inc, actor, "created", {"title": title, "severity": int(severity),
                                                    "attack_family": attack_family, "is_replay": is_replay})
            s.commit()
            out = self.to_dict(inc)
        if not is_replay:
            ws = (aggregate or {}).get("window_start")
            if isinstance(ws, (int, float)) and det >= ws:
                obs_metrics.INCIDENT_MTTD.observe(det - ws)
            self.refresh_state_gauge()
        self.publish({"type": "incident.created", "incident": out})
        return out

    def transition(self, incident_id: str, to: str, actor: str, justification: Optional[str] = None) -> dict:
        if to not in STATES:
            raise ValidationFailed(f"unknown state '{to}'")
        with self._lock, self.db.session() as s:
            inc = self._load(s, incident_id)
            frm = inc.status
            if to not in TRANSITIONS[frm]:
                raise IllegalTransition(f"illegal transition {frm} -> {to}")
            detail: Dict[str, Any] = {"from": frm, "to": to}
            if to == "contained":
                approved = self._approved_action_ids(inc)
                just = (justification or "").strip()
                if not approved and len(just) < MIN_JUSTIFICATION:
                    raise ValidationFailed(
                        "containment requires at least one approved action or a written justification "
                        f"(>= {MIN_JUSTIFICATION} chars)")
                detail["approved_actions"] = approved
                if just:
                    detail["justification"] = just
                    inc.containment_justification = just
                inc.contained_at = self.clock()
            elif justification:
                detail["justification"] = justification.strip()
            if to == "closed":
                inc.closed_at = self.clock()
            inc.status = to
            self._append(s, inc, actor, "transition", detail)
            s.commit()
            out = self.to_dict(inc)
        if not out["is_replay"]:
            if to == "contained" and out["contained_at"] is not None:
                obs_metrics.INCIDENT_MTTC.observe(max(0.0, out["contained_at"] - out["detected_at"]))
            self.refresh_state_gauge()
        self.publish({"type": "incident.transition", "incident_id": incident_id, "from": detail["from"], "to": to})
        return out

    def _approved_action_ids(self, inc: Incident) -> List[str]:
        mgr = self.manager_for(inc)
        ids = []
        for link in inc.actions:
            a = mgr.get_action(link.action_id)
            if a and a.get("status") in APPROVED_STATUSES:
                ids.append(link.action_id)
        return ids

    def add_note(self, incident_id: str, actor: str, text: str) -> dict:
        text = (text or "").strip()
        if not text:
            raise ValidationFailed("note text is empty")
        with self._lock, self.db.session() as s:
            inc = self._load(s, incident_id)
            ev = self._append(s, inc, actor, "note", {"text": text})
            s.commit()
            seq = ev.seq
        self.publish({"type": "incident.note", "incident_id": incident_id, "seq": seq})
        return {"incident_id": incident_id, "seq": seq}

    def link_action(self, incident_id: str, action_id: str, actor: str, ttl_s: Optional[int] = None) -> dict:
        with self._lock, self.db.session() as s:
            inc = self._load(s, incident_id)
            if self.manager_for(inc).get_action(action_id) is None:
                raise NotFound(f"action {action_id} not found")
            existing = s.get(IncidentAction, action_id)
            if existing is not None:
                if existing.incident_id != incident_id:
                    raise ValidationFailed(f"action {action_id} is already linked to {existing.incident_id}")
                return self._action_dict(existing)
            link = IncidentAction(action_id=action_id, incident_id=incident_id, linked_at=self.clock(),
                                  linked_by=actor, ttl_s=ttl_s, rollback_state="linked")
            s.add(link)
            self._append(s, inc, actor, "action_linked", {"action_id": action_id})
            s.commit()
            return self._action_dict(link)

    def record_event(self, incident_id: str, actor: str, kind: str, detail: Any) -> None:
        with self._lock, self.db.session() as s:
            inc = self._load(s, incident_id)
            self._append(s, inc, actor, kind, detail)
            s.commit()

    def record_playbook_run(self, incident_id: str, playbook_id: str, step: str, status: str,
                            actor: str, result: dict) -> dict:
        with self._lock, self.db.session() as s:
            inc = self._load(s, incident_id)
            run = PlaybookRun(incident_id=incident_id, playbook_id=playbook_id, step=step, status=status,
                              actor=actor, ts=self.clock(), result=result)
            s.add(run)
            self._append(s, inc, actor, "playbook_step",
                         {"playbook": playbook_id, "step": step, "status": status, **result})
            s.commit()
            return {"id": run.id, "playbook_id": playbook_id, "step": step, "status": status, "result": result}

    # ------------------------------------------------------------------ queries
    def get(self, incident_id: str, full: bool = True) -> dict:
        with self.db.session() as s:
            return self.to_dict(self._load(s, incident_id), full=full)

    SORTS = {
        "created_desc": (Incident.created_at.desc(),),
        "created_asc": (Incident.created_at.asc(),),
        "severity_desc": (Incident.severity.desc(), Incident.created_at.desc()),
        "severity_asc": (Incident.severity.asc(), Incident.created_at.desc()),
    }

    def list(self, status: Optional[str] = None, include_replay: bool = True,
             limit: int = 50, offset: int = 0, sort: str = "created_desc",
             min_severity: Optional[int] = None) -> dict:
        with self.db.session() as s:
            q = select(Incident)
            if status:
                q = q.where(Incident.status == status)
            if not include_replay:
                q = q.where(Incident.is_replay.is_(False))
            if min_severity:
                q = q.where(Incident.severity >= int(min_severity))
            total = s.scalar(select(func.count()).select_from(q.subquery()))
            order = self.SORTS.get(sort, self.SORTS["created_desc"])
            rows = s.scalars(q.order_by(*order).limit(limit).offset(offset)).all()
            return {"total": total, "limit": limit, "offset": offset, "sort": sort,
                    "items": [self.to_dict(r) for r in rows]}

    def verify_chain(self, incident_id: str) -> Dict[str, Any]:
        with self.db.session() as s:
            evs = s.scalars(select(IncidentEvent).where(IncidentEvent.incident_id == incident_id)
                            .order_by(IncidentEvent.seq)).all()
            return verify_events(evs)

    @staticmethod
    def _action_dict(a: IncidentAction) -> dict:
        return {"action_id": a.action_id, "incident_id": a.incident_id, "rollback_state": a.rollback_state,
                "ttl_s": a.ttl_s, "approved_at": a.approved_at, "rollback_at": a.rollback_at,
                "rolled_back_at": a.rolled_back_at, "permanent_reason": a.permanent_reason,
                "attempts": a.attempts, "next_attempt_at": a.next_attempt_at, "last_error": a.last_error,
                "linked_by": a.linked_by, "linked_at": a.linked_at}

    def to_dict(self, inc: Incident, full: bool = False) -> dict:
        d = {
            "id": inc.id, "title": inc.title, "attack_family": inc.attack_family, "severity": inc.severity,
            "status": inc.status, "csf_function": CSF_FUNCTION.get(inc.status), "owner": inc.owner,
            "created_at": inc.created_at, "detected_at": inc.detected_at, "contained_at": inc.contained_at,
            "closed_at": inc.closed_at, "detected_at_iso": _iso(inc.detected_at),
            "cert_in_deadline": inc.cert_in_deadline, "cert_in_reported_at": inc.cert_in_reported_at,
            "cert_in_seconds_remaining": (None if inc.cert_in_deadline is None or inc.cert_in_reported_at
                                          else inc.cert_in_deadline - self.clock()),
            "is_replay": bool(inc.is_replay), "source_alert_ids": list(inc.source_alert_ids or []),
        }
        if full:
            d["aggregate"] = inc.aggregate_json
            d["analysis"] = inc.analysis_json
            d["containment_justification"] = inc.containment_justification
            d["events"] = [{"seq": e.seq, "ts": e.ts, "ts_iso": _iso(e.ts), "actor": e.actor, "kind": e.kind,
                            "detail": e.detail, "hash": e.hash} for e in inc.events]
            d["actions"] = [self._action_dict(a) for a in inc.actions]
            d["playbook_runs"] = [{"playbook_id": r.playbook_id, "step": r.step, "status": r.status,
                                   "actor": r.actor, "ts": r.ts, "result": r.result} for r in inc.playbook_runs]
            d["chain"] = verify_events(inc.events)
            d["allowed_transitions"] = sorted(TRANSITIONS[inc.status])
        return d
