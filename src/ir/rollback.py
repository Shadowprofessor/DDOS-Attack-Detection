# -*- coding: utf-8 -*-
"""
Auto-rollback of human-approved blocks linked to incidents.

* `sync()`   — an incident-linked action that a human approved (manager status EXECUTED) gets
               rollback_at = approved_at + ttl (per-action ttl, else `ir.rollback_ttl_s`, 600 s).
* `tick()`   — due rollbacks call `PendingActionManager.revert()` (removes the block; never
               creates one). Failures are retried with exponential backoff, recorded as incident
               events and counted; after `rollback_max_attempts` the link is marked `failed`.
* `extend()` — admin-only (enforced in the API): push rollback_at out, or make it permanent,
               always with a reason.

All state lives in the DB, so a fresh scheduler after a restart picks up where the old one left off.
"""
from __future__ import annotations

import logging
import threading
from typing import List, Optional

from sqlalchemy import select

from src.ir.lifecycle import NotFound, ValidationFailed
from src.ir.models import Incident, IncidentAction
from src.obs import metrics as obs_metrics
from src.obs.logging import log_safe

logger = logging.getLogger("ir.rollback")

ROLLBACK_ACTOR = "system:auto_rollback"


class RollbackScheduler:
    def __init__(self, service):
        self.service = service
        self.settings = service.settings
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------ core
    def sync(self) -> int:
        """Schedule rollbacks for newly approved linked actions. Returns how many were scheduled."""
        n = 0
        with self.service._lock, self.service.db.session() as s:
            links = s.scalars(select(IncidentAction).where(IncidentAction.rollback_state == "linked")).all()
            for link in links:
                inc = s.get(Incident, link.incident_id)
                action = self.service.manager_for(inc).get_action(link.action_id)
                if not action or action.get("status") != "EXECUTED":
                    continue
                approved_at = float(action.get("approved_at") or self.service.clock())
                ttl = link.ttl_s or self.settings.rollback_ttl_s
                link.approved_at = approved_at
                link.rollback_at = approved_at + ttl
                link.next_attempt_at = link.rollback_at
                link.rollback_state = "scheduled"
                self.service._append(s, inc, ROLLBACK_ACTOR, "rollback_scheduled",
                                     {"action_id": link.action_id, "approver": action.get("approver"),
                                      "ttl_s": ttl, "rollback_at": link.rollback_at})
                n += 1
            s.commit()
        return n

    def tick(self) -> List[dict]:
        self.sync()
        now = self.service.clock()
        results: List[dict] = []
        with self.service._lock, self.service.db.session() as s:
            due = s.scalars(select(IncidentAction).where(IncidentAction.rollback_state == "scheduled",
                                                         IncidentAction.next_attempt_at <= now)).all()
            for link in due:
                inc = s.get(Incident, link.incident_id)
                mgr = self.service.manager_for(inc)
                action = mgr.get_action(link.action_id)
                if action and action.get("status") == "ROLLED_BACK":  # reverted elsewhere
                    ok, msg = True, "already rolled back"
                else:
                    try:
                        ok, msg, _ = mgr.revert(link.action_id, actor=ROLLBACK_ACTOR,
                                                reason=f"TTL expired ({inc.id})")
                    except Exception as e:  # enforcer crashed: treat as a failed attempt
                        ok, msg = False, f"revert raised {type(e).__name__}"
                link.attempts += 1
                if ok:
                    link.rollback_state = "rolled_back"
                    link.rolled_back_at = now
                    link.last_error = None
                    obs_metrics.ROLLBACKS.inc(result="success")
                    self.service._append(s, inc, ROLLBACK_ACTOR, "rollback_done",
                                         {"action_id": link.action_id, "attempt": link.attempts})
                    results.append({"type": "rollback.done", "incident_id": inc.id, "action_id": link.action_id})
                else:
                    link.last_error = str(msg)[:500]
                    obs_metrics.ROLLBACKS.inc(result="failure")
                    final = link.attempts >= self.settings.rollback_max_attempts
                    if final:
                        link.rollback_state = "failed"
                        link.next_attempt_at = None
                    else:
                        link.next_attempt_at = now + self.settings.rollback_backoff_s * (2 ** (link.attempts - 1))
                    logger.error("Rollback of action %s failed (attempt %d%s): %s", log_safe(link.action_id),
                                 link.attempts, ", giving up" if final else "", log_safe(msg))
                    self.service._append(s, inc, ROLLBACK_ACTOR, "rollback_failed",
                                         {"action_id": link.action_id, "attempt": link.attempts,
                                          "error": link.last_error, "final": final,
                                          "next_attempt_at": link.next_attempt_at})
                    results.append({"type": "rollback.failed", "incident_id": inc.id,
                                    "action_id": link.action_id, "final": final})
            s.commit()
        for ev in results:
            self.service.publish(ev)
        return results

    # ------------------------------------------------------------------ admin ops
    def status(self, action_id: str) -> dict:
        with self.service.db.session() as s:
            link = s.get(IncidentAction, action_id)
            if link is None:
                raise NotFound(f"action {action_id} is not linked to any incident")
            d = self.service._action_dict(link)
            d["seconds_until_rollback"] = (None if link.rollback_state != "scheduled" or link.rollback_at is None
                                           else link.rollback_at - self.service.clock())
            return d

    def extend(self, action_id: str, actor: str, reason: str, seconds: Optional[int] = None,
               permanent: bool = False) -> dict:
        reason = (reason or "").strip()
        if len(reason) < 5:
            raise ValidationFailed("a reason (>= 5 chars) is required to extend or make a block permanent")
        if not permanent and (seconds is None or seconds <= 0):
            raise ValidationFailed("give positive 'seconds' or permanent=true")
        with self.service._lock, self.service.db.session() as s:
            link = s.get(IncidentAction, action_id)
            if link is None:
                raise NotFound(f"action {action_id} is not linked to any incident")
            if link.rollback_state not in ("scheduled", "linked"):
                raise ValidationFailed(f"cannot extend: rollback state is '{link.rollback_state}'")
            inc = s.get(Incident, link.incident_id)
            if permanent:
                link.rollback_state = "permanent"
                link.permanent_reason = reason
                link.next_attempt_at = None
                detail = {"action_id": action_id, "permanent": True, "reason": reason}
            else:
                if link.rollback_state == "linked":
                    # Not approved yet: store as the TTL to apply when it is.
                    link.ttl_s = (link.ttl_s or self.settings.rollback_ttl_s) + int(seconds)
                    detail = {"action_id": action_id, "ttl_s": link.ttl_s, "reason": reason}
                else:
                    link.rollback_at = (link.rollback_at or self.service.clock()) + int(seconds)
                    link.next_attempt_at = link.rollback_at
                    detail = {"action_id": action_id, "rollback_at": link.rollback_at,
                              "extended_by_s": int(seconds), "reason": reason}
            self.service._append(s, inc, actor, "rollback_extended", detail)
            s.commit()
        return self.status(action_id)

    # ------------------------------------------------------------------ background
    def start(self, interval_s: Optional[float] = None, extra_tick=None) -> None:
        if self._thread and self._thread.is_alive():
            return
        interval = interval_s or self.settings.scheduler_interval_s
        self._stop.clear()

        def loop():
            while not self._stop.wait(interval):
                try:
                    self.tick()
                    if extra_tick:
                        extra_tick()
                except Exception as e:
                    logger.error("IR scheduler tick failed: %s", log_safe(e))

        self._thread = threading.Thread(target=loop, name="ir-scheduler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._thread = None
