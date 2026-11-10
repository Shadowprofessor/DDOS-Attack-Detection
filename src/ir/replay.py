# -*- coding: utf-8 -*-
"""
Replay engine: push a stored incident aggregate through L1 -> L2 -> (mock) L3 into an isolated
replay incident (`is_replay=True`) for demos and regression tests without live traffic.

* L1: the scenario's recorded alert events are re-emitted in order, time-compressed by `speed`.
* L2: the stored ML verdict (+ OOD score) is carried through as recorded.
* L3: the deterministic rule-based analyst (`rule_based_analysis`); never calls the LLM.

Scope note: v4.2.0 replays stored *aggregates*. Re-scoring raw flow captures through the live
L1/L2 detectors is not done here.

Replay incidents use `DryRunActionManager`: playbook steps may "propose" actions, but they land
in an in-memory dry-run queue. The real PendingActionManager is never touched.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from src.agent.schemas import IncidentAggregate

SCENARIO_DIR = Path(__file__).resolve().parent.parent.parent / "replay" / "scenarios"
MAX_REPLAY_WALL_S = 10.0


class DryRunActionManager:
    """In-memory stand-in for PendingActionManager. Records proposals; executes nothing."""

    def __init__(self):
        self._actions: Dict[str, dict] = {}
        self._lock = threading.Lock()

    def propose(self, action_type: str, attacker_ip: str, victim_ip: str, reason: str, **kw: Any) -> str:
        aid = f"dry-{uuid.uuid4().hex[:8]}"
        with self._lock:
            self._actions[aid] = {"action_id": aid, "action_type": action_type, "attacker_ip": attacker_ip,
                                  "victim_ip": victim_ip, "reason": reason, "status": "PENDING",
                                  "dry_run": True, "auto_execute": False, "proposed_at": time.time(),
                                  "source": kw.get("source")}
        return aid

    def get_action(self, action_id: str) -> Optional[dict]:
        with self._lock:
            return self._actions.get(action_id)

    def revert(self, action_id: str, actor: str = "", reason: str = ""):
        with self._lock:
            a = self._actions.get(action_id)
            if not a or a["status"] != "EXECUTED":
                return False, "not executed", a
            a["status"] = "ROLLED_BACK"
            return True, "dry-run revert", a

    def all(self) -> List[dict]:
        with self._lock:
            return list(self._actions.values())

    def clear(self) -> None:
        with self._lock:
            self._actions.clear()


_DRY_RUN = DryRunActionManager()


def get_dry_run_manager() -> DryRunActionManager:
    return _DRY_RUN


def list_scenarios(directory: Path = SCENARIO_DIR) -> List[str]:
    return sorted(p.stem for p in Path(directory).glob("*.json"))


def load_scenario(name: str, directory: Path = SCENARIO_DIR) -> IncidentAggregate:
    if name not in list_scenarios(directory):  # allowlist: no path traversal
        raise KeyError(name)
    data = json.loads((Path(directory) / f"{name}.json").read_text(encoding="utf-8"))
    return IncidentAggregate.model_validate(data)


class ReplayEngine:
    def __init__(self, service, sleep: Callable[[float], None] = time.sleep):
        self.service = service
        self.sleep = sleep

    def replay(self, agg: IncidentAggregate, speed: float = 60.0, actor: str = "replay",
               scenario: Optional[str] = None) -> Dict[str, Any]:
        from src.agent.threat_analyst import rule_based_analysis

        speed = max(1.0, float(speed))
        stages: List[dict] = []
        # L1: re-emit recorded alerts, time-compressed and capped in wall time.
        alerts = sorted(agg.alert_history, key=lambda a: a.ts)
        budget = MAX_REPLAY_WALL_S
        prev = alerts[0].ts if alerts else None
        for a in alerts:
            delay = min(max(0.0, (a.ts - prev) / speed), budget)
            if delay:
                self.sleep(delay)
                budget -= delay
            prev = a.ts
            stages.append({"layer": "L1", "rule": a.rule, "source_layer": a.layer, "ts": a.ts})
            self.service.publish({"type": "replay.alert", "incident_id": agg.incident_id,
                                  "layer": a.layer, "rule": a.rule})
        # L2: stored verdict.
        if agg.ml:
            stages.append({"layer": "L2", "label": agg.ml.label, "confidence": agg.ml.confidence,
                           "ood_score": agg.ml.ood_score})
        # L3: deterministic mock analyst (no LLM call in replay).
        analysis = rule_based_analysis(agg)
        stages.append({"layer": "L3", "attack_type": analysis.attack_type, "severity": analysis.severity,
                       "source": "rules"})
        result = {"analysis": analysis.model_dump(), "source": "rules", "prompt_version": "replay",
                  "degraded": True, "degraded_reason": "replay uses the rule-based analyst (mock L3)"}
        inc = self.service.create_incident(
            title=f"[REPLAY] {analysis.attack_type}" + (f" ({scenario})" if scenario else ""),
            severity=analysis.severity, actor=actor, aggregate=agg.model_dump(), analysis=result,
            source_alert_ids=[f"{a.layer}:{a.rule}" for a in alerts][:50],
            detected_at=self.service.clock(), is_replay=True,
        )
        return {"incident": inc, "stages": stages, "speed": speed}
