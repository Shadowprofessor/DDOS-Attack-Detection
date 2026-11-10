# -*- coding: utf-8 -*-
"""Wires the IR components together: DB, service, playbooks, rollback + CERT-In scheduler, WS hub."""
from __future__ import annotations

import asyncio
import json
import logging
import threading
from typing import Any, Optional, Set, Tuple

from src.ir.cert_in import CertInMonitor
from src.ir.db import IRDatabase, database_url_from_config
from src.ir.lifecycle import IncidentService
from src.ir.playbooks import load_playbooks
from src.ir.replay import ReplayEngine
from src.ir.rollback import RollbackScheduler
from src.ir.settings import IRSettings

logger = logging.getLogger("ir.runtime")


class IncidentHub:
    """Server->client fan-out for /ws/incidents. `publish()` is safe to call from any thread."""

    def __init__(self):
        self._conns: Set[Tuple[Any, asyncio.AbstractEventLoop]] = set()
        self._lock = threading.Lock()

    def add(self, ws, loop) -> None:
        with self._lock:
            self._conns.add((ws, loop))

    def remove(self, ws) -> None:
        with self._lock:
            self._conns = {c for c in self._conns if c[0] is not ws}

    def count(self) -> int:
        with self._lock:
            return len(self._conns)

    def publish(self, event: dict) -> None:
        text = json.dumps(event, default=str)
        with self._lock:
            conns = list(self._conns)
        for ws, loop in conns:
            if loop.is_closed():
                self.remove(ws)
                continue
            try:
                asyncio.run_coroutine_threadsafe(ws.send_text(text), loop)
            except RuntimeError:
                self.remove(ws)


class IRRuntime:
    def __init__(self, config: Optional[dict] = None, database_url: Optional[str] = None, clock=None,
                 manager_factory=None):
        self.settings = IRSettings.from_config(config)
        self.db = IRDatabase(database_url or database_url_from_config(config))
        self.hub = IncidentHub()
        kw = {"clock": clock} if clock else {}
        self.service = IncidentService(self.db, self.settings, publish=self.hub.publish,
                                       manager_factory=manager_factory, **kw)
        self.playbooks = load_playbooks()
        self.rollback = RollbackScheduler(self.service)
        self.cert_in = CertInMonitor(self.service)
        self.replay = ReplayEngine(self.service)

    def start(self) -> None:
        self.rollback.start(extra_tick=self.cert_in.check)

    def stop(self) -> None:
        self.rollback.stop()

    def close(self) -> None:
        self.stop()
        self.db.dispose()


_runtime: Optional[IRRuntime] = None
_runtime_lock = threading.Lock()


def get_ir_runtime() -> IRRuntime:
    global _runtime
    with _runtime_lock:
        if _runtime is None:
            from src.config.loader import get_config
            try:
                cfg = get_config()
            except Exception:  # config problems must not take the scoring API down
                cfg = {}
            _runtime = IRRuntime(cfg)
        return _runtime


def set_ir_runtime(rt: Optional[IRRuntime]) -> None:
    """Swap the process runtime (tests). Closes the previous one."""
    global _runtime
    with _runtime_lock:
        if _runtime is not None and _runtime is not rt:
            _runtime.close()
        _runtime = rt
