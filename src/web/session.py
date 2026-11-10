# -*- coding: utf-8 -*-
"""
Server-side sessions for the SOC web app.

Login exchanges an API key for an opaque session id held in an HttpOnly, Secure, SameSite=Strict
cookie. The key never goes back to the browser. Each session carries a synchroniser CSRF token
that state-changing requests must echo in `X-CSRF-Token`. Every login mints a fresh id (rotation);
sessions expire after `idle_s` of inactivity or `absolute_s` total. The role is re-resolved from
the stored key on every request, so revoking a key takes effect immediately.
"""
from __future__ import annotations

import hmac
import os
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional

COOKIE_NAME = "ddos_session"
CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass
class Session:
    sid: str
    key: str
    csrf: str
    created_at: float
    last_seen: float = field(default=0.0)


class SessionStore:
    def __init__(self, idle_s: float = 1800.0, absolute_s: float = 8 * 3600.0,
                 clock: Callable[[], float] = time.time, max_sessions: int = 1000):
        self.idle_s = idle_s
        self.absolute_s = absolute_s
        self.clock = clock
        self.max_sessions = max_sessions
        self._s: Dict[str, Session] = {}
        self._lock = threading.Lock()

    def _expired(self, s: Session, now: float) -> bool:
        return now - s.last_seen > self.idle_s or now - s.created_at > self.absolute_s

    def create(self, key: str, replace_sid: Optional[str] = None) -> Session:
        now = self.clock()
        with self._lock:
            if replace_sid:
                self._s.pop(replace_sid, None)
            for sid in [k for k, v in self._s.items() if self._expired(v, now)]:
                del self._s[sid]
            if len(self._s) >= self.max_sessions:  # bound memory: drop the oldest
                oldest = min(self._s.values(), key=lambda v: v.last_seen)
                del self._s[oldest.sid]
            s = Session(sid=secrets.token_urlsafe(32), key=key, csrf=secrets.token_urlsafe(32),
                        created_at=now, last_seen=now)
            self._s[s.sid] = s
            return s

    def get(self, sid: Optional[str]) -> Optional[Session]:
        if not sid:
            return None
        now = self.clock()
        with self._lock:
            s = self._s.get(sid)
            if s is None:
                return None
            if self._expired(s, now):
                del self._s[sid]
                return None
            s.last_seen = now
            return s

    def delete(self, sid: Optional[str]) -> None:
        if sid:
            with self._lock:
                self._s.pop(sid, None)

    def clear(self) -> None:
        with self._lock:
            self._s.clear()

    @staticmethod
    def csrf_ok(s: Session, presented: Optional[str]) -> bool:
        return bool(presented) and hmac.compare_digest(s.csrf, presented)


_store = SessionStore(idle_s=float(os.environ.get("DDOS_SESSION_IDLE_S", "1800")),
                      absolute_s=float(os.environ.get("DDOS_SESSION_ABSOLUTE_S", str(8 * 3600))))


def get_session_store() -> SessionStore:
    return _store
