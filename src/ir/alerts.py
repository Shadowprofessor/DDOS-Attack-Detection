# -*- coding: utf-8 -*-
"""SOC alerts (v6.0.0): IR events -> deduplicated, rate-limited alerts for the web app, plus an
optional outbound webhook (Discord / Slack / Telegram / generic JSON).

* Alerts only TELL people. Nothing here proposes, approves or executes a mitigation.
* The webhook is OFF unless `DDOS_ALERT_WEBHOOK_URL` is set in the environment (never in the repo).
  The URL is treated as a secret: it is never logged or returned by the API.
* Dedupe: the same alert key within `dedupe_s` is counted, not re-sent.
* Rate limit: at most `rate_per_min` alerts per rolling minute; extra ones are counted and reported
  in the next alert that gets through. A CERT-In deadline breach is never rate-limited.
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import urllib.request
from collections import deque
from datetime import datetime, timezone
from typing import Callable, Deque, Dict, List, Optional
from urllib.parse import urlparse

from src.obs import metrics as obs_metrics

logger = logging.getLogger("ir.alerts")

ALERT_EVENTS = obs_metrics.REGISTRY.counter("ddos_soc_alerts_total", "SOC alerts by kind and outcome.")
WEBHOOK_SENDS = obs_metrics.REGISTRY.counter("ddos_alert_webhook_total", "Alert webhook posts by outcome.")

DISCORD_HOSTS = frozenset({"discord.com", "discordapp.com", "ptb.discord.com", "canary.discord.com"})
LEVELS = {5: "critical", 4: "high", 3: "medium", 2: "low", 1: "low", 0: "info"}
_CTRL = re.compile(r"[\x00-\x1f\x7f]+")


def level_for(severity: int) -> str:
    return LEVELS.get(max(0, min(5, int(severity))), "info")


def clean(text: Optional[str], limit: int = 300) -> str:
    """Telemetry-derived text is untrusted: strip control chars, collapse whitespace, cap length,
    and defuse chat mentions (@everyone, <@id>) before it reaches the UI or a webhook."""
    t = _CTRL.sub(" ", str(text or "")).strip()
    t = re.sub(r"\s+", " ", t).replace("@", "(at)")
    return t[:limit]


def _hhmm(ts: Optional[float]) -> str:
    return "" if ts is None else datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%H:%M UTC")


class WebhookSender:
    """Posts one alert to the configured URL in a background thread (5 s timeout)."""

    def __init__(self, url: str, telegram_chat_id: Optional[str] = None, min_severity: int = 4,
                 post: Optional[Callable[[str, bytes], int]] = None):
        u = urlparse(url)
        if u.scheme != "https" or not u.netloc:
            raise ValueError("DDOS_ALERT_WEBHOOK_URL must be an https:// URL")
        self.url, self.host = url, u.netloc.lower()
        self.telegram_chat_id = telegram_chat_id
        self.min_severity = min_severity
        self._post = post or self._urllib_post

    @property
    def kind(self) -> str:
        if self.host in DISCORD_HOSTS:  # exact hostnames, never a suffix match
            return "discord"
        if self.host == "hooks.slack.com":
            return "slack"
        if self.host == "api.telegram.org":
            return "telegram"
        return "generic"

    def payload(self, alert: dict) -> dict:
        text = f"[{alert['level'].upper()}] {alert['title']}"
        if alert.get("reason"):
            text += f"\n{alert['reason']}"
        if alert.get("incident_id"):
            text += f"\nIncident {alert['incident_id']}"
        if alert.get("suppressed"):
            text += f"\n(+{alert['suppressed']} similar alerts suppressed)"
        k = self.kind
        if k == "discord":
            return {"content": text[:1900], "allowed_mentions": {"parse": []}}
        if k == "slack":
            return {"text": text[:3000]}
        if k == "telegram":
            return {"chat_id": self.telegram_chat_id, "text": text[:4000], "disable_web_page_preview": True}
        return {"text": text, "alert": alert}

    @staticmethod
    def _urllib_post(url: str, body: bytes) -> int:
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/json", "User-Agent": "ddos-soc-alerts"})
        with urllib.request.urlopen(req, timeout=5) as r:  # nosec B310 - https enforced above
            return r.status

    def wants(self, alert: dict) -> bool:
        return alert["severity"] >= self.min_severity and alert["kind"] != "analysis"

    def send(self, alert: dict, background: bool = True) -> None:
        if not self.wants(alert):
            return
        if self.kind == "telegram" and not self.telegram_chat_id:
            WEBHOOK_SENDS.inc(outcome="misconfigured")
            return
        body = json.dumps(self.payload(alert)).encode("utf-8")

        def go():
            try:
                status = self._post(self.url, body)
                WEBHOOK_SENDS.inc(outcome="ok" if 200 <= status < 300 else "http_error")
            except Exception as e:  # never log the URL: it is a secret
                WEBHOOK_SENDS.inc(outcome="error")
                logger.warning("alert webhook (%s) failed: %s", self.kind, type(e).__name__)

        if background:
            threading.Thread(target=go, name="alert-webhook", daemon=True).start()
        else:
            go()

    @classmethod
    def from_env(cls, env=os.environ) -> Optional["WebhookSender"]:
        url = (env.get("DDOS_ALERT_WEBHOOK_URL") or "").strip()
        if not url:
            return None
        try:
            return cls(url, telegram_chat_id=(env.get("DDOS_ALERT_TELEGRAM_CHAT_ID") or "").strip() or None,
                       min_severity=int(env.get("DDOS_ALERT_WEBHOOK_MIN_SEVERITY") or 4))
        except ValueError as e:
            logger.warning("alert webhook disabled: %s", e)
            return None


class AlertEngine:
    def __init__(self, publish: Callable[[dict], None], clock: Callable[[], float] = time.time,
                 webhook: Optional[WebhookSender] = None, dedupe_s: float = 120.0, rate_per_min: int = 10,
                 keep: int = 100):
        self._publish, self.clock, self.webhook = publish, clock, webhook
        self.dedupe_s, self.rate_per_min = dedupe_s, rate_per_min
        self._lock = threading.Lock()
        self._last: Dict[str, float] = {}
        self._sent: Deque[float] = deque()
        self._suppressed = 0
        self._seq = 0
        self.recent: Deque[dict] = deque(maxlen=keep)

    # -------------------------------------------------------------- mapping
    @staticmethod
    def from_event(ev: dict) -> Optional[dict]:
        t = ev.get("type")
        if t == "incident.created":
            inc = ev.get("incident") or {}
            if inc.get("is_replay"):
                return None
            sev = int(inc.get("severity") or 3)
            reason = ev.get("reason") or ""
            if inc.get("cert_in_deadline"):
                reason = (reason + " " if reason else "") + f"CERT-In report due by {_hhmm(inc['cert_in_deadline'])} (6 h)."
            return {"kind": "incident", "severity": sev, "title": inc.get("title") or "New incident",
                    "reason": reason, "incident_id": inc.get("id"),
                    "key": f"incident:{re.sub(r'[0-9a-f]{8,}', '', str(inc.get('title')))}"}
        if t == "cert_in.warning":
            label = ev.get("warning")
            sev, title = {"started": (3, "CERT-In 6 h reporting clock started"),
                          "1h": (4, "CERT-In report due in 1 hour"),
                          "15m": (5, "CERT-In report due in 15 minutes"),
                          "breach": (5, "CERT-In 6 h reporting deadline missed")}.get(label, (4, "CERT-In timer"))
            return {"kind": "cert_in", "severity": sev, "title": title, "incident_id": ev.get("incident_id"),
                    "reason": f"Deadline {_hhmm_iso(ev.get('deadline'))}. Draft the report from the incident page; "
                              "a human submits it.",
                    "key": f"cert_in:{ev.get('incident_id')}:{label}", "critical": label == "breach"}
        if t == "incident.analysis" and ev.get("attack_type"):
            return {"kind": "analysis", "severity": 0, "title": f"AI analyst: {ev['attack_type']}",
                    "reason": ev.get("reason") or "", "incident_id": ev.get("incident_id"),
                    "key": f"analysis:{ev.get('incident_id')}:{ev.get('attack_type')}"}
        if t == "alert.test":
            return {"kind": "test", "severity": 3, "title": "Test alert",
                    "reason": "Sent from Settings to check toasts, sound, browser notifications and the webhook.",
                    "incident_id": None, "key": "test"}
        if t == "rollback.failed":
            return {"kind": "rollback", "severity": 4, "title": "Auto-rollback of a block FAILED",
                    "reason": "An approved block could not be rolled back; check the Approvals page.",
                    "incident_id": ev.get("incident_id"), "key": f"rollback:{ev.get('action_id')}"}
        return None

    # -------------------------------------------------------------- pipeline
    def observe(self, ev: dict) -> Optional[dict]:
        try:
            a = self.from_event(ev)
        except Exception as e:  # an alert bug must never break IR writes
            logger.debug("alert mapping failed: %s", type(e).__name__)
            return None
        if a is None:
            return None
        now = self.clock()
        with self._lock:
            key = a.pop("key")
            critical = a.pop("critical", False)
            last = self._last.get(key)
            if last is not None and now - last < self.dedupe_s:
                ALERT_EVENTS.inc(kind=a["kind"], outcome="deduped")
                return None
            while self._sent and now - self._sent[0] >= 60.0:
                self._sent.popleft()
            if len(self._sent) >= self.rate_per_min and not critical:
                self._suppressed += 1
                ALERT_EVENTS.inc(kind=a["kind"], outcome="rate_limited")
                return None
            self._last[key] = now
            self._sent.append(now)
            self._seq += 1
            a.update(id=f"al-{int(now)}-{self._seq}", ts=now, level=level_for(a["severity"]),
                     title=clean(a["title"], 200), reason=clean(a.get("reason")),
                     sound=a["severity"] >= 3, suppressed=self._suppressed)
            self._suppressed = 0
            self.recent.appendleft(a)
        ALERT_EVENTS.inc(kind=a["kind"], outcome="sent")
        try:
            self._publish({"type": "alert", "alert": a})
        except Exception as e:
            logger.debug("alert publish failed: %s", type(e).__name__)
        if self.webhook is not None:
            self.webhook.send(a)
        return a

    def list(self, limit: int = 50) -> List[dict]:
        with self._lock:
            return list(self.recent)[:limit]


def _hhmm_iso(iso: Optional[str]) -> str:
    try:
        return _hhmm(datetime.fromisoformat(str(iso)).timestamp())
    except Exception:
        return "unknown"
