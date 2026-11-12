# -*- coding: utf-8 -*-
"""v6.0.0 SOC alerts: mapping, dedupe, rate limit, sanitising, webhook formats (off by default), API."""
import ast
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import src.api.scoring_service as api_module
from src.api.scoring_service import app
from src.ir.alerts import AlertEngine, WebhookSender, clean
from src.ir.runtime import IRRuntime, set_ir_runtime
from src.mitigation.manager import PendingActionManager

ANALYST = {"X-API-Key": "al-analyst-key"}
ADMIN = {"X-Admin-Key": "al-admin-key"}
HOOK = "https://discord.com/api/webhooks/123/SECRET-TOKEN"


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def incident_ev(title="[LIVE] L1 SYN Flood toward 10.99.0.10", sev=4, iid="INC-1", deadline=None, reason="SYN 50%"):
    return {"type": "incident.created", "reason": reason,
            "incident": {"id": iid, "title": title, "severity": sev, "is_replay": False, "cert_in_deadline": deadline}}


def engine(**kw):
    out, clk = [], kw.pop("clock", Clock())
    return AlertEngine(out.append, clock=clk, **kw), out, clk


def test_incident_alert_has_reason_level_sound_and_cert_in_deadline():
    eng, out, _ = engine()
    a = eng.observe(incident_ev(deadline=1000.0 + 6 * 3600))
    assert out == [{"type": "alert", "alert": a}]
    assert a["level"] == "high" and a["sound"] is True and a["kind"] == "incident"
    assert a["reason"].startswith("SYN 50%") and "CERT-In report due by" in a["reason"] and "(6 h)" in a["reason"]


def test_replay_incidents_and_unrelated_events_do_not_alert():
    eng, out, _ = engine()
    ev = incident_ev()
    ev["incident"]["is_replay"] = True
    assert eng.observe(ev) is None
    assert eng.observe({"type": "incident.note", "incident_id": "x"}) is None
    assert eng.observe({"type": "incident.analysis", "incident_id": "x"}) is None  # no verdict yet
    assert out == []


def test_dedupe_same_alert_within_window_then_again_after():
    eng, out, clk = engine(dedupe_s=120)
    assert eng.observe(incident_ev(iid="A"))
    clk.t += 30
    assert eng.observe(incident_ev(iid="B")) is None  # same attack re-opened: deduped
    clk.t += 100
    assert eng.observe(incident_ev(iid="C"))
    assert len(out) == 2


def test_rate_limit_counts_suppressed_and_never_drops_a_cert_in_breach():
    eng, out, clk = engine(rate_per_min=3)
    for i in range(5):
        eng.observe(incident_ev(title=f"flood {i}", iid=f"I{i}"))
    assert len(out) == 3
    breach = eng.observe({"type": "cert_in.warning", "incident_id": "I0", "warning": "breach",
                          "deadline": "2026-11-13T07:00:00+00:00"})
    assert breach and breach["level"] == "critical" and breach["suppressed"] == 2
    clk.t += 61
    nxt = eng.observe(incident_ev(title="later", iid="L"))
    assert nxt and nxt["suppressed"] == 0


def test_cert_in_warnings_map_to_rising_severity():
    eng, _, _ = engine()
    sev = {w: eng.observe({"type": "cert_in.warning", "incident_id": "I", "warning": w,
                           "deadline": "2026-11-13T07:00:00+00:00"})["severity"] for w in ("1h", "15m", "breach")}
    assert sev == {"1h": 4, "15m": 5, "breach": 5}


def test_analysis_alert_is_info_without_sound():
    eng, _, _ = engine()
    a = eng.observe({"type": "incident.analysis", "incident_id": "I", "attack_type": "UDP flood", "reason": "UDP 100%"})
    assert a["level"] == "info" and a["sound"] is False and a["title"] == "AI analyst: UDP flood"


def test_untrusted_text_is_cleaned():
    assert clean("hi" + chr(0) + chr(27) + "[31m @everyone   <@123>") == "hi [31m (at)everyone <(at)123>"
    assert len(clean("x" * 999)) == 300


class TestWebhook:
    def test_off_by_default(self):
        assert WebhookSender.from_env({}) is None

    def test_https_only(self):
        assert WebhookSender.from_env({"DDOS_ALERT_WEBHOOK_URL": "http://discord.com/api/webhooks/1/x"}) is None

    @pytest.mark.parametrize("url,key", [(HOOK, "content"), ("https://hooks.slack.com/services/T/B/x", "text"),
                                         ("https://example.org/hook", "alert")])
    def test_formats(self, url, key):
        sent = []
        wh = WebhookSender(url, post=lambda u, b: sent.append((u, json.loads(b))) or 204)
        a = AlertEngine(lambda e: None, clock=Clock(), webhook=wh)
        a.webhook.send(dict(a.observe(incident_ev()) or {}), background=False)  # once more, synchronously
        assert sent and key in sent[-1][1]
        if key == "content":
            assert sent[-1][1]["allowed_mentions"] == {"parse": []}

    def test_telegram_needs_chat_id_and_min_severity_applies(self):
        sent = []
        wh = WebhookSender("https://api.telegram.org/botX/sendMessage", telegram_chat_id="42",
                           post=lambda u, b: sent.append(json.loads(b)) or 200)
        eng = AlertEngine(lambda e: None, clock=Clock(), webhook=None)
        hi = eng.observe(incident_ev(sev=4))
        lo = eng.observe(incident_ev(title="minor", sev=2))
        wh.send(hi, background=False)
        wh.send(lo, background=False)  # below DDOS_ALERT_WEBHOOK_MIN_SEVERITY (4)
        assert len(sent) == 1 and sent[0]["chat_id"] == "42"
        none = WebhookSender("https://api.telegram.org/botX/sendMessage", post=lambda u, b: sent.append(b) or 200)
        none.send(hi, background=False)
        assert len(sent) == 1  # no chat id: not sent

    def test_failure_never_logs_the_url(self, caplog):
        def boom(u, b):
            raise OSError(f"cannot reach {u}")

        WebhookSender(HOOK, post=boom).send({"severity": 5, "kind": "incident", "level": "critical", "title": "t"},
                                             background=False)
        assert "SECRET-TOKEN" not in caplog.text and "discord.com/api" not in caplog.text


def test_alerts_module_cannot_mitigate():
    """Alerts only tell people: no mitigation manager, approve, subprocess or shell in this module."""
    src = Path(__file__).resolve().parent.parent / "src" / "ir" / "alerts.py"
    tree = ast.parse(src.read_text(encoding="utf-8"))
    names = {getattr(n, "attr", None) or getattr(n, "id", None) for n in ast.walk(tree)}
    mods = {a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
    mods |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert not {"approve", "propose", "execute"} & names
    assert not {"subprocess", "src.mitigation.manager"} & mods


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DDOS_IR_SCHEDULER", "off")
    monkeypatch.setenv("DDOS_ALERT_WEBHOOK_URL", HOOK)
    storage = str(tmp_path / "actions.json")
    monkeypatch.setenv("DDOS_PENDING_ACTIONS_PATH", storage)
    orig_api, orig_admin = set(api_module.API_KEYS), set(api_module.ADMIN_KEYS)
    api_module.API_KEYS.add("al-analyst-key")
    api_module.ADMIN_KEYS.add("al-admin-key")
    mgr = PendingActionManager.get_instance(storage)
    mgr.clear()
    rt = IRRuntime({}, database_url=f"sqlite:///{(tmp_path / 'ir.db').as_posix()}", manager_factory=lambda: mgr)
    posts = []
    rt.alerts.webhook._post = lambda u, b: posts.append(json.loads(b)) or 204
    set_ir_runtime(rt)
    try:
        with TestClient(app) as client:
            yield client, rt, posts
    finally:
        set_ir_runtime(None)
        api_module.API_KEYS, api_module.ADMIN_KEYS = orig_api, orig_admin


def test_api_incident_creates_one_alert_with_its_reason_and_never_exposes_the_url(env):
    client, rt, posts = env
    body = {"title": "[LIVE] L1 SYN Flood toward 10.99.0.10", "severity": 4,
            "aggregate": {"incident_id": "a1", "window_start": 1.0, "pps": 3000.0, "dst_ips": ["10.99.0.10"],
                          "alert_history": [{"ts": 1.0, "layer": "L1", "rule": "SYN flood",
                                             "detail": "2,997 pps toward 10.99.0.10, SYN 50% of TCP"}]}}
    with client.websocket_connect("/ws/incidents") as ws:
        ws.send_text(json.dumps({"type": "auth", "key": "al-analyst-key"}))
        assert json.loads(ws.receive_text())["type"] == "auth_ok"
        assert client.post("/api/incidents", headers=ANALYST, json=body).status_code == 201
        assert client.post("/api/incidents", headers=ANALYST, json=body).status_code == 201  # same attack again
        types = [json.loads(ws.receive_text())["type"] for _ in range(3)]
    assert types.count("alert") == 1 and types.count("incident.created") == 2
    r = client.get("/api/alerts", headers=ANALYST).json()
    assert len(r["alerts"]) == 1 and "2,997 pps" in r["alerts"][0]["reason"]
    assert r["webhook"] == {"enabled": True, "kind": "discord"} and "SECRET" not in json.dumps(r)
    import time as _t
    for _ in range(50):
        if posts:
            break
        _t.sleep(0.05)
    assert len(posts) == 1 and "SYN Flood" in posts[0]["content"]


def test_test_alert_is_admin_only(env):
    client, _, _ = env
    assert client.post("/api/alerts/test", headers=ANALYST).status_code == 403
    r = client.post("/api/alerts/test", headers=ADMIN)
    assert r.status_code == 200 and r.json()["sent"] is True
