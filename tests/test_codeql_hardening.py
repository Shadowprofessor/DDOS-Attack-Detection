# -*- coding: utf-8 -*-
"""Regression tests for the v4.1.1 CodeQL fixes (log injection, path injection, error leaks, XSS)."""
import os
import re

from src.obs.logging import log_safe

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_log_safe_escapes_newlines_and_truncates():
    forged = "1.2.3.4\n2026-01-01 INFO admin approved everything\r"
    out = log_safe(forged)
    assert "\n" not in out and "\r" not in out
    assert "\\n" in out and "\\r" in out
    assert len(log_safe("x" * 1000)) == 200
    assert log_safe(None) == "None"


def test_legacy_dashboard_incident_id_rejects_paths():
    src = open(os.path.join(ROOT, "Codes", "dashboard", "app.py"), encoding="utf-8").read()
    pat = re.search(r'_SAFE_INCIDENT_ID = re\.compile\(r"([^"]+)"\)', src)
    assert pat, "incident-id allowlist missing"
    rx = re.compile(pat.group(1))
    assert rx.fullmatch("INC-20261110-abc_1")
    for bad in ("../../etc/passwd", "..", "a/b", "a\b", "x" * 65, "", "id.json"):
        assert not rx.fullmatch(bad), bad
    assert "_SAFE_INCIDENT_ID.fullmatch(str(new_id))" in src


def test_approve_failure_does_not_leak_error_detail(monkeypatch):
    from fastapi.testclient import TestClient
    from src.api import scoring_service as svc

    secret_detail = "Traceback: /opt/secret/path iptables failed with token=abc"

    class FakeMgr:
        def get_action(self, aid):
            return {"status": "PENDING", "action_id": aid}

        def approve(self, aid, approver=None):
            return False, secret_detail, None

        def get_pending(self):
            return {}

    monkeypatch.setattr(svc, "get_manager", lambda: FakeMgr())
    admin = next(iter(svc.ADMIN_KEYS))
    with TestClient(svc.app) as client:
        r = client.post("/actions/approve/act-1", headers={"X-Admin-Key": admin})
    assert r.status_code == 500
    assert secret_detail not in r.text and "token=abc" not in r.text


def test_dashboard_js_escapes_server_fields():
    js = open(os.path.join(ROOT, "src", "web", "realtime_dashboard", "static", "app.js"), encoding="utf-8").read()
    # This nested template is itself the argument of escapeHtml(...), so it is safe.
    js = js.replace("`iptables -I INPUT -s ${action.attacker_ip} -j DROP`)", "")
    # These server-controlled fields must never be interpolated into HTML unescaped.
    for expr in ("action.attacker_ip", "action.victim_ip", "action.action_id", "dossier.attack_mechanics",
                 "dossier.blast_radius", "caveat", "degReason", "label"):
        assert "${" + expr + "}" not in js, expr
    assert "new Map()" in js and "taxonomyCounts[" not in js  # no prototype-pollution via labels
    assert 'if (str === null || str === undefined) return "";' in js  # 0 still renders
