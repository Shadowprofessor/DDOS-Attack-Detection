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


def test_soc_app_has_no_raw_html_sinks_or_browser_storage():
    """v5.0.0: legacy app.js was removed; the same guarantee now covers the React SOC app.
    Server strings are rendered as React text only, lint bans the raw-HTML sinks, and nothing is
    kept in browser storage (the session lives in an HttpOnly cookie)."""
    src = os.path.join(ROOT, "dashboard", "src")
    for root, _, files in os.walk(src):
        for name in files:
            if not name.endswith((".ts", ".tsx")) or ".test." in name:
                continue
            text = open(os.path.join(root, name), encoding="utf-8").read()
            for sink in ("dangerouslySetInnerHTML", ".innerHTML", "outerHTML", "document.write", "eval("):
                assert sink not in text, f"{name}: {sink}"
            for store in ("localStorage", "sessionStorage", "document.cookie"):
                assert store not in text, f"{name}: {store}"
    lint = open(os.path.join(ROOT, "dashboard", "eslint.config.js"), encoding="utf-8").read()
    assert "JSXAttribute[name.name='dangerouslySetInnerHTML']" in lint
    assert "MemberExpression[property.name='innerHTML']" in lint
