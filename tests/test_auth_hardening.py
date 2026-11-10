# -*- coding: utf-8 -*-
"""
Regression tests for F-1 (GRC review): built-in convenience auth keys
('scoring-key-test', 'admin-key-test', 'dev-admin-key') must NOT be valid
outside an explicit DDOS_ENV=test environment, and the admin tier must reject
them so they can never approve a real mitigation action.
"""
import pytest
from fastapi.testclient import TestClient

from src.api import scoring_service as svc


@pytest.fixture
def clean_lab_env(monkeypatch):
    """Force a lab (non-test, non-prod) env with no injected keys."""
    monkeypatch.setattr(svc, "_ENV_NAME", "lab")
    monkeypatch.setattr(svc, "API_KEYS", {k for k in svc.API_KEYS if k != "scoring-key-test"})
    monkeypatch.setattr(svc, "ADMIN_KEYS", {k for k in svc.ADMIN_KEYS if k != "admin-key-test"})
    monkeypatch.delenv("DDOS_API_KEYS", raising=False)
    monkeypatch.delenv("DDOS_ADMIN_KEYS", raising=False)


def test_builtin_test_keys_absent_in_lab_env(clean_lab_env):
    assert "scoring-key-test" not in svc._get_valid_api_keys()
    assert "admin-key-test" not in svc._get_valid_admin_keys()


def test_builtin_test_keys_present_only_in_test_env(monkeypatch):
    monkeypatch.setattr(svc, "_ENV_NAME", "test")
    assert "scoring-key-test" in svc._get_valid_api_keys()
    assert "admin-key-test" in svc._get_valid_admin_keys()


def test_admin_endpoint_rejects_builtin_key_in_lab(clean_lab_env):
    """The old hardcoded admin key must not authorize approvals outside test env."""
    with TestClient(svc.app) as client:
        r = client.post(
            "/actions/approve/nonexistent-id",
            headers={"X-Admin-Key": "admin-key-test"},
        )
        # 401 (unknown credential) is expected; must NOT be 200/404-as-authorized.
        assert r.status_code in (401, 403)


def test_dev_key_written_to_file_never_stdout_or_logs(capsys, caplog, tmp_path, monkeypatch):
    """Generated dev key values go to an owner-only local file, NEVER to stdout or (JSON) logs."""
    key_file = tmp_path / ".dev-keys"
    monkeypatch.setenv("DDOS_DEV_KEY_FILE", str(key_file))
    secret = "dev-UNIT-TEST-SECRET-VALUE"
    with caplog.at_level("DEBUG"):
        path = svc._announce_dev_key("scoring API key", secret)
    out = capsys.readouterr().out
    assert path == str(key_file)
    assert secret in key_file.read_text(encoding="utf-8")
    assert str(key_file) in out, "the file path is printed so the developer can find the key"
    assert secret not in out, "dev key value must not go to stdout"
    assert secret not in caplog.text, "dev key value must never appear in log output"


def test_dashboard_ws_no_longer_unions_hardcoded_keys():
    """The WS router must derive keys only from the auth helpers, not a literal set."""
    import inspect
    from src.web.realtime_dashboard import router as ws_router
    src = inspect.getsource(ws_router.websocket_dashboard_endpoint)
    assert "dev-admin-key" not in src
    assert "admin-key-test" not in src
    assert "scoring-key-test" not in src
