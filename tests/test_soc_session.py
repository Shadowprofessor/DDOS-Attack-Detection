# -*- coding: utf-8 -*-
"""v4.3.0 SOC web app backend: session cookie, CSRF, rotation, CSP/security headers, SPA mount, overview."""
import pytest
from fastapi.testclient import TestClient

import src.api.scoring_service as api_module
import src.web.app_server as app_server
from src.api.scoring_service import app
from src.api.session_router import login_limiter
from src.ir.runtime import IRRuntime, set_ir_runtime
from src.mitigation.manager import PendingActionManager
from src.web.session import COOKIE_NAME, SessionStore, get_session_store

ANALYST_KEY = "soc-analyst-key-1"
ADMIN_KEY = "soc-admin-key-01"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DDOS_IR_SCHEDULER", "off")
    storage = str(tmp_path / "actions.json")
    monkeypatch.setenv("DDOS_PENDING_ACTIONS_PATH", storage)
    orig_api, orig_admin = set(api_module.API_KEYS), set(api_module.ADMIN_KEYS)
    api_module.API_KEYS.add(ANALYST_KEY)
    api_module.ADMIN_KEYS.add(ADMIN_KEY)
    mgr = PendingActionManager.get_instance(storage)
    mgr.clear()
    set_ir_runtime(IRRuntime({}, database_url=f"sqlite:///{(tmp_path / 'ir.db').as_posix()}",
                             manager_factory=lambda: mgr))
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<!doctype html><div id=root></div>", encoding="utf-8")
    (dist / "assets" / "app-abc123.js").write_text("console.log(1)", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("TOP-SECRET", encoding="utf-8")
    monkeypatch.setattr(app_server, "DIST_DIR", dist)
    get_session_store().clear()
    login_limiter.clear()
    try:
        with TestClient(app, base_url="https://testserver") as c:
            yield c
    finally:
        set_ir_runtime(None)
        get_session_store().clear()
        api_module.API_KEYS, api_module.ADMIN_KEYS = orig_api, orig_admin


def _login(c, key=ANALYST_KEY):
    r = c.post("/api/session/login", json={"api_key": key})
    assert r.status_code == 200, r.text
    return r


class TestSessionCookie:
    def test_cookie_flags(self, client):
        r = _login(client)
        sc = r.headers["set-cookie"].lower()
        assert sc.startswith(COOKIE_NAME + "=")
        for flag in ("httponly", "secure", "samesite=strict", "path=/"):
            assert flag in sc, flag
        assert ANALYST_KEY not in r.text and ANALYST_KEY not in sc  # key never returned
        assert r.json()["role"] == "analyst" and len(r.json()["csrf_token"]) >= 32

    def test_bad_key_401_and_rate_limit(self, client):
        assert client.post("/api/session/login", json={"api_key": "wrong-key-123"}).status_code == 401
        codes = [client.post("/api/session/login", json={"api_key": "wrong-key-123"}).status_code
                 for _ in range(12)]
        assert 429 in codes

    def test_session_authenticates_get_without_headers(self, client):
        _login(client)
        assert client.get("/api/incidents").status_code == 200
        assert client.get("/api/session").json()["role"] == "analyst"

    def test_rotation_on_login(self, client):
        sid1 = _login(client).cookies[COOKIE_NAME]
        sid2 = _login(client, ADMIN_KEY).cookies[COOKIE_NAME]
        assert sid1 != sid2
        assert get_session_store().get(sid1) is None  # old session destroyed
        assert client.get("/api/session").json()["role"] == "admin"

    def test_logout_requires_csrf_and_clears(self, client):
        csrf = _login(client).json()["csrf_token"]
        assert client.post("/api/session/logout").status_code == 403
        assert client.post("/api/session/logout", headers={"X-CSRF-Token": csrf}).status_code == 204
        client.cookies.clear()
        assert client.get("/api/session").status_code == 401

    def test_revoked_key_kills_session(self, client):
        _login(client)
        api_module.API_KEYS.discard(ANALYST_KEY)
        assert client.get("/api/incidents").status_code == 401

    def test_idle_and_absolute_expiry(self):
        t = [1000.0]
        st = SessionStore(idle_s=10, absolute_s=100, clock=lambda: t[0])
        s = st.create("k")
        t[0] += 9
        assert st.get(s.sid)
        t[0] += 11
        assert st.get(s.sid) is None
        s2 = st.create("k")
        for _ in range(12):
            t[0] += 9
            st.get(s2.sid)
        assert st.get(s2.sid) is None  # absolute lifetime exceeded


class TestCSRF:
    def test_state_change_without_csrf_is_403(self, client):
        _login(client)
        r = client.post("/api/incidents", json={"title": "csrf test", "severity": 2})
        assert r.status_code == 403 and "CSRF" in r.json()["detail"]
        r = client.post("/api/incidents", json={"title": "csrf test", "severity": 2},
                        headers={"X-CSRF-Token": "forged"})
        assert r.status_code == 403

    def test_state_change_with_csrf_ok(self, client):
        csrf = _login(client).json()["csrf_token"]
        r = client.post("/api/incidents", json={"title": "csrf test", "severity": 2},
                        headers={"X-CSRF-Token": csrf})
        assert r.status_code == 201

    def test_header_key_clients_unaffected(self, client):
        r = client.post("/api/incidents", json={"title": "cli test", "severity": 2},
                        headers={"X-API-Key": ANALYST_KEY})
        assert r.status_code == 201

    def test_session_role_still_enforced(self, client):
        csrf = _login(client).json()["csrf_token"]
        iid = client.post("/api/incidents", json={"title": "x flood", "severity": 5},
                          headers={"X-CSRF-Token": csrf}).json()["id"]
        assert client.get(f"/api/incidents/{iid}/cert-in/draft").status_code == 403


class TestHeadersAndSpa:
    def test_csp_and_security_headers_on_app_and_api(self, client):
        for path in ("/app", "/app/incidents", "/api/session"):
            h = client.get(path).headers
            csp = h["content-security-policy"]
            for d in ("default-src 'self'", "script-src 'self'", "object-src 'none'",
                      "frame-ancestors 'none'", "base-uri 'none'"):
                assert d in csp, (path, d)
            assert "unsafe-inline" not in csp and "unsafe-eval" not in csp
            assert h["x-content-type-options"] == "nosniff"
            assert h["referrer-policy"] == "no-referrer"
            assert "permissions-policy" in h

    def test_spa_fallback_and_assets(self, client):
        assert "id=root" in client.get("/app/incidents/INC-1").text
        r = client.get("/app/assets/app-abc123.js")
        assert r.status_code == 200 and "immutable" in r.headers["cache-control"]
        assert client.get("/app/assets/missing.js").status_code == 404

    def test_fallback_never_shadows_api(self, client):
        assert client.get("/api/incidents").status_code == 401  # JSON API, not index.html
        assert client.get("/api/does-not-exist").status_code == 404
        assert "id=root" not in client.get("/api/does-not-exist").text

    @pytest.mark.parametrize("p", ["/app/../secret.txt", "/app/..%2Fsecret.txt", "/app/%2e%2e/secret.txt"])
    def test_no_path_traversal(self, client, p):
        assert "TOP-SECRET" not in client.get(p).text

    def test_not_built_is_503(self, client, monkeypatch, tmp_path):
        monkeypatch.setattr(app_server, "DIST_DIR", tmp_path / "nope")
        assert client.get("/app").status_code == 503


class TestOverview:
    def test_requires_auth(self, client):
        assert client.get("/api/overview").status_code == 401

    def test_shape(self, client):
        csrf = _login(client, ADMIN_KEY).json()["csrf_token"]
        h = {"X-CSRF-Token": csrf}
        client.post("/api/incidents", json={"title": "big flood", "severity": 5}, headers=h)
        client.post("/api/incidents", json={"title": "small flood", "severity": 2}, headers=h)
        o = client.get("/api/overview").json()
        assert o["incidents"]["open"] == 2
        assert o["incidents"]["by_severity_open"]["5"] == 1
        assert len(o["cert_in_timers"]) == 1 and o["cert_in_timers"][0]["severity"] == 5
        assert set(o["health"]) >= {"models_loaded", "llm", "ws_clients"}
        assert "api_key" not in str(o["health"]["llm"])
