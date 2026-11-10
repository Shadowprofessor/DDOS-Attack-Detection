# -*- coding: utf-8 -*-
"""v4.7.0 bug-hunt regressions (docs/security/bug_hunt.md)."""
import pytest
from fastapi.testclient import TestClient

import src.api.ir_router as ir_router
import src.api.scoring_service as api_module
import src.web.realtime_dashboard.router as dash_router
from src.api.analyst_router import _KeyRateLimiter
from src.api.scoring_service import app
from src.ir.runtime import IRRuntime, set_ir_runtime
from src.mitigation.manager import PendingActionManager

KEY = "bughunt-analyst-key"
H = {"X-API-Key": KEY}


@pytest.fixture
def c(tmp_path, monkeypatch):
    monkeypatch.setenv("DDOS_IR_SCHEDULER", "off")
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    storage = str(tmp_path / "a.json")
    monkeypatch.setenv("DDOS_PENDING_ACTIONS_PATH", storage)
    orig = set(api_module.API_KEYS)
    api_module.API_KEYS.add(KEY)
    mgr = PendingActionManager.get_instance(storage)
    mgr.clear()
    set_ir_runtime(IRRuntime({}, database_url=f"sqlite:///{(tmp_path / 'ir.db').as_posix()}", manager_factory=lambda: mgr))
    monkeypatch.setattr(ir_router, "ir_write_limiter", _KeyRateLimiter(3))
    monkeypatch.setattr(dash_router, "_chat_limiter", _KeyRateLimiter(2))
    try:
        with TestClient(app) as client:
            yield client
    finally:
        set_ir_runtime(None)
        api_module.API_KEYS = orig


def test_ir_writes_are_rate_limited_per_actor(c):
    codes = [c.post("/api/incidents", headers=H, json={"title": f"flood {i}", "severity": 2}).status_code for i in range(5)]
    assert codes[:3] == [201, 201, 201] and codes[3:] == [429, 429]
    assert c.get("/api/incidents", headers=H).status_code == 200  # reads are not limited


def test_replay_shares_the_write_limit(c):
    for _ in range(3):
        c.post("/api/incidents", headers=H, json={"title": "flood x", "severity": 2})
    assert c.post("/api/replay", headers=H, json={"scenario": "syn_flood", "speed": 10000}).status_code == 429


def test_chat_is_rate_limited(c):
    codes = [c.post("/api/chat", headers=H, json={"message": "summary?"}).status_code for _ in range(4)]
    assert codes == [200, 200, 429, 429]


@pytest.mark.parametrize("body", [[], "just a string", 42])
def test_chat_non_object_body_is_not_a_500(c, body):
    r = c.post("/api/chat", headers=H, json=body)
    assert r.status_code == 200 and r.json()["authority"] == "READ_ONLY_ADVISORY"


def test_chat_message_is_truncated(c, monkeypatch):
    seen = {}

    class Fake:
        def answer_query(self, m):
            seen["len"] = len(m)
            return {"response": "ok", "authority": "READ_ONLY_ADVISORY", "model": "fake"}

    import src.agent.soc_chat_assistant as chat_mod
    monkeypatch.setattr(chat_mod, "get_soc_chat_assistant", lambda: Fake())
    c.post("/api/chat", headers=H, json={"message": "x" * 50_000})
    assert seen["len"] == 2000
