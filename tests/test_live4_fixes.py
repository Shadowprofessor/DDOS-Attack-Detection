# -*- coding: utf-8 -*-
"""v5.4.0 live4 findings: /score/flow proposed blocking the VICTIM (it scored the victim's reply flows)."""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import src.api.live_router as live_router
import src.api.scoring_service as svc
from src.live.bridge import Bridge
from src.live.state import LiveState
from src.mitigation.manager import PendingActionManager

V = "10.99.0.10"


class NoHttp:
    def post(self, path, body=None):
        return 200, {}


def test_bridge_never_samples_flows_sent_by_a_victim(tmp_path):
    b = Bridge(Path(tmp_path), NoHttp(), clock=lambda: 0.0)
    b.alerted.add(V)
    b._candidate({"src": V, "dst": "10.99.0.120", "flow": None})       # victim's reply: skipped
    b._candidate({"src": "10.99.0.120", "dst": V, "flow": None})       # attacker -> victim: kept
    b.busiest_dst = "10.99.0.30"
    b._candidate({"src": "10.99.0.30", "dst": "10.99.0.121", "flow": None})  # busiest destination's replies: skipped
    assert [(c["src"], c["dst"]) for c in b.candidates] == [("10.99.0.120", V)]


@pytest.fixture
def c(tmp_path, monkeypatch):
    storage = str(tmp_path / "a.json")
    monkeypatch.setenv("DDOS_PENDING_ACTIONS_PATH", storage)
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    mgr = PendingActionManager.get_instance(storage)
    mgr.clear()
    orig = set(svc.API_KEYS)
    svc.API_KEYS.add("live4-key")
    monkeypatch.setattr(svc.rate_limiter, "allow", lambda k: True)
    st = LiveState()
    monkeypatch.setattr(live_router, "_state", st)
    try:
        with TestClient(svc.app) as client:
            yield client, mgr, st
    finally:
        svc.API_KEYS = orig
        mgr.clear()


def test_score_flow_never_proposes_blocking_a_victim_under_live_alert(c, monkeypatch):
    client, mgr, st = c

    class AlwaysAttack:
        def score_flow(self, **kw):
            return "TFTP", 0.95, {"mode": "xgb_only", "xgboost": {"label": "TFTP", "confidence": 0.95}}

    monkeypatch.setattr(svc, "get_default_ensemble", lambda: AlwaysAttack())
    st.open[V] = {"id": "live-1", "dst": V}  # V is under a live alert
    r = client.post("/score/flow", headers={"X-API-Key": "live4-key"},
                    json={"features": {"src_ip": V, "dst_ip": "10.99.0.120", "Protocol": 17}}).json()
    assert r["result"]["is_attack"] and r["result"]["proposed_action_id"] is None
    assert not any(a["attacker_ip"] == V for a in mgr.get_pending().values())
    r2 = client.post("/score/flow", headers={"X-API-Key": "live4-key"},
                     json={"features": {"src_ip": "10.99.0.120", "dst_ip": V, "Protocol": 17}}).json()
    assert r2["result"]["proposed_action_id"]  # the real attacker can still be proposed (PENDING)
