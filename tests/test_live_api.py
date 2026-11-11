# -*- coding: utf-8 -*-
"""v5.2.0 live API: L1 on every window, alert episodes, OVS rates, validation, auth, /ws/live."""
import pytest
from fastapi.testclient import TestClient

import src.api.live_router as live_router
import src.api.scoring_service as api_module
from src.api.analyst_router import _KeyRateLimiter
from src.api.scoring_service import app
from src.live.state import LiveState, traffic_hint

KEY = "test-live"  # placeholder key for the in-process app
H = {"X-API-Key": KEY}


class Clock:
    def __init__(self, t=1_000.0):
        self.t = t

    def __call__(self):
        return self.t


def win(start, pps, dst="10.99.0.10", syn=0.0, proto=None, talkers=None, **kw):
    w = {"start": start, "end": start + 1, "dst": dst, "packets": int(pps), "bytes": int(pps * 40),
         "pps": pps, "bps": pps * 320, "unique_src": 20, "src_entropy": 4.3,
         "proto_mix": proto or {"tcp": 1.0}, "tcp_flags": {"syn": 1.0} if syn else {},
         "syn_rate": syn, "conn_rate": syn, "pkt_size": {"mean": 40, "p50": 40, "p95": 40, "max": 40},
         "top_talkers": talkers or [{"ip": "10.99.0.100", "packets": int(pps / 20)}], "top_dst_ports": []}
    w.update(kw)
    return w


def test_episode_opens_on_first_violating_window_and_clears_after_quiet_windows():
    clk = Clock()
    st = LiveState(clock=clk, clear_after=3)
    assert [e["type"] for e in st.ingest_window(win(0, 30), "s")] == ["live.window"]  # benign rate
    clk.t = 1001.2
    ev = st.ingest_window(win(1, 1480, syn=1480), "s")
    assert [e["type"] for e in ev] == ["live.window", "live.alert"]
    ep = ev[1]["episode"]
    assert ep["opened_at"] == 1001.2 and ep["status"] == "CRITICAL" and ep["vector"] == "Rate-Based SYN Flood"
    assert ep["window_start"] == 1 and "TCP 100%" in ep["hint"]
    assert [e["type"] for e in st.ingest_window(win(2, 1500, syn=1500), "s")] == ["live.window"]  # same episode
    assert st.open["10.99.0.10"]["peak_pps"] == 1500
    for i in range(2):
        assert [e["type"] for e in st.ingest_window(win(3 + i, 0, proto={}), "s")] == ["live.window"]
    clk.t = 1006.0
    ev = st.ingest_window(win(5, 0, proto={}), "s")
    assert ev[-1]["type"] == "live.clear" and ev[-1]["episode"]["closed_at"] == 1006.0
    snap = st.snapshot()
    assert snap["open_alerts"] == [] and len(snap["episodes"]) == 1 and len(snap["victims"]["10.99.0.10"]) == 6


def test_l1_window_reasons_carry_the_numbers():
    st = LiveState(clock=Clock())
    ev = st.ingest_window(win(0, 1416, proto={"icmp": 0.99, "tcp": 0.01}), "s")
    w = ev[0]["window"]
    assert w["l1"]["status"] == "CRITICAL" and any("1416.0 pps" in r for r in w["l1"]["rules"])
    assert w["hint"] == "ICMP 99%"
    assert traffic_hint({"proto_mix": {}}) == "no traffic"


def test_ovs_rates_from_counter_deltas_and_counter_reset():
    st = LiveState(clock=Clock())
    p = {"port": "1", "rx_packets": 100, "tx_packets": 50, "rx_bytes": 10_000, "tx_bytes": 5_000}
    assert st.ingest_ovs("s1", 10.0, [p])["ports"][0]["rx_pps"] is None  # first sample: no rate yet
    r = st.ingest_ovs("s1", 12.0, [{**p, "rx_packets": 3100, "rx_bytes": 130_000}])["ports"][0]
    assert r["rx_pps"] == 1500.0 and r["tx_pps"] == 0.0 and r["rx_bps"] == 480_000.0
    assert st.ingest_ovs("s1", 14.0, [p])["ports"][0]["rx_pps"] is None  # counters went backwards


@pytest.fixture
def c(monkeypatch):
    orig = set(api_module.API_KEYS)
    api_module.API_KEYS.add(KEY)
    monkeypatch.setattr(live_router, "_state", LiveState())
    monkeypatch.setattr(live_router, "live_write_limiter", _KeyRateLimiter(1000))
    try:
        with TestClient(app) as client:
            yield client
    finally:
        api_module.API_KEYS = orig


def test_windows_endpoint_runs_l1_and_returns_opened_alerts(c):
    r = c.post("/api/live/windows", headers=H, json={"sensor": "bridge-1", "windows": [win(0, 20), win(1, 1500, syn=1500)]})
    assert r.status_code == 200
    body = r.json()
    assert body["accepted"] == 2 and len(body["alerts_opened"]) == 1 and body["open_alerts"] == ["10.99.0.10"]
    st = c.get("/api/live/state", headers=H).json()
    assert len(st["victims"]["10.99.0.10"]) == 2 and st["open_alerts"][0]["sensor"] == "bridge-1"
    metrics = c.get("/metrics").text
    assert 'ddos_live_window_pps{dst="10.99.0.10"} 1500.0' in metrics


def test_live_routes_need_a_key_and_reject_bad_input(c):
    assert c.get("/api/live/state").status_code == 401
    assert c.post("/api/live/windows", json={"sensor": "x", "windows": [win(0, 1)]}).status_code == 401
    bad_ip = win(0, 1, dst="10.99.0.999")
    assert c.post("/api/live/windows", headers=H, json={"sensor": "x", "windows": [bad_ip]}).status_code == 422
    extra = {**win(0, 1), "cmd": "rm -rf /"}
    assert c.post("/api/live/windows", headers=H, json={"sensor": "x", "windows": [extra]}).status_code == 422
    neg = {**win(0, 1), "pps": -5}
    assert c.post("/api/live/windows", headers=H, json={"sensor": "x", "windows": [neg]}).status_code == 422
    assert c.post("/api/live/windows", headers=H, json={"sensor": "bad sensor!", "windows": [win(0, 1)]}).status_code == 422
    assert c.post("/api/live/windows", headers=H, json={"sensor": "x", "windows": [win(i, 1) for i in range(201)]}).status_code == 422


def test_live_writes_are_rate_limited(c, monkeypatch):
    monkeypatch.setattr(live_router, "live_write_limiter", _KeyRateLimiter(2))
    codes = [c.post("/api/live/windows", headers=H, json={"sensor": "x", "windows": [win(i, 1)]}).status_code for i in range(3)]
    assert codes == [200, 200, 429]


def test_ovs_and_flows_endpoints_and_reset(c):
    p = {"port": "s1-eth1", "rx_packets": 0, "tx_packets": 0, "rx_bytes": 0, "tx_bytes": 0}
    assert c.post("/api/live/ovs", headers=H, json={"sensor": "w", "switch": "s1", "ts": 1.0, "ports": [p]}).status_code == 200
    p2 = {**p, "rx_packets": 2000, "rx_bytes": 80_000, "rx_dropped": 3}
    assert c.post("/api/live/ovs", headers=H, json={"sensor": "w", "switch": "s1", "ts": 3.0, "ports": [p2]}).status_code == 200
    f = {"src": "10.99.0.100", "dst": "10.99.0.10", "proto": 6, "sport": 1, "dport": 443, "packets": 3, "start": 1.0,
         "end": 1.1, "final": True, "label": "Benign", "is_attack": False, "confidence": 0.9, "ood_suspected": False}
    assert c.post("/api/live/flows", headers=H, json={"sensor": "w", "flows": [f]}).status_code == 200
    assert c.post("/api/live/flows", headers=H, json={"sensor": "w", "flows": [{**f, "label": "<script>"}]}).status_code == 422
    st = c.get("/api/live/state", headers=H).json()
    assert st["ovs"][0]["rx_pps"] == 1000.0 and st["ovs"][0]["rx_dropped"] == 3 and st["flows"][0]["label"] == "Benign"
    assert 'ddos_ovs_port_pps{dir="rx",port="s1-eth1",switch="s1"} 1000.0' in c.get("/metrics").text
    assert c.post("/api/live/reset", headers=H).status_code == 204
    assert c.get("/api/live/state", headers=H).json()["ovs"] == []


def test_ws_live_auth_and_events(c):
    with c.websocket_connect("/ws/live", headers=H) as ws:
        assert ws.receive_json()["type"] == "auth_ok"
        c.post("/api/live/windows", headers=H, json={"sensor": "x", "windows": [win(0, 1500, syn=1500)]})
        types = {ws.receive_json()["type"] for _ in range(2)}
        assert types == {"live.window", "live.alert"}
    with c.websocket_connect("/ws/live") as ws:
        ws.send_json({"type": "auth", "key": "wrong"})
        with pytest.raises(Exception):
            ws.receive_json()


def test_live_router_cannot_approve_or_execute():
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(live_router))
    names = {n.attr if isinstance(n, ast.Attribute) else getattr(n, "id", "") for n in ast.walk(tree)
             if isinstance(n, (ast.Attribute, ast.Name))}
    assert not names & {"approve", "execute", "propose", "subprocess", "system"}
