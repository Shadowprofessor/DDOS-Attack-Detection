# -*- coding: utf-8 -*-
"""v5.2.0 live bridge end to end, in-process: a growing pcap -> real API (L1 window alert ->
incident -> rule analysis; flows -> /score/flow; OVS samples). No network, no WSL."""
import json

import pytest
from fastapi.testclient import TestClient

import src.api.ir_router as ir_router
import src.api.live_router as live_router
import src.api.scoring_service as api_module
from src.api.analyst_router import _KeyRateLimiter
from src.api.scoring_service import app
from src.ir.runtime import IRRuntime, set_ir_runtime
from src.live.bridge import Bridge, aggregate_from_windows
from src.live.state import LiveState
from src.mitigation.manager import PendingActionManager
from tests.test_live_stream import frame, global_header, record

KEY = "live-bridge-key-01"


class ClientHttp:
    def __init__(self, c):
        self.c, self.calls = c, []

    def post(self, path, body=None):
        r = self.c.post(path, headers={"X-API-Key": KEY}, json=body or {})
        self.calls.append((path, r.status_code))
        return r.status_code, (r.json() if r.content else {})


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


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
    monkeypatch.setattr(ir_router, "ir_write_limiter", _KeyRateLimiter(1000))
    monkeypatch.setattr(live_router, "live_write_limiter", _KeyRateLimiter(1000))
    monkeypatch.setattr(live_router, "_state", LiveState())
    monkeypatch.setattr(api_module.rate_limiter, "allow", lambda key: True)
    try:
        with TestClient(app) as client:
            yield client
    finally:
        set_ir_runtime(None)
        api_module.API_KEYS = orig
        mgr.clear()


def syn_flood_records(t0, seconds=3, pps=600):
    out = []
    for i in range(seconds * pps):
        ts = t0 + i / pps
        out.append(record(ts, frame(f"10.99.0.{100 + i % 20}", "10.99.0.10", sport=20000 + i % 30000, flags=0x02)))
    return out


def test_bridge_opens_incident_from_a_growing_pcap_and_relays_flows_and_ovs(c, tmp_path):
    run = tmp_path / "live1"
    run.mkdir()
    (run / "old.pcap").write_bytes(global_header())  # present before start: ignored
    clk = Clock(1000.0)
    http = ClientHttp(c)
    b = Bridge(run, http, sensor="test-bridge", clock=clk, flows_per_s=2, export_s=1.0)
    assert b.tick()["packets"] == 0

    pcap = run / "syn_flood.pcap"
    recs = syn_flood_records(1000.0)
    pcap.write_bytes(global_header() + b"".join(recs[:900]) + recs[900][:10])  # torn last record
    clk.t = 1001.6
    r = b.tick()
    assert r["packets"] == 900 and r["alerts"] == 1  # window [1000,1001) closed -> L1 alert -> incident
    with pcap.open("ab") as fh:
        fh.write(recs[900][10:] + b"".join(recs[901:]))
    (run / "ovs_ports.jsonl").write_text(
        json.dumps({"switch": "s1", "ts": 1000.0, "ports": [{"port": "1", "rx_packets": 0, "tx_packets": 0, "rx_bytes": 0, "tx_bytes": 0}]}) + "\n"
        + json.dumps({"switch": "s1", "ts": 1002.0, "ports": [{"port": "1", "rx_packets": 1200, "tx_packets": 10, "rx_bytes": 48000, "tx_bytes": 400}]}) + "\n"
        + '{"switch": "s1", "ts": 1004')  # partial line: left for the next tick
    clk.t = 1020.0  # the rest of the flood arrives (late, in one burst)
    r1 = b.tick()
    clk.t = 1040.0  # then quiet: idle flows finalise; zero windows close the episode
    r2 = b.tick()
    assert r1["ovs"] + r2["ovs"] == 2 and r1["flows_scored"] + r2["flows_scored"] >= 1

    state = c.get("/api/live/state", headers={"X-API-Key": KEY}).json()
    v = state["victims"]["10.99.0.10"]
    assert v[0]["pps"] == 600 and v[0]["l1"]["status"] == "CRITICAL"
    assert state["episodes"][0]["closed_at"] is not None and state["open_alerts"] == []
    assert state["ovs"][0]["rx_pps"] == 600.0 and state["flows"]

    incs = c.get("/api/incidents", headers={"X-API-Key": KEY}).json()
    items = incs["items"] if isinstance(incs, dict) else incs
    assert len(items) == 1 and items[0]["title"].startswith("[LIVE] L1 Rate-Based SYN Flood toward 10.99.0.10")
    full = c.get(f"/api/incidents/{items[0]['id']}", headers={"X-API-Key": KEY}).json()
    assert full["analysis"]["source"] == "rules" and full["analysis"]["analysis"]["attack_type"] == "TCP SYN flood"
    assert full["detected_at"] == state["episodes"][0]["opened_at"]

    log = [json.loads(x) for x in (run / "live_bridge.jsonl").read_text().splitlines()]
    kinds = [e["event"] for e in log]
    assert "alert" in kinds and "incident_created" in kinds and "incident_analyzed" in kinds and "flow_scored" in kinds
    assert not any(e.get("pcap") == "old.pcap" for e in log)
    assert ("/api/live/windows", 200) in http.calls and all(code < 500 for _, code in http.calls)


def test_aggregate_from_windows_weights_by_packets():
    w = lambda pk, tcp, syn: {"start": 0, "dst": "10.99.0.10", "packets": pk, "pps": pk, "bps": pk * 320,
                              "unique_src": 20, "src_entropy": 4.3, "proto_mix": {"tcp": tcp, "udp": 1 - tcp},
                              "tcp_flags": {"syn": syn}, "top_talkers": [{"ip": "10.99.0.100", "packets": pk // 2}],
                              "top_dst_ports": [{"port": 443, "packets": pk}], "pkt_size": {"p50": 40, "p95": 60}}
    a = aggregate_from_windows([w(1000, 1.0, 1.0), w(0, 0, 0), w(1000, 0.5, 0.0)], "live-1")
    assert a["protocol_mix"] == {"tcp": 0.75, "udp": 0.25} and a["tcp_flag_ratios"] == {"syn": round(1000 / 1500, 4)}
    assert a["pps"] == 1000 and a["top_src_ips"][0] == {"key": "10.99.0.100", "share": 0.5}
    assert a["dst_ports"][0] == {"key": "443", "share": 1.0}


class SlowHttp(ClientHttp):
    """Like the real LLM path in live2: the analysis call blocks for a while."""

    def __init__(self, c, gate):
        super().__init__(c)
        self.gate = gate

    def post(self, path, body=None):
        if path.endswith("/analyze"):
            assert self.gate.wait(10)
        return super().post(path, body)


def test_slow_l3_analysis_runs_in_the_background_and_never_blocks_the_live_loop(c, tmp_path):
    import threading

    run = tmp_path / "live2"
    run.mkdir()
    clk = Clock(1000.0)
    gate = threading.Event()
    b = Bridge(run, ClientHttp(c), clock=clk, flows_per_s=0, analyze_http=SlowHttp(c, gate), analyze_async=True)
    b.tick()
    recs = syn_flood_records(1000.0, seconds=2)
    (run / "syn_flood.pcap").write_bytes(global_header() + b"".join(recs))
    clk.t = 1001.6
    assert b.tick()["alerts"] == 1  # returned although the analysis is still blocked
    kinds = lambda: [json.loads(x)["event"] for x in (run / "live_bridge.jsonl").read_text().splitlines()]
    assert "incident_created" in kinds() and "incident_analyzed" not in kinds()
    gate.set()
    b.close()
    assert "incident_analyzed" in kinds()



def test_incident_never_inherits_the_previous_floods_ml_verdict(tmp_path):
    """live9: the UDP incident carried the SYN flood's 'Syn 0.99' and Lightning repeated it."""
    from src.live.bridge import Bridge

    class NoHttp:
        def get(self, path):
            return 200, {}

        def post(self, path, body=None):
            return 200, {}

    b = Bridge(tmp_path, NoHttp(), flows_per_s=0)
    b.ml_latest["10.99.0.10"] = {"label": "Syn", "confidence": 0.99, "flow_end": 1000.0}  # SYN flood flow
    udp = {"id": "live-2", "dst": "10.99.0.10", "window_start": 1150.0}  # UDP flood episode, later
    assert b.ml_for_episode(udp) is None
    b.ml_latest["10.99.0.10"] = {"label": "UDP", "confidence": 0.97, "flow_end": 1151.5}
    assert b.ml_for_episode(udp) == {"label": "UDP", "confidence": 0.97}
    syn = {"id": "live-1", "dst": "10.99.0.10", "window_start": 1000.5}  # within 1 s slack
    b.ml_latest["10.99.0.10"] = {"label": "Syn", "confidence": 0.99, "flow_end": 1000.0}
    assert b.ml_for_episode(syn)["label"] == "Syn"
