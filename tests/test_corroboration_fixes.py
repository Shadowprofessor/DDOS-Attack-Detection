# -*- coding: utf-8 -*-
"""v5.3.0 pre-fix 5: /score/flow rate corroboration must not flag benign traffic, and models that
did not run are "not scored", never a placeholder verdict."""
import pytest
from fastapi.testclient import TestClient

import src.api.scoring_service as svc
from src.features.anomaly_detector import PerDestinationBaseline
from src.features.threshold_detector import RateThresholdDetector


def test_window_rate_is_count_over_window_not_over_the_gap_between_samples():
    d = RateThresholdDetector(window_seconds=2.0)
    f = {"Total Fwd Packets": 6, "Total Backward Packets": 6}
    d.record_flow(f, src_ip="10.99.0.150", dst_ip="10.99.0.10", timestamp=100.00)
    r = d.record_flow(f, src_ip="10.99.0.151", dst_ip="10.99.0.10", timestamp=100.05)
    assert r.current_pps == 12.0 and r.status == "NORMAL"  # 24 packets / 2 s; was 24 / 0.05 s = 480 pps


def test_adaptive_baseline_learns_each_destination_and_ignores_warmup():
    b = PerDestinationBaseline(warmup=5)
    for _ in range(5):
        assert b.evaluate("10.99.0.10", 40.0, 30_000.0)["severity"] == "LEARNING"
    assert b.evaluate("10.99.0.10", 45.0, 32_000.0)["is_anomaly"] is False  # a busy server's normal rate
    hit = b.evaluate("10.99.0.10", 1500.0, 500_000.0)
    assert hit["is_anomaly"] and hit["severity"] == "CRITICAL" and "above its own baseline" in hit["anomaly_reasons"][0]
    assert b.evaluate("10.99.0.10", 1500.0, 500_000.0)["baseline_metrics"]["mean_pps"] < 50  # did not learn the flood
    assert b.evaluate("10.99.0.20", 1500.0, 1.0)["severity"] == "LEARNING"  # other destination: own baseline


@pytest.fixture
def c(tmp_path, monkeypatch):
    monkeypatch.setenv("DDOS_PENDING_ACTIONS_PATH", str(tmp_path / "a.json"))
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    orig = set(svc.API_KEYS)
    svc.API_KEYS.add("corr-key")
    monkeypatch.setattr(svc.rate_limiter, "allow", lambda k: True)
    monkeypatch.setattr(svc, "_THRESHOLD_DETECTOR", RateThresholdDetector())
    monkeypatch.setattr(svc, "_H9_BASELINES", PerDestinationBaseline())
    from src.agent.campaign_correlator import CampaignCorrelator
    monkeypatch.setattr(svc, "_CAMPAIGN_CORRELATOR", CampaignCorrelator(window_seconds=60.0))
    try:
        with TestClient(svc.app) as client:
            yield client
    finally:
        svc.API_KEYS = orig


def _flow(src, i):
    return {"features": {"src_ip": src, "dst_ip": "10.99.0.10", "Protocol": 6, "Destination Port": 80,
                         "Total Fwd Packets": 6, "Total Backward Packets": 5, "Fwd Packets Length Total": 420,
                         "Bwd Packets Length Total": 6000, "Flow Duration": 250000, "Flow Packets/s": 44.0 + i,
                         "SYN Flag Count": 1, "ACK Flag Count": 10}}


def test_normal_clients_of_one_server_are_not_a_campaign(c):
    """v5.2.0 live runs: >=3 benign clients to one victim were flagged by rate corroboration."""
    verdicts = []
    for i in range(30):
        r = c.post("/score/flow", headers={"X-API-Key": "corr-key"}, json=_flow(f"10.99.0.{150 + i % 6}", i)).json()["result"]
        verdicts.append("MULTI_LAYER" in str((r.get("per_model_breakdown") or {}).get("consensus_tier")))
    assert not any(verdicts)


def test_no_placeholder_model_verdicts_when_corroboration_overrides(c, monkeypatch):
    from src.models import ensemble

    class OnlyBenign:
        def score_flow(self, **kw):
            return "Benign", 0.9, {"mode": "xgb_only"}  # no per-model entries at all

    monkeypatch.setattr(svc, "get_default_ensemble", lambda: OnlyBenign())
    d = svc._THRESHOLD_DETECTOR
    for i in range(1200):  # a real flood at the victim: H6 has rate evidence
        d.record_flow({"Total Fwd Packets": 1, "SYN Flag Count": 1}, src_ip=f"10.99.0.{100 + i % 50}", dst_ip="10.99.0.10")
    r = None
    for i in range(4):
        r = c.post("/score/flow", headers={"X-API-Key": "corr-key"},
                   json={"features": {"src_ip": f"10.99.0.{100 + i}", "dst_ip": "10.99.0.10", "SYN Flag Count": 1,
                                      "Total Fwd Packets": 1}}).json()["result"]
    bd = r["per_model_breakdown"]
    assert bd["consensus_tier"] == "MULTI_LAYER_CAMPAIGN_CORROBORATION"
    for m in ("random_forest", "xgboost"):
        assert bd[m] == {"status": "not scored", "label": None, "confidence": None}
    assert ensemble  # imported module stays available
