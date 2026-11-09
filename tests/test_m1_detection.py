# -*- coding: utf-8 -*-
"""
M1 tests: zero-day novelty detector, leakage-safe splits, L7 low-and-slow.
"""
import numpy as np
import pytest
from fastapi.testclient import TestClient

from src.models.anomaly_novelty import NoveltyDetector
from src.models.eval_split import group_split, time_split, assert_no_group_overlap
from src.features.l7_lowslow import LowSlowDetector, LowSlowConfig


# --------------------------- Novelty detector ---------------------------------
def test_novelty_flags_heldout_outliers():
    rng = np.random.default_rng(0)
    benign = rng.normal(0.0, 1.0, size=(600, 20))
    det = NoveltyDetector(n_estimators=120).fit(benign)

    inliers = rng.normal(0.0, 1.0, size=(100, 20))
    heldout_attack = rng.normal(8.0, 1.0, size=(100, 20))  # unseen cluster

    assert det.anomaly_score(heldout_attack).mean() > det.anomaly_score(inliers).mean()
    assert det.is_novel(heldout_attack).mean() > 0.8
    assert det.is_novel(inliers).mean() < 0.3


def test_novelty_save_load_roundtrip(tmp_path):
    rng = np.random.default_rng(1)
    det = NoveltyDetector(n_estimators=60).fit(rng.normal(size=(200, 10)))
    sample = rng.normal(5.0, 1.0, size=(5, 10))
    before = det.anomaly_score(sample)
    path = str(tmp_path / "novelty.joblib")
    det.save(path)
    reloaded = NoveltyDetector.load(path)
    np.testing.assert_allclose(before, reloaded.anomaly_score(sample))


def test_novelty_handles_nan_inf():
    det = NoveltyDetector(n_estimators=40).fit(np.random.default_rng(2).normal(size=(100, 6)))
    bad = np.array([[np.nan, np.inf, -np.inf, 0.0, 1.0, 2.0]])
    score = det.anomaly_score(bad)
    assert score.shape == (1,)
    assert np.isfinite(score).all()


# --------------------------- Leakage-safe splits ------------------------------
def test_group_split_zero_overlap():
    groups = np.array([f"capture_{i % 10}" for i in range(1000)])
    train_idx, test_idx = group_split(groups, test_frac=0.3, random_state=1)
    assert len(set(train_idx) & set(test_idx)) == 0
    assert_no_group_overlap(groups, train_idx, test_idx)
    assert len(train_idx) + len(test_idx) == 1000
    # The split is by whole capture, so some captures are entirely held out.
    assert len(set(groups[test_idx])) >= 1


def test_time_split_is_chronological():
    timestamps = np.arange(100)[::-1].astype(float)  # reversed order on purpose
    train_idx, test_idx = time_split(timestamps, test_frac=0.2)
    assert timestamps[train_idx].max() <= timestamps[test_idx].min()


def test_group_split_requires_two_groups():
    with pytest.raises(ValueError):
        group_split(np.array(["only_one"] * 50))


# --------------------------- L7 low-and-slow ----------------------------------
def test_lowslow_flags_slowloris():
    det = LowSlowDetector(LowSlowConfig(concurrent_threshold=20, min_duration_sec=10, max_bytes_per_sec=50))
    alert = None
    for i in range(25):
        alert = det.observe(
            {
                "src_ip": f"10.0.0.{i}", "src_port": 1000 + i,
                "dst_ip": "10.0.0.250", "dst_port": 80,
                "duration_sec": 30.0, "fwd_bytes": 200, "header_complete": False,
            },
            now=1000.0,
        )
    assert alert is not None
    assert alert["attack_hint"] == "Slowloris/RUDY"
    assert alert["concurrent_slow_connections"] >= 20


def test_lowslow_ignores_normal_fast_requests():
    det = LowSlowDetector(LowSlowConfig(concurrent_threshold=20))
    for i in range(60):
        result = det.observe(
            {
                "src_ip": f"10.0.0.{i}", "src_port": 2000 + i,
                "dst_ip": "10.0.0.250", "dst_port": 80,
                "duration_sec": 0.2, "fwd_bytes": 8000, "header_complete": True,
            },
            now=1000.0,
        )
        assert result is None
    assert det.active_slow_count("10.0.0.250", 80) == 0


# --------------------------- OOD + low-slow wired into /score/flow ------------
def test_score_flow_includes_ood_block():
    from src.api import scoring_service as svc

    with TestClient(svc.app) as client:
        cols = svc.registry.feature_cols
        assert cols, "registry feature columns should be loaded"
        body = {"features": {c: 0.0 for c in cols}}
        resp = client.post("/score/flow", json=body,
                           headers={"X-API-Key": svc._generated_dev_key or "x"})
        assert resp.status_code == 200, resp.text
        ood = resp.json().get("ood")
        assert ood is not None
        assert set(["ood_score", "tau", "ood_suspected"]).issubset(ood.keys())


def test_score_flow_low_slow_fires_on_concurrent_slow_connections(monkeypatch):
    from src.api import scoring_service as svc

    monkeypatch.setattr(svc, "_LOWSLOW", LowSlowDetector(LowSlowConfig(concurrent_threshold=20)))
    with TestClient(svc.app) as client:
        cols = svc.registry.feature_cols
        last = None
        for i in range(24):
            feats = {c: 0.0 for c in cols}
            feats.update({
                "Flow Duration": 30_000_000.0,        # 30s in microseconds -> "slow"
                "Fwd Packets Length Total": 200.0,     # starved byte-rate
                "src_ip": f"10.9.9.{i}", "Destination Port": 80,
            })
            resp = client.post("/score/flow", json={"features": feats},
                               headers={"X-API-Key": svc._generated_dev_key or "x"})
            assert resp.status_code == 200, resp.text
            last = resp.json().get("low_slow")
        assert last is not None
        assert last["attack_hint"] == "Slowloris/RUDY"
        assert last["concurrent_slow_connections"] >= 20
