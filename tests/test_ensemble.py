# -*- coding: utf-8 -*-
"""
Tests for Calibrated Ensemble Scorer — Prompt 5.

Verifies:
  - EnsembleClassifier initialization and 13-class taxonomy alignment
  - Weight fitting via Logistic Regression / grid search on validation data
  - score_flow contract: (label, confidence, per_model_breakdown)
  - Condition 1: Stacking meta-models and validation-derived weights
  - Condition 2: Propagation of SequenceClassifier caveat in all breakdowns
  - Condition 3: Explicit exclusion of SequenceClassifier when history_window is absent
  - Fallback modes: rf_only, xgb_only, rf_xgb
  - Scoped n_jobs=1 on RF instance
  - FastAPI /score/flow endpoint with model query parameters
  - src.api.app re-exports
"""

import os
import pytest
import numpy as np
from fastapi.testclient import TestClient

from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES, NUM_FEATURES
from src.models.classifier import DDoSClassifier, CICDDOS2019_CLASSES
from src.models.sequence_classifier import SequenceClassifier, PSEUDO_TEMPORAL_CAVEAT
from src.models.ensemble import (
    EnsembleClassifier,
    score_flow,
    get_default_ensemble,
)
from src.api.scoring_service import app, _generated_dev_key, API_KEYS
import src.api.scoring_service as api_module


def get_active_api_key():
    return next(iter(api_module.API_KEYS)) if api_module.API_KEYS else (_generated_dev_key or "test-api-key")


TEST_API_KEY = _generated_dev_key or "test-api-key"


@pytest.fixture
def dummy_features():
    """Deterministic dummy feature vector of 77 features."""
    rng = np.random.RandomState(42)
    return rng.randn(NUM_FEATURES).astype(np.float32)


@pytest.fixture
def dummy_history_window():
    """Deterministic sliding window of 5 snapshots (5, 77)."""
    rng = np.random.RandomState(42)
    return rng.randn(5, NUM_FEATURES).astype(np.float32)


@pytest.fixture
def ensemble_instance():
    """Default EnsembleClassifier instance for testing."""
    return EnsembleClassifier(device="cpu")


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


def test_ensemble_initialization(ensemble_instance):
    """Verify EnsembleClassifier initializes RF, XGB, Seq and matches 13 classes."""
    ens = ensemble_instance
    assert ens.classes == CICDDOS2019_CLASSES
    assert len(ens.classes) == 13
    assert ens.rf_classifier is not None
    assert ens.xgb_classifier is not None
    assert ens.seq_classifier is not None


def test_score_flow_return_contract(ensemble_instance, dummy_features):
    """Verify score_flow returns (label, confidence, per_model_breakdown)."""
    label, confidence, breakdown = ensemble_instance.score_flow(dummy_features)

    assert isinstance(label, str)
    assert label in CICDDOS2019_CLASSES
    assert isinstance(confidence, float)
    assert 0.0 <= confidence <= 1.0

    assert isinstance(breakdown, dict)
    assert "random_forest" in breakdown
    assert "xgboost" in breakdown
    assert "sequence_classifier" in breakdown
    assert "weights" in breakdown
    assert "mode" in breakdown


def test_ensemble_without_history_window(ensemble_instance, dummy_features):
    """Condition 3: Verify SequenceClassifier is explicitly excluded when history_window is absent."""
    label, confidence, breakdown = ensemble_instance.score_flow(
        features=dummy_features, history_window=None
    )

    seq_info = breakdown["sequence_classifier"]
    # Must explicitly state exclusion due to lack of temporal sequence
    assert seq_info.get("excluded_due_to_missing_history") is True
    assert seq_info.get("label") is None
    assert seq_info.get("confidence") is None

    # Condition 2: Caveat must still be propagated
    assert seq_info.get("caveat") == PSEUDO_TEMPORAL_CAVEAT

    # Final decision must be driven by tabular models (RF/XGB), not dragged by 0-step LSTM
    assert breakdown["mode"] in ("ensemble_tabular", "rf_xgb")
    assert confidence > 0.0


def test_ensemble_with_history_window(ensemble_instance, dummy_features, dummy_history_window):
    """Verify SequenceClassifier is active when a multi-step history_window is provided."""
    label, confidence, breakdown = ensemble_instance.score_flow(
        features=dummy_features, history_window=dummy_history_window
    )

    seq_info = breakdown["sequence_classifier"]
    assert seq_info.get("excluded_due_to_missing_history") is not True
    assert seq_info.get("label") in CICDDOS2019_CLASSES
    assert isinstance(seq_info.get("confidence"), float)
    assert 0.0 <= seq_info.get("confidence") <= 1.0

    # Condition 2: Caveat must be present
    assert seq_info.get("caveat") == PSEUDO_TEMPORAL_CAVEAT
    assert breakdown["mode"] == "ensemble_full"


def test_caveat_propagated_in_all_modes(ensemble_instance, dummy_features):
    """Condition 2: Verify caveat is present across all query modes."""
    for mode in ["ensemble", "rf_only", "xgb_only", "rf_xgb"]:
        _, _, breakdown = ensemble_instance.score_flow(dummy_features, mode=mode)
        assert "sequence_classifier" in breakdown
        assert breakdown["sequence_classifier"]["caveat"] == PSEUDO_TEMPORAL_CAVEAT


def test_ensemble_fallback_modes(ensemble_instance, dummy_features):
    """Verify fallback query modes rf_only, xgb_only, and rf_xgb."""
    # 1. RF only
    label_rf, conf_rf, bkd_rf = ensemble_instance.score_flow(dummy_features, mode="rf_only")
    assert bkd_rf["mode"] == "rf_only"
    assert bkd_rf["weights"] == {"random_forest": 1.0}
    assert "random_forest" in bkd_rf
    assert "xgboost" not in bkd_rf or bkd_rf.get("xgboost") is None

    # 2. XGB only
    label_xgb, conf_xgb, bkd_xgb = ensemble_instance.score_flow(dummy_features, mode="xgb_only")
    assert bkd_xgb["mode"] == "xgb_only"
    assert bkd_xgb["weights"] == {"xgboost": 1.0}
    assert "xgboost" in bkd_xgb
    assert "random_forest" not in bkd_xgb or bkd_xgb.get("random_forest") is None

    # 3. RF + XGB
    label_tab, conf_tab, bkd_tab = ensemble_instance.score_flow(dummy_features, mode="rf_xgb")
    assert bkd_tab["mode"] == "rf_xgb"
    assert "random_forest" in bkd_tab
    assert "xgboost" in bkd_tab


def test_rf_n_jobs_scoped_to_ensemble():
    """Verify rf.model.n_jobs=1 is scoped to the ensemble and does not mutate shared RF."""
    # Create an independent RF instance
    rf_independent = DDoSClassifier("models/cicddos2019_rf.pkl")
    original_n_jobs = getattr(rf_independent.model, "n_jobs", None)

    # Instantiate ensemble
    ens = EnsembleClassifier()
    assert getattr(ens.rf_classifier.model, "n_jobs", None) == 1

    # Verify original instance's n_jobs attribute was not changed
    assert getattr(rf_independent.model, "n_jobs", None) == original_n_jobs


def test_fit_weights_on_synthetic_data(tmp_path):
    """Condition 1: Verify fit_weights fits LogisticRegression meta-model and grid weights."""
    ens = EnsembleClassifier(device="cpu")
    rng = np.random.RandomState(42)

    val_X = rng.randn(30, NUM_FEATURES).astype(np.float32)
    val_y = np.array([ens.classes[i % len(ens.classes)] for i in range(30)])

    save_path = str(tmp_path / "test_weights.joblib")
    report = ens.fit_weights(val_X, val_y, save_path=save_path)

    assert "tabular_meta_accuracy" in report
    assert "scalar_weights_tabular" in report
    assert "scalar_weights_full" in report

    # Weights must sum to 1.0
    tab_sum = sum(report["scalar_weights_tabular"].values())
    assert pytest.approx(tab_sum, abs=1e-2) == 1.0

    full_sum = sum(report["scalar_weights_full"].values())
    assert pytest.approx(full_sum, abs=1e-2) == 1.0

    # SequenceClassifier contribution must never exceed 0.15 safety cap
    assert report["scalar_weights_full"]["sequence_classifier"] <= 0.15

    assert os.path.isfile(save_path)


def test_module_level_score_flow(dummy_features):
    """Verify module-level score_flow() function."""
    label, conf, bkd = score_flow(dummy_features)
    assert label in CICDDOS2019_CLASSES
    assert 0.0 <= conf <= 1.0
    assert "weights" in bkd


def test_api_score_flow_with_model_param(client):
    """Verify /score/flow endpoint with model query parameters."""
    dummy_payload = {"features": {" Destination Port": 80, " Flow Duration": 1000}}
    key = get_active_api_key()

    # 1. Default (automated real-time path: xgb_only)
    res = client.post(
        "/score/flow",
        json=dummy_payload,
        headers={"X-API-Key": key},
    )
    assert res.status_code == 200
    data = res.json()
    assert "result" in data
    assert "per_model_breakdown" in data["result"]
    assert data["result"]["per_model_breakdown"]["mode"] == "xgb_only"

    # 2. Explicit ensemble query param
    res_ens = client.post(
        "/score/flow?model=ensemble",
        json=dummy_payload,
        headers={"X-API-Key": key},
    )
    assert res_ens.status_code == 200
    assert "weights" in res_ens.json()["result"]["per_model_breakdown"]
    assert res_ens.json()["result"]["per_model_breakdown"]["mode"] in ("ensemble_tabular", "rf_xgb")

    # 3. RF only query param
    res_rf = client.post(
        "/score/flow?model=rf_only",
        json=dummy_payload,
        headers={"X-API-Key": key},
    )
    assert res_rf.status_code == 200
    assert res_rf.json()["result"]["per_model_breakdown"]["mode"] == "rf_only"

    # 3. XGB only query param
    res_xgb = client.post(
        "/score/flow?model=xgb_only",
        json=dummy_payload,
        headers={"X-API-Key": key},
    )
    assert res_xgb.status_code == 200
    assert res_xgb.json()["result"]["per_model_breakdown"]["mode"] == "xgb_only"

    # 4. History window in payload
    history_payload = {
        "features": {" Destination Port": 80, " Flow Duration": 1000},
        "history_window": [
            {" Destination Port": 80, " Flow Duration": 500},
            {" Destination Port": 80, " Flow Duration": 750},
            {" Destination Port": 80, " Flow Duration": 1000},
        ],
    }
    res_hw = client.post(
        "/score/flow",
        json=history_payload,
        headers={"X-API-Key": TEST_API_KEY},
    )
    assert res_hw.status_code == 200
    bkd = res_hw.json()["result"]["per_model_breakdown"]
    assert bkd["mode"] == "ensemble_full"
    assert bkd["sequence_classifier"]["caveat"] == PSEUDO_TEMPORAL_CAVEAT


def test_app_py_reexport():
    """Verify src.api.app exposes app instance and schemas."""
    from src.api.app import app as app_instance, score_flow as sf_endpoint
    assert app_instance is not None
    assert callable(sf_endpoint)


def test_production_fails_loudly_when_models_missing(monkeypatch):
    """
    Verify production safety guard: EnsembleClassifier must raise FileNotFoundError
    if model files are missing and no test/CI environment variables are set.
    """
    for env_var in ("CI", "GITHUB_ACTIONS", "PYTEST_CURRENT_TEST", "DDOS_ALLOW_TEST_DUMMY"):
        monkeypatch.delenv(env_var, raising=False)

    with pytest.raises(FileNotFoundError, match="Dummy fallback is strictly forbidden in production"):
        EnsembleClassifier(rf_path="/nonexistent/path/rf.pkl", xgb_path="/nonexistent/path/xgb.pkl")


def test_test_env_permits_dummy_fallback(monkeypatch):
    """
    Verify test/CI environment permits dummy fallback when explicit opt-in is provided.
    """
    monkeypatch.setenv("DDOS_ALLOW_TEST_DUMMY", "1")
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)

    ens = EnsembleClassifier(rf_path="/nonexistent/path/rf.pkl", xgb_path="/nonexistent/path/xgb.pkl")
    assert ens.rf_classifier is not None
    assert ens.xgb_classifier is not None


def test_degraded_confidence_metadata_and_reasons():
    """
    Verify feature_completeness and source_mode handling:
    1. host_ingress mode with completeness=0.7013 generates degraded_confidence=True
       and host_ingress-specific reason text.
    2. cloud_flow_log mode with completeness=0.2468 generates cloud_flow_log-specific reason.
    3. minor degradation (e.g. 0.90) sets degraded_confidence=True but degradation_reason is None.
    4. pristine input (1.0) sets degraded_confidence=False and degradation_reason=None.
    """
    ens = get_default_ensemble()
    dummy_vec = [0.0] * 77

    # 1. host_ingress mode (0.7013)
    _, _, bkd_ingress = ens.score_flow(
        dummy_vec,
        feature_completeness=0.7013,
        source_mode="host_ingress",
    )
    assert bkd_ingress["degraded_confidence"] is True
    assert bkd_ingress["feature_completeness"] == 0.7013
    assert bkd_ingress["degradation_reason"] == "host_ingress: 23 backward features unobserved and zero-filled"

    # 2. cloud_flow_log mode (0.2468)
    _, _, bkd_cloud = ens.score_flow(
        dummy_vec,
        feature_completeness=0.2468,
        source_mode="cloud_flow_log",
    )
    assert bkd_cloud["degraded_confidence"] is True
    assert bkd_cloud["feature_completeness"] == 0.2468
    assert bkd_cloud["degradation_reason"] == "cloud flow log: limited field set, 19/77 features populated"
    assert "host_ingress" not in bkd_cloud["degradation_reason"]

    # 3. Minor degradation gap (< 1.0 but > 0.75)
    _, _, bkd_minor = ens.score_flow(
        dummy_vec,
        feature_completeness=0.90,
        source_mode="tap",
    )
    assert bkd_minor["degraded_confidence"] is True
    assert bkd_minor["degradation_reason"] is None

    # 4. Pristine 1.0
    _, _, bkd_pristine = ens.score_flow(
        dummy_vec,
        feature_completeness=1.0,
        source_mode="libpcap",
    )
    assert bkd_pristine["degraded_confidence"] is False
    assert bkd_pristine["degradation_reason"] is None

