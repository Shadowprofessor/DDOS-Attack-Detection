# -*- coding: utf-8 -*-
"""
Tests for Sequence Classifier (BiLSTM) and Training Pipeline — Prompt 4.
"""

import os
import sys
import time
import tempfile
import pytest
import numpy as np
import torch

from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES, NUM_FEATURES
from src.models.classifier import CICDDOS2019_CLASSES
from src.models.sequence_classifier import (
    BiLSTMSequenceModel,
    SequenceClassifier,
    PSEUDO_TEMPORAL_CAVEAT,
)
from src.models.train_sequence import (
    build_synthetic_windows,
    is_slowloris_proxy,
    oversample_slow_attacks,
    train_sequence_model,
)


@pytest.fixture
def dummy_features():
    """Generate deterministic dummy feature matrix of shape (10, 77)."""
    np.random.seed(42)
    return np.random.randn(10, NUM_FEATURES).astype(np.float32)


@pytest.fixture
def sequence_clf():
    """Create a default SequenceClassifier instance on CPU."""
    torch.manual_seed(42)
    return SequenceClassifier(window_size=10, device="cpu")


def test_bilstm_forward_shape():
    """Verify BiLSTM model output shape is (batch, num_classes) for (batch, W, 77)."""
    batch_size = 4
    window_size = 10
    model = BiLSTMSequenceModel(num_features=77, num_classes=13, hidden_size=128, num_layers=2)
    x = torch.randn(batch_size, window_size, 77)
    logits = model(x)
    assert logits.shape == (batch_size, 13)


def test_variable_window_sizes():
    """Verify model can process variable sequence lengths (1, 5, 10, 20)."""
    model = BiLSTMSequenceModel(num_features=77, num_classes=13)
    model.eval()
    for seq_len in [1, 5, 10, 20]:
        x = torch.randn(2, seq_len, 77)
        with torch.no_grad():
            out = model(x)
        assert out.shape == (2, 13)


def test_short_window_padding(sequence_clf):
    """Verify windows shorter than window_size are zero-padded and produce valid output."""
    short_window = np.random.randn(3, NUM_FEATURES).astype(np.float32)
    res = sequence_clf.predict_window(short_window)
    assert "label" in res
    assert "confidence" in res
    assert isinstance(res["confidence"], float)
    assert 0.0 <= res["confidence"] <= 1.0
    assert len(res["probabilities"]) == len(sequence_clf.classes)


def test_nan_inf_safety(sequence_clf):
    """Verify NaNs and Infs do not crash inference or result in NaN predictions."""
    dirty_window = np.random.randn(10, NUM_FEATURES).astype(np.float32)
    dirty_window[0, 5] = np.nan
    dirty_window[2, 10] = np.inf
    dirty_window[4, 15] = -np.inf
    dirty_window[7, :] = np.nan

    res = sequence_clf.predict_window(dirty_window)
    assert not np.isnan(res["confidence"])
    assert not np.isinf(res["confidence"])
    for cls_name, prob in res["probabilities"].items():
        assert not np.isnan(prob)
        assert not np.isinf(prob)


def test_predict_vector_interface(sequence_clf):
    """Verify predict_vector satisfies the exact DDoSClassifier interface contract."""
    vec = np.random.randn(NUM_FEATURES).astype(np.float32)
    res = sequence_clf.predict_vector(vec)

    assert set(res.keys()) == {"label", "is_attack", "confidence", "probabilities"}
    assert isinstance(res["label"], str)
    assert isinstance(res["is_attack"], bool)
    assert isinstance(res["confidence"], float)
    assert isinstance(res["probabilities"], dict)

    # Probabilities should sum to approximately 1.0
    total_prob = sum(res["probabilities"].values())
    assert abs(total_prob - 1.0) < 1e-4

    # Convenience predict() method returns class label string
    pred_str = sequence_clf.predict(vec)
    assert pred_str == res["label"]

    # Also test dict-based feature input
    dict_vec = {name: float(vec[i]) for i, name in enumerate(CICFLOWMETER_FEATURE_NAMES)}
    dict_res = sequence_clf.predict_vector(dict_vec)
    assert dict_res["label"] == res["label"]


def test_predict_window(sequence_clf, dummy_features):
    """Verify predict_window handles standard (W, 77) array input."""
    res = sequence_clf.predict_window(dummy_features)
    assert res["label"] in sequence_clf.classes
    assert isinstance(res["is_attack"], bool)
    assert 0.0 <= res["confidence"] <= 1.0


def test_predict_batch_2d_and_3d(sequence_clf):
    """Verify predict_batch handles both 2D (N, 77) and 3D (N, W, 77) inputs."""
    # 2D input: 5 separate feature vectors
    batch_2d = np.random.randn(5, NUM_FEATURES).astype(np.float32)
    res_2d = sequence_clf.predict_batch(batch_2d)
    assert len(res_2d) == 5
    for item in res_2d:
        assert "label" in item
        assert "confidence" in item

    # 3D input: 4 sliding windows of 10 timesteps each
    batch_3d = np.random.randn(4, 10, NUM_FEATURES).astype(np.float32)
    res_3d = sequence_clf.predict_batch(batch_3d)
    assert len(res_3d) == 4
    for item in res_3d:
        assert "label" in item
        assert "confidence" in item


def test_inference_latency(sequence_clf, dummy_features):
    """Verify single-window inference latency is well under 50ms per window."""
    latencies = []
    # Warmup
    for _ in range(5):
        _ = sequence_clf.predict_window(dummy_features)

    # Measure 50 iterations
    for _ in range(50):
        t0 = time.perf_counter()
        _ = sequence_clf.predict_window(dummy_features)
        t1 = time.perf_counter()
        latencies.append((t1 - t0) * 1000.0)

    p95_latency = np.percentile(latencies, 95)
    mean_latency = np.mean(latencies)
    assert p95_latency < 50.0, f"95th percentile latency {p95_latency:.2f}ms exceeds 50ms limit"
    assert mean_latency < 20.0, f"Mean latency {mean_latency:.2f}ms unexpectedly high"


def test_save_load_roundtrip(sequence_clf, dummy_features):
    """Verify save and load roundtrip preserves weights, metadata, and exact predictions."""
    orig_pred = sequence_clf.predict_window(dummy_features)

    with tempfile.TemporaryDirectory() as tmp_dir:
        model_path = os.path.join(tmp_dir, "test_seq_model.pt")
        sequence_clf.save(model_path)
        assert os.path.exists(model_path)

        loaded_clf = SequenceClassifier(device="cpu")
        loaded_clf.load(model_path)

        new_pred = loaded_clf.predict_window(dummy_features)
        assert new_pred["label"] == orig_pred["label"]
        assert abs(new_pred["confidence"] - orig_pred["confidence"]) < 1e-5
        for k in orig_pred["probabilities"]:
            assert abs(new_pred["probabilities"][k] - orig_pred["probabilities"][k]) < 1e-5


def test_classes_match_taxonomy(sequence_clf):
    """Verify model classes match the 13 canonical CICDDoS2019 classes in exact order."""
    assert len(sequence_clf.classes) == 13
    assert sequence_clf.classes == list(CICDDOS2019_CLASSES)

    # Verify exact taxonomy and index order match with production RF & XGBoost models
    import joblib

    for mpath in ["models/cicddos2019_xgboost.pkl", "models/cicddos2019_rf.pkl"]:
        if os.path.exists(mpath):
            bundle = joblib.load(mpath)
            prod_classes = list(bundle["classes"])
            assert sequence_clf.classes == prod_classes
            assert len(prod_classes) == 13


def test_pseudo_temporal_caveat_preserved(sequence_clf):
    """Verify exact caveat string required by specification is preserved."""
    exact_caveat = (
        "Trained on synthetic pseudo-temporal windows (same-class CSV rows grouped, not real "
        "sequential flows). Advantage on genuine low-and-slow attacks is UNVERIFIED until "
        "retrained on real packet-sequence data."
    )
    assert SequenceClassifier.CAVEAT == exact_caveat
    assert sequence_clf.CAVEAT == exact_caveat

    # Verify caveat is present in checkpoint
    with tempfile.TemporaryDirectory() as tmp_dir:
        mpath = os.path.join(tmp_dir, "caveat_check.pt")
        sequence_clf.save(mpath)
        checkpoint = torch.load(mpath, weights_only=False)
        assert checkpoint.get("caveat") == exact_caveat


def test_tightened_slowloris_heuristic():
    """Verify tightened Slowloris proxy heuristic with strict allowlist.
    
    Ensures WebDDoS matches, while TFTP, Syn, and Benign are strictly excluded
    even when they have high duration and low rate.
    """
    import pandas as pd

    # Benign long-lived keepalive connection (rejected)
    benign_flow = pd.Series({
        "Label": "Benign",
        "Normalized_Label": "Benign",
        "Flow Duration": 15_000_000.0,
        "Flow Packets/s": 0.5,
        "Total Fwd Packets": 10.0,
        "Fwd Packets Length Total": 500.0,
    })
    assert not is_slowloris_proxy(benign_flow)

    # TFTP orphaned/timeout flow with low rate + high duration (REJECTED by allowlist)
    tftp_flow = pd.Series({
        "Label": "TFTP",
        "Normalized_Label": "TFTP",
        "Flow Duration": 60_000_000.0,
        "Flow Packets/s": 0.03,
        "Total Fwd Packets": 2.0,
        "Fwd Packets Length Total": 120.0,
    })
    assert not is_slowloris_proxy(tftp_flow)

    # Syn orphaned/timeout flow with low rate + high duration (REJECTED by allowlist)
    syn_flow = pd.Series({
        "Label": "Syn",
        "Normalized_Label": "Syn",
        "Flow Duration": 45_000_000.0,
        "Flow Packets/s": 0.04,
        "Total Fwd Packets": 2.0,
        "Fwd Packets Length Total": 120.0,
    })
    assert not is_slowloris_proxy(syn_flow)

    # WebDDoS labeled attack flow (ACCEPTED by allowlist)
    webddos_flow = pd.Series({
        "Label": "WebDDoS",
        "Normalized_Label": "WebDDoS",
        "Flow Duration": 500.0,
        "Flow Packets/s": 2000.0,
    })
    assert is_slowloris_proxy(webddos_flow)

    # WebDDoS with slow traffic signature check
    slow_webddos = pd.Series({
        "Label": "WebDDoS",
        "Normalized_Label": "WebDDoS",
        "Flow Duration": 7_500_000.0,
        "Flow Packets/s": 2.5,
    })
    assert is_slowloris_proxy(slow_webddos, require_slow_signature=True)
    assert not is_slowloris_proxy(webddos_flow, require_slow_signature=True)
    flood_flow = pd.Series({
        "Label": "Syn",
        "Normalized_Label": "Syn",
        "Flow Duration": 500_000.0,
        "Flow Packets/s": 5000.0,
        "Total Fwd Packets": 2500.0,
        "Fwd Packets Length Total": 100_000.0,
    })
    assert not is_slowloris_proxy(flood_flow)


def test_synthetic_window_building_and_mini_train():
    """Verify window building, oversampling, and small training loop function end-to-end."""
    import pandas as pd

    np.random.seed(42)
    # Create synthetic dataset with Benign, Syn, and WebDDoS
    data = []
    for _ in range(30):
        row = {col: float(np.random.rand()) for col in CICFLOWMETER_FEATURE_NAMES}
        row["Normalized_Label"] = "Benign"
        data.append(row)

    for _ in range(30):
        row = {col: float(np.random.rand()) for col in CICFLOWMETER_FEATURE_NAMES}
        row["Normalized_Label"] = "Syn"
        data.append(row)

    for _ in range(12):
        row = {col: float(np.random.rand()) for col in CICFLOWMETER_FEATURE_NAMES}
        row["Normalized_Label"] = "WebDDoS"
        data.append(row)

    df = pd.DataFrame(data)
    X_windows, y_labels = build_synthetic_windows(df, window_size=5, stride=2)
    assert X_windows.ndim == 3
    assert X_windows.shape[1] == 5
    assert X_windows.shape[2] == NUM_FEATURES

    # Test oversampler
    X_over, y_over = oversample_slow_attacks(X_windows, y_labels, target_classes=("WebDDoS",), multiplier=3)
    assert len(X_over) > len(X_windows)

    # Mini train test (2 epochs)
    classes = ["Benign", "Syn", "WebDDoS"]
    label_map = {c: i for i, c in enumerate(classes)}
    y_enc = np.array([label_map[y] for y in y_over])

    model, history = train_sequence_model(
        X_over, y_enc, X_over, y_enc, classes=classes, epochs=2, batch_size=4, lr=1e-3, device="cpu"
    )
    assert len(history["train_loss"]) == 2
    assert isinstance(model, BiLSTMSequenceModel)
