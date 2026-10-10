# -*- coding: utf-8 -*-
"""
Tests for Multi-Dataset Retraining Pipeline (src/models/train_multi_dataset.py).

Covers:
  - load_and_merge_datasets: schema, provenance, label normalization
  - train_and_evaluate_multi_dataset: aggregate + per-dataset metrics
  - Performance gate: gate_passed logic
  - Saved bundle inference
"""

import os
import json
import tempfile
import pytest
import numpy as np
import pandas as pd

from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES, NUM_FEATURES, Packet
from src.features.dataset_registry import load_dataset
from src.models.classifier import DDoSClassifier, CICDDOS2019_CLASSES
from src.models.train_multi_dataset import (
    load_and_merge_datasets,
    train_and_evaluate_multi_dataset,
    EXTENDED_CANONICAL_CLASSES,
)


@pytest.fixture
def synthetic_multi_sources():
    """Create multi-source synthetic data for training pipeline tests."""
    np.random.seed(42)

    # 1. CICDDoS2019 sample
    cic_data = []
    labels_cic = ["DrDoS_DNS", "Syn", "BENIGN", "UDP-lag"]
    for i in range(40):
        row = {col: float(np.random.uniform(1.0, 100.0)) for col in CICFLOWMETER_FEATURE_NAMES}
        row[" Protocol"] = float(np.random.choice([6, 17]))
        row[" Label"] = labels_cic[i % len(labels_cic)]
        cic_data.append(row)

    # 2. CICIoT2023 sample
    iot_data = []
    labels_iot = ["DDoS-SYN_Flood", "DDoS-UDP_Flood", "BenignTraffic"]
    for i in range(30):
        row = {
            "flow_duration": float(np.random.uniform(10.0, 500.0)),
            "Protocol Type": 6.0 if i % 2 == 0 else 17.0,
            "Header_Length": 32.0,
            "ack_count": float(i % 5),
            "syn_count": float(i % 10),
            "label": labels_iot[i % len(labels_iot)],
        }
        for col in CICFLOWMETER_FEATURE_NAMES:
            if col not in row:
                row[col] = float(np.random.uniform(0.0, 50.0))
        iot_data.append(row)

    # 3. CAIDA sample
    caida_data = []
    labels_caida = ["syn_flood", "ddos", "normal"]
    for i in range(30):
        row = {
            "duration": float(np.random.uniform(1.0, 50.0)),
            "proto": 6.0,
            "pkts": float(10 + i),
            "bytes": float(100 + i * 50),
            "attack_type": labels_caida[i % len(labels_caida)],
        }
        for col in CICFLOWMETER_FEATURE_NAMES:
            if col not in row:
                row[col] = float(np.random.uniform(0.0, 20.0))
        caida_data.append(row)

    return [
        ("cicddos2019", pd.DataFrame(cic_data)),
        ("ciciot2023", pd.DataFrame(iot_data)),
        ("caida", pd.DataFrame(caida_data)),
    ]


def test_load_and_merge_datasets(synthetic_multi_sources):
    """Verify merged dataset has correct schema, provenance, and labels."""
    df_merged = load_and_merge_datasets(sources=synthetic_multi_sources)
    assert isinstance(df_merged, pd.DataFrame)
    assert "Normalized_Label" in df_merged.columns
    assert "_source_dataset" in df_merged.columns

    # 77 features + Normalized_Label + _source_dataset = 79
    assert len(df_merged.columns) == NUM_FEATURES + 2
    assert len(df_merged) > 0

    # All features from CICFLOWMETER_FEATURE_NAMES present
    for col in CICFLOWMETER_FEATURE_NAMES:
        assert col in df_merged.columns, f"Missing feature column: {col}"

    # Ensure all labels map to canonical + extended taxonomy set
    unique_labels = set(df_merged["Normalized_Label"].unique())
    assert unique_labels.issubset(EXTENDED_CANONICAL_CLASSES)


def test_source_provenance_tracked(synthetic_multi_sources):
    """Verify each row retains its source dataset provenance."""
    df_merged = load_and_merge_datasets(sources=synthetic_multi_sources)
    source_values = set(df_merged["_source_dataset"].unique())
    assert "cicddos2019" in source_values
    assert "ciciot2023" in source_values
    assert "caida" in source_values


def test_feature_count_matches_flow_extractor(synthetic_multi_sources):
    """Verify pipeline uses exactly NUM_FEATURES (77) feature columns."""
    df_merged = load_and_merge_datasets(sources=synthetic_multi_sources)
    feature_cols_in_df = [c for c in df_merged.columns if c in CICFLOWMETER_FEATURE_NAMES]
    assert len(feature_cols_in_df) == NUM_FEATURES


def test_train_and_evaluate_multi_dataset(synthetic_multi_sources):
    """End-to-end test: train, evaluate aggregate + per-dataset, check reports."""
    with tempfile.TemporaryDirectory() as tmp_out, tempfile.TemporaryDirectory() as tmp_eval:
        # Use a low baseline so synthetic data passes the gate
        results = train_and_evaluate_multi_dataset(
            sources=synthetic_multi_sources,
            output_dir=tmp_out,
            eval_dir=tmp_eval,
            random_state=42,
            baseline_f1=0.0,  # Ensure gate passes for test
        )

        assert "XGBoost" in results
        assert "RandomForest" in results

        for model_name in ["XGBoost", "RandomForest"]:
            metrics = results[model_name]
            assert "accuracy" in metrics
            assert "macro_f1" in metrics
            assert "weighted_f1" in metrics
            assert "classification_report" in metrics
            assert "confusion_matrix" in metrics
            assert metrics["accuracy"] >= 0.0

            # Per-dataset evaluation must be present
            assert "per_dataset" in metrics
            per_ds = metrics["per_dataset"]
            assert isinstance(per_ds, dict)
            assert len(per_ds) > 0

            # Each source should have evaluation metrics
            for src_name, src_metrics in per_ds.items():
                assert "accuracy" in src_metrics
                assert "macro_f1" in src_metrics
                assert "weighted_f1" in src_metrics
                assert "sample_count" in src_metrics
                assert "classification_report" in src_metrics
                assert "confusion_matrix" in src_metrics
                assert src_metrics["sample_count"] > 0

        # Check saved bundles (gate passed with baseline_f1=0.0)
        assert os.path.exists(os.path.join(tmp_out, "cicddos2019_xgboost.pkl"))
        assert os.path.exists(os.path.join(tmp_out, "cicddos2019_rf.pkl"))

        # Check evaluation reports
        assert os.path.exists(os.path.join(tmp_eval, "multi_dataset_evaluation.md"))
        assert os.path.exists(os.path.join(tmp_eval, "eval_report.json"))

        # Check JSON report content
        with open(os.path.join(tmp_eval, "eval_report.json")) as f:
            eval_json = json.load(f)
            assert "XGBoost" in eval_json
            assert "confusion_matrix" in eval_json["XGBoost"]
            assert "per_dataset" in eval_json["XGBoost"]


def test_performance_gate_blocks_save(synthetic_multi_sources):
    """Verify that an impossibly high baseline prevents production bundle saving."""
    with tempfile.TemporaryDirectory() as tmp_out, tempfile.TemporaryDirectory() as tmp_eval:
        results = train_and_evaluate_multi_dataset(
            sources=synthetic_multi_sources,
            output_dir=tmp_out,
            eval_dir=tmp_eval,
            random_state=42,
            baseline_f1=1.0,  # Impossible to achieve perfectly — gate should fail
        )

        gate = results.get("_performance_gate", {})
        # If the model achieves 1.0 F1 (unlikely but possible with synthetic data), skip
        if gate.get("best_achieved_f1", 0) < 1.0:
            assert gate["gate_passed"] is False
            # Bundles should NOT be saved
            assert not os.path.exists(os.path.join(tmp_out, "cicddos2019_xgboost.pkl"))
            assert not os.path.exists(os.path.join(tmp_out, "cicddos2019_rf.pkl"))

        # Evaluation reports should ALWAYS be saved regardless of gate
        assert os.path.exists(os.path.join(tmp_eval, "eval_report.json"))
        assert os.path.exists(os.path.join(tmp_eval, "multi_dataset_evaluation.md"))


def test_performance_gate_passes_and_saves(synthetic_multi_sources):
    """Verify that meeting the baseline allows production bundle saving."""
    with tempfile.TemporaryDirectory() as tmp_out, tempfile.TemporaryDirectory() as tmp_eval:
        results = train_and_evaluate_multi_dataset(
            sources=synthetic_multi_sources,
            output_dir=tmp_out,
            eval_dir=tmp_eval,
            random_state=42,
            baseline_f1=0.0,  # Any non-zero F1 passes
        )

        gate = results.get("_performance_gate", {})
        assert gate["gate_passed"] is True
        assert os.path.exists(os.path.join(tmp_out, "cicddos2019_xgboost.pkl"))
        assert os.path.exists(os.path.join(tmp_out, "cicddos2019_rf.pkl"))


def test_saved_bundles_inference(synthetic_multi_sources):
    """Verify saved model bundles can perform inference correctly."""
    with tempfile.TemporaryDirectory() as tmp_out, tempfile.TemporaryDirectory() as tmp_eval:
        train_and_evaluate_multi_dataset(
            sources=synthetic_multi_sources,
            output_dir=tmp_out,
            eval_dir=tmp_eval,
            random_state=42,
            baseline_f1=0.0,
        )

        xgb_path = os.path.join(tmp_out, "cicddos2019_xgboost.pkl")
        clf = DDoSClassifier(xgb_path)

        # Predict sample vector
        sample_vec = [1.0] * len(CICFLOWMETER_FEATURE_NAMES)
        pred_label = clf.predict(sample_vec)
        assert pred_label in EXTENDED_CANONICAL_CLASSES


def test_eval_markdown_contains_per_dataset_section(synthetic_multi_sources):
    """Verify the Markdown report contains per-dataset evaluation sections."""
    with tempfile.TemporaryDirectory() as tmp_out, tempfile.TemporaryDirectory() as tmp_eval:
        train_and_evaluate_multi_dataset(
            sources=synthetic_multi_sources,
            output_dir=tmp_out,
            eval_dir=tmp_eval,
            random_state=42,
            baseline_f1=0.0,
        )

        md_path = os.path.join(tmp_eval, "multi_dataset_evaluation.md")
        with open(md_path, "r", encoding="utf-8") as f:
            md_content = f.read()

        assert "Per-Dataset Evaluation" in md_content
        assert "Performance Gate" in md_content
        assert "cicddos2019" in md_content or "ciciot2023" in md_content or "caida" in md_content
