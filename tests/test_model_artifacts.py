# -*- coding: utf-8 -*-
"""Test loading and inference of exported model artifacts from src/models/."""
import os
import json
import joblib
import pandas as pd
import numpy as np
import pytest
from sklearn.metrics import f1_score, accuracy_score, classification_report
from sklearn.model_selection import train_test_split

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "src", "models")
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "Codes", "ml", "datasets")

def test_model_artifacts_exist():
    """Verify all expected model artifact files exist on disk."""
    required_files = [
        "stage1_binary_xgb.joblib",
        "stage2_triage_xgb.joblib",
        "feature_preprocessor.joblib",
        "label_encoder_stage1.joblib",
        "label_encoder_stage2.joblib",
        "taxonomy_config.json"
    ]
    for filename in required_files:
        filepath = os.path.join(MODEL_DIR, filename)
        assert os.path.isfile(filepath), f"Missing required model artifact: {filepath}"

def test_exported_artifacts_inference_and_performance():
    """Load serialized models from disk and verify full multi-class macro F1 & per-class floors on held-out samples."""
    stage1_path = os.path.join(MODEL_DIR, "stage1_binary_xgb.joblib")
    stage2_path = os.path.join(MODEL_DIR, "stage2_triage_xgb.joblib")
    preprocessor_path = os.path.join(MODEL_DIR, "feature_preprocessor.joblib")
    le1_path = os.path.join(MODEL_DIR, "label_encoder_stage1.joblib")
    le2_path = os.path.join(MODEL_DIR, "label_encoder_stage2.joblib")
    config_path = os.path.join(MODEL_DIR, "taxonomy_config.json")

    # Load artifacts directly from disk
    stage1_model = joblib.load(stage1_path)
    stage2_model = joblib.load(stage2_path)
    preprocessor = joblib.load(preprocessor_path)
    le1 = joblib.load(le1_path)
    le2 = joblib.load(le2_path)
    with open(config_path, "r", encoding="utf-8") as f:
        taxonomy_config = json.load(f)

    # Load all 17 parquet files to build a representative dataset sample
    all_files = sorted([f for f in os.listdir(DATA_DIR) if f.endswith('.parquet')])
    if not all_files:
        pytest.skip("No dataset parquet files found")

    dfs = []
    for tf in all_files:
        fp = os.path.join(DATA_DIR, tf)
        df_part = pd.read_parquet(fp)
        df_part.columns = [c.strip() for c in df_part.columns]
        dfs.append(df_part)

    full_raw = pd.concat(dfs, ignore_index=True)

    feature_cols = preprocessor['feature_cols']
    medians = preprocessor['medians']

    # Apply dataset deduplication on features
    full_sample = full_raw.drop_duplicates(subset=feature_cols).reset_index(drop=True)

    # Normalize labels using taxonomy configuration maps
    raw_norm_map = taxonomy_config['raw_label_normalization_map']
    stage2_map = taxonomy_config['stage2_consolidation_map']

    clean_labels = full_sample['Label'].map(lambda x: raw_norm_map.get(str(x).strip(), str(x).strip()))
    true_binary = clean_labels.apply(lambda x: 'Benign' if x == 'Benign' else 'Attack')

    # Take a stratified 10,000 sample for test evaluation
    X_sample = full_sample[feature_cols].copy()
    X_sample = X_sample.replace([np.inf, -np.inf], np.nan)
    for col, val in medians.items():
        if col in X_sample.columns:
            X_sample[col] = X_sample[col].fillna(val)

    X_sub, _, y1_sub, _, clean_sub, _ = train_test_split(
        X_sample, true_binary, clean_labels, train_size=10000, random_state=42, stratify=clean_labels
    )

    # 1. Stage 1 Inference & Assertion
    preds_s1_idx = stage1_model.predict(X_sub)
    preds_s1_label = le1.inverse_transform(preds_s1_idx)

    s1_macro_f1 = f1_score(y1_sub, preds_s1_label, average='macro')
    assert s1_macro_f1 >= 0.9900, f"Expected Stage 1 Macro F1 >= 0.9900, got {s1_macro_f1:.4f}"

    # 2. Stage 2 Inference & Assertion on Attack flows
    attack_mask = ~clean_sub.isin(['Benign', 'WebDDoS'])
    X_attacks = X_sub[attack_mask]
    true_stage2_labels = clean_sub[attack_mask].map(stage2_map)

    preds_s2_idx = stage2_model.predict(X_attacks)
    preds_s2_label = le2.inverse_transform(preds_s2_idx)

    s2_report = classification_report(true_stage2_labels, preds_s2_label, output_dict=True)
    s2_macro_f1 = f1_score(true_stage2_labels, preds_s2_label, average='macro')

    # Overall Stage 2 Macro F1 Assertion across all 6 classes (>= 0.9500)
    assert s2_macro_f1 >= 0.9500, f"Expected Stage 2 6-Class Macro F1 >= 0.9500, got {s2_macro_f1:.4f}"

    # Per-Class Floor Assertions for weaker classes
    refl_amp_f1 = s2_report['Reflection-Amplification']['f1-score']
    udp_based_f1 = s2_report['UDP-Based']['f1-score']

    assert refl_amp_f1 >= 0.8500, f"Expected Reflection-Amplification F1 >= 0.8500, got {refl_amp_f1:.4f}"
    assert udp_based_f1 >= 0.8500, f"Expected UDP-Based F1 >= 0.8500, got {udp_based_f1:.4f}"
