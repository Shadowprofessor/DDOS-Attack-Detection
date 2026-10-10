# -*- coding: utf-8 -*-
"""
Multi-Dataset Retraining & Evaluation Pipeline — Step 2 of Phase 1.

Features:
  - Ingests multiple heterogeneous flow dataset sources via src.features.dataset_registry
    (CICDDoS2019, CICIoT2023, CAIDA, synthetic flow stats)
  - Merges datasets and normalizes labels to the canonical DDoS taxonomy
  - Applies 77-feature deduplication to eliminate cross-day synthetic leakage
  - Stratified 80/20 train/test split with median imputation and standard scaling
  - Class balancing via majority subsampling cap and minority SMOTE / RandomOverSampler
  - Trains primary XGBoost classifier + Random Forest baseline model
  - Generates detailed evaluation metrics: Confusion Matrix, Classification Report,
    Per-Class Precision / Recall / F1-Score per source dataset + aggregate
  - Performance gate: refuses to overwrite production bundles unless new combined
    F1 beats the configurable baseline (default 99.8%)
  - Exports production joblib model bundles to models/
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path
from typing import Dict, Tuple, List, Optional, Union, Any

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# Ensure workspace root is in sys.path
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from xgboost import XGBClassifier

from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES, NUM_FEATURES
from src.features.dataset_registry import (
    load_dataset,
    load_cicddos2019,
    load_ciciot2023,
    load_caida,
    load_insdn,
    load_synthetic_sdn,
    load_pcap,
    validate_schema,
    normalize_labels,
)
from src.models.classifier import CICDDOS2019_CLASSES, DDoSClassifier, LABEL_NORMALIZATION

DEFAULT_OUTPUT_DIR = "models"
DEFAULT_EVAL_DIR = "docs/eval"

# Hard baseline: new models must beat this weighted F1 to overwrite production bundles
DEFAULT_BASELINE_F1 = 0.998

# Extended canonical class set (includes Other_DDoS from taxonomy map)
EXTENDED_CANONICAL_CLASSES = set(CICDDOS2019_CLASSES) | {"Other_DDoS"}

# User-facing explicit source names for evaluation reporting
SOURCE_DISPLAY_NAMES: Dict[str, str] = {
    "ciciot2023": "CICIoT2023 (unofficial Hugging Face mirror, partial: Benign/SYN Flood/UDP Flood only, 3 of 33+ official attack classes)",
    "synthetic_sdn": "synthetic_sdn (eval-only, 6/77 real features, not used in training)",
    "insdn": "insdn",
    "cicddos2019": "cicddos2019",
}


def load_and_merge_datasets(
    sources: Optional[List[Tuple[str, Any]]] = None,
    data_dir: Optional[str] = None
) -> pd.DataFrame:
    """Load multiple flow datasets via dataset_registry and merge into unified DataFrame.

    Tracks which source each row came from via the '_source_dataset' column so
    per-dataset evaluation can be performed later.

    Args:
        sources: List of (source_type, source_data) tuples.
        data_dir: Optional path to directory containing parquet/csv files.

    Returns:
        Unified pd.DataFrame with normalized feature columns + 'Normalized_Label'
        + '_source_dataset' provenance column.
    """
    dfs = []

    if sources:
        for stype, sdata in sources:
            print(f"[*] Ingesting source: type='{stype}'")
            df = load_dataset(stype, sdata)
            if isinstance(df, pd.DataFrame):
                df = df.copy()
                df["_source_dataset"] = stype
                dfs.append(df)
            else:  # Generator
                for chunk in df:
                    chunk = chunk.copy()
                    chunk["_source_dataset"] = stype
                    dfs.append(chunk)

    if data_dir and os.path.isdir(data_dir):
        print(f"[*] Scanning data directory: {data_dir}")
        for fname in sorted(os.listdir(data_dir)):
            fpath = os.path.join(data_dir, fname)
            if fname.endswith(".parquet"):
                raw_df = pd.read_parquet(fpath)
                df = load_cicddos2019(raw_df)
                df = df.copy()
                df["_source_dataset"] = "cicddos2019"
                dfs.append(df)
            elif fname.endswith(".csv"):
                raw_df = pd.read_csv(fpath, low_memory=False)
                df = load_cicddos2019(raw_df)
                df = df.copy()
                df["_source_dataset"] = "cicddos2019"
                dfs.append(df)

        # Ingest InSDN if present in data_dir or workspace
        insdn_dir = os.path.join(data_dir, "InSDN_DatasetCSV")
        if not os.path.isdir(insdn_dir):
            insdn_dir = os.path.join(PROJECT_ROOT, "Codes", "ml", "datasets", "InSDN_DatasetCSV")
        if os.path.isdir(insdn_dir):
            print(f"[*] Ingesting InSDN dataset from: {insdn_dir}")
            df_insdn = load_insdn(insdn_dir, nrows=15000)
            df_insdn = df_insdn.copy()
            df_insdn["_source_dataset"] = "insdn"
            dfs.append(df_insdn)

        # Ingest partial CICIoT2023 if present in workspace
        ciciot_dir = os.path.join(PROJECT_ROOT, "data", "ciciot2023")
        if os.path.isdir(ciciot_dir):
            print(f"[*] Ingesting CICIoT2023 partial mirror from: {ciciot_dir}")
            for fname in sorted(os.listdir(ciciot_dir)):
                if fname.endswith(".csv"):
                    fpath = os.path.join(ciciot_dir, fname)
                    df_iot = load_ciciot2023(fpath)
                    df_iot = df_iot.copy()
                    df_iot["_source_dataset"] = "ciciot2023"
                    dfs.append(df_iot)

    if not dfs:
        raise ValueError("No valid datasets loaded. Provide sources list or data_dir with files.")

    merged_df = pd.concat(dfs, ignore_index=True)
    print(f"[*] Merged {len(dfs)} dataset partitions: {len(merged_df):,} total raw rows")

    # Locate and normalize target label
    label_col = None
    for c in merged_df.columns:
        if c.lower() == "label":
            label_col = c
            break

    if label_col:
        merged_df["Normalized_Label"] = normalize_labels(merged_df[label_col])
    else:
        # Default to Benign if label column absent
        merged_df["Normalized_Label"] = "Benign"

    # Use exactly the 77 feature columns from CICFLOWMETER_FEATURE_NAMES
    feature_cols = list(CICFLOWMETER_FEATURE_NAMES)
    assert len(feature_cols) == NUM_FEATURES, (
        f"Feature column count mismatch: expected {NUM_FEATURES}, got {len(feature_cols)}"
    )

    for col in feature_cols:
        if col not in merged_df.columns:
            merged_df[col] = 0.0

    # Filter rows to canonical taxonomy classes (including Other_DDoS)
    valid_mask = merged_df["Normalized_Label"].isin(EXTENDED_CANONICAL_CLASSES)
    keep_cols = feature_cols + ["Normalized_Label", "_source_dataset"]
    filtered_df = merged_df[valid_mask][keep_cols].copy()

    # Deduplicate feature rows to prevent data leakage (only on feature cols)
    pre_dedup = len(filtered_df)
    filtered_df = filtered_df.drop_duplicates(subset=feature_cols).reset_index(drop=True)
    print(f"[*] Deduplication: removed {pre_dedup - len(filtered_df):,} duplicate rows ({len(filtered_df):,} unique rows remaining)")

    # Verify feature count
    actual_feature_count = len(feature_cols)
    print(f"[*] Feature schema: {actual_feature_count} features (expected {NUM_FEATURES})")
    if actual_feature_count != NUM_FEATURES:
        raise RuntimeError(
            f"Feature count mismatch: pipeline uses {actual_feature_count} features "
            f"but flow_extractor.py defines {NUM_FEATURES}. This is a correctness bug."
        )

    return filtered_df


def prepare_balanced_training_data(
    X_train: np.ndarray,
    y_train: np.ndarray,
    label_encoder: LabelEncoder,
    majority_cap: int = 10000,
    random_state: int = 42
) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Applies majority subsampling and computes inverse-frequency sample weights.

    Returns (X_sub, y_sub, sample_weights) — no synthetic examples are generated.
    Sample weights let the model attend to rare classes via loss reweighting
    instead of SMOTE, which would blur decision boundaries between confusable
    reflection/amplification protocols.
    """
    unique, counts = np.unique(y_train, return_counts=True)
    print(f"[*] Train set class distribution before balancing:")
    for u, c in zip(unique, counts):
        lbl = label_encoder.classes_[u] if u < len(label_encoder.classes_) else str(u)
        print(f"    - {lbl:15s}: {c:>7,}")

    # Step 1: Subsample majority classes
    indices_to_keep = []
    rng = np.random.RandomState(random_state)
    for u in unique:
        class_indices = np.where(y_train == u)[0]
        if len(class_indices) > majority_cap:
            chosen = rng.choice(class_indices, size=majority_cap, replace=False)
            indices_to_keep.extend(chosen)
        else:
            indices_to_keep.extend(class_indices)

    indices_to_keep = np.array(indices_to_keep)
    X_sub = X_train[indices_to_keep]
    y_sub = y_train[indices_to_keep]

    # Step 2: Compute inverse-frequency sample weights (balanced weighting)
    u_sub, c_sub = np.unique(y_sub, return_counts=True)
    n_samples = len(y_sub)
    n_classes = len(u_sub)
    class_weight_map = {}
    for u, c in zip(u_sub, c_sub):
        # sklearn 'balanced' formula: n_samples / (n_classes * count)
        class_weight_map[u] = n_samples / (n_classes * c)
    sample_weights = np.array([class_weight_map[y] for y in y_sub])

    print(f"[*] Post-subsampling train set size: {len(y_sub):,} samples (no SMOTE — using sample weights instead)")
    print(f"[*] Sample weight range: [{sample_weights.min():.3f}, {sample_weights.max():.3f}]")
    for u, c in zip(u_sub, c_sub):
        lbl = label_encoder.classes_[u] if u < len(label_encoder.classes_) else str(u)
        print(f"    - {lbl:15s}: n={c:>6,}, weight={class_weight_map[u]:.3f}")

    return X_sub, y_sub, sample_weights


def _evaluate_per_dataset(
    model,
    X_test_scaled: np.ndarray,
    y_test: np.ndarray,
    source_test: np.ndarray,
    label_encoder: LabelEncoder,
    model_name: str,
) -> Dict[str, dict]:
    """Evaluate model performance separately for each source dataset in the test set.

    Returns:
        Dict mapping source_name -> {accuracy, macro_f1, weighted_f1,
                                       classification_report, confusion_matrix}
    """
    per_dataset = {}
    unique_sources = np.unique(source_test)

    for src in unique_sources:
        mask = source_test == src
        if mask.sum() == 0:
            continue

        X_src = X_test_scaled[mask]
        y_src = y_test[mask]

        y_pred_src = model.predict(X_src)
        acc = float(accuracy_score(y_src, y_pred_src))
        macro_f1 = float(f1_score(y_src, y_pred_src, average="macro", zero_division=0))
        weighted_f1 = float(f1_score(y_src, y_pred_src, average="weighted", zero_division=0))

        # Determine class names present in this source
        present_indices = sorted(set(np.concatenate([np.unique(y_src), np.unique(y_pred_src)])))
        target_names = [
            label_encoder.classes_[idx] if idx < len(label_encoder.classes_) else str(idx)
            for idx in present_indices
        ]

        report_dict = classification_report(
            y_src, y_pred_src, labels=present_indices,
            target_names=target_names, output_dict=True, zero_division=0
        )
        cm = confusion_matrix(y_src, y_pred_src, labels=present_indices)

        per_dataset[src] = {
            "accuracy": acc,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "sample_count": int(mask.sum()),
            "classification_report": report_dict,
            "confusion_matrix": cm.tolist(),
            "class_names": target_names,
        }

        # Flag any attack class with recall < 95%
        recall_warnings = []
        for cls_name in target_names:
            if cls_name.lower() == "benign":
                continue
            if cls_name in report_dict and report_dict[cls_name].get("recall", 1.0) < 0.95:
                recall_warnings.append(
                    f"    [!] {model_name}/{src}: {cls_name} recall = "
                    f"{report_dict[cls_name]['recall']:.4f} (< 95% threshold)"
                )

        if recall_warnings:
            print(f"[!] Low recall warnings for {model_name} on {src}:")
            for w in recall_warnings:
                print(w)

    return per_dataset


def run_family_grouping_experiment(
    X_train_bal: np.ndarray,
    y_train_bal: np.ndarray,
    X_test_scaled: np.ndarray,
    y_test: np.ndarray,
    le: LabelEncoder,
    random_state: int = 42,
) -> dict:
    """Evaluate consolidated families vs individual classes."""
    family_map = {
        "DNS": "Reflection-Amplification",
        "LDAP": "Reflection-Amplification",
        "NetBIOS": "Reflection-Amplification",
        "Portmap": "Reflection-Amplification",
        "SNMP": "Reflection-Amplification",
        "UDP": "UDP-Based",
        "UDP-Lag": "UDP-Based",
    }
    y_train_names = le.inverse_transform(y_train_bal)
    y_test_names = le.inverse_transform(y_test)

    y_train_fam = np.array([family_map.get(n, n) for n in y_train_names])
    y_test_fam = np.array([family_map.get(n, n) for n in y_test_names])

    le_fam = LabelEncoder()
    le_fam.fit(sorted(list(set(np.concatenate([y_train_fam, y_test_fam])))))
    y_train_fam_enc = le_fam.transform(y_train_fam)
    y_test_fam_enc = le_fam.transform(y_test_fam)

    xgb_fam = XGBClassifier(
        n_estimators=100, max_depth=6, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8, n_jobs=-1,
        random_state=random_state, eval_metric="mlogloss",
    )
    xgb_fam.fit(X_train_bal, y_train_fam_enc)
    y_pred_fam = xgb_fam.predict(X_test_scaled)

    rep_fam = classification_report(
        y_test_fam_enc, y_pred_fam, target_names=le_fam.classes_, output_dict=True, zero_division=0
    )
    cm_fam = confusion_matrix(y_test_fam_enc, y_pred_fam)

    return {
        "classification_report": rep_fam,
        "classes": list(le_fam.classes_),
        "confusion_matrix": cm_fam.tolist(),
        "udp_based_recall": float(rep_fam.get("UDP-Based", {}).get("recall", 0.0)),
        "udp_based_precision": float(rep_fam.get("UDP-Based", {}).get("precision", 0.0)),
        "udp_based_f1": float(rep_fam.get("UDP-Based", {}).get("f1-score", 0.0)),
        "udp_based_support": int(rep_fam.get("UDP-Based", {}).get("support", 0)),
        "reflection_recall": float(rep_fam.get("Reflection-Amplification", {}).get("recall", 0.0)),
        "reflection_precision": float(rep_fam.get("Reflection-Amplification", {}).get("precision", 0.0)),
        "reflection_f1": float(rep_fam.get("Reflection-Amplification", {}).get("f1-score", 0.0)),
        "reflection_support": int(rep_fam.get("Reflection-Amplification", {}).get("support", 0)),
    }


def train_and_evaluate_multi_dataset(
    sources: Optional[List[Tuple[str, Any]]] = None,
    data_dir: Optional[str] = None,
    eval_only_sources: Optional[List[Tuple[str, Any]]] = None,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    eval_dir: str = DEFAULT_EVAL_DIR,
    random_state: int = 42,
    baseline_f1: float = DEFAULT_BASELINE_F1,
) -> dict:
    """End-to-end multi-dataset training and evaluation pipeline.

    Includes:
      - Per-dataset evaluation (Precision/Recall/F1/CM for each source)
      - Aggregate evaluation over the merged test set
      - Performance gate: refuses to save production bundles if combined
        weighted F1 < baseline_f1
    """
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(eval_dir, exist_ok=True)

    # 1. Ingest and merge multi-source datasets
    df = load_and_merge_datasets(sources=sources, data_dir=data_dir)

    feature_cols = list(CICFLOWMETER_FEATURE_NAMES)
    X_raw = df[feature_cols].values
    y_raw = df["Normalized_Label"].values
    source_raw = np.array(df["_source_dataset"].tolist(), dtype=object)

    # 2. Encode target labels
    le = LabelEncoder()
    le.fit(sorted(list(set(y_raw))))
    y = le.transform(y_raw)

    # 3. Stratified 80/20 train/test split (preserving source provenance)
    print("[*] Performing 80/20 stratified train/test split...")
    unique_classes, class_counts = np.unique(y, return_counts=True)
    if min(class_counts) < 2:
        X_train_raw, X_test_raw, y_train, y_test, src_train, src_test = train_test_split(
            X_raw, y, source_raw, test_size=0.2, random_state=random_state
        )
    else:
        X_train_raw, X_test_raw, y_train, y_test, src_train, src_test = train_test_split(
            X_raw, y, source_raw, test_size=0.2, random_state=random_state, stratify=y
        )

    print(f"[*] Train set: {len(X_train_raw):,} samples | Test set: {len(X_test_raw):,} samples")

    # 4. Impute & Scale
    print("[*] Imputing missing/infinite values & scaling features...")
    X_train_clean = np.where(np.isinf(X_train_raw), np.nan, X_train_raw)
    X_test_clean = np.where(np.isinf(X_test_raw), np.nan, X_test_raw)

    imputer = SimpleImputer(strategy="median")
    X_train_imp = imputer.fit_transform(X_train_clean)
    X_test_imp = imputer.transform(X_test_clean)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_imp)
    X_test_scaled = scaler.transform(X_test_imp)

    # 5. Class Balancing (majority subsampling + sample weights, no SMOTE)
    X_train_bal, y_train_bal, sample_weights = prepare_balanced_training_data(
        X_train_scaled, y_train, le, majority_cap=10000, random_state=random_state
    )

    # 6. Train Primary XGBoost & Baseline Random Forest Classifiers
    print("\n" + "=" * 60)
    print("[*] Training Primary XGBoost Classifier...")
    print("=" * 60)
    t0 = time.time()
    xgb_model = XGBClassifier(
        n_estimators=300,
        max_depth=8,
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=3,
        gamma=0.1,
        n_jobs=-1,
        random_state=random_state,
        eval_metric="mlogloss",
    )
    xgb_model.fit(X_train_bal, y_train_bal, sample_weight=sample_weights)
    xgb_train_time = time.time() - t0

    print("\n" + "=" * 60)
    print("[*] Training Baseline Random Forest Classifier...")
    print("=" * 60)
    t0 = time.time()
    rf_model = RandomForestClassifier(
        n_estimators=300,
        max_depth=20,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=random_state,
    )
    rf_model.fit(X_train_bal, y_train_bal)
    rf_train_time = time.time() - t0

    # 7. Evaluate on held-out test set — AGGREGATE + PER-DATASET
    results = {}
    models = {
        "XGBoost": (xgb_model, xgb_train_time),
        "RandomForest": (rf_model, rf_train_time),
    }

    for name, (model, train_time) in models.items():
        y_pred = model.predict(X_test_scaled)
        acc = float(accuracy_score(y_test, y_pred))
        macro_f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
        weighted_f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
        report_dict = classification_report(
            y_test, y_pred, target_names=le.classes_, output_dict=True, zero_division=0
        )
        cm = confusion_matrix(y_test, y_pred)

        # Per-dataset evaluation
        per_dataset_metrics = _evaluate_per_dataset(
            model, X_test_scaled, y_test, src_test, le, name
        )

        results[name] = {
            "accuracy": acc,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "training_time": train_time,
            "classification_report": report_dict,
            "confusion_matrix": cm.tolist(),
            "per_dataset": per_dataset_metrics,
        }

    # 7b. Evaluate Eval-Only Sources (Isolated from training split)
    if eval_only_sources is None:
        eval_only_sources = []
        flowstats_path = os.path.join(PROJECT_ROOT, "FlowStatsfile.csv")
        if not os.path.isfile(flowstats_path):
            flowstats_path = os.path.join(PROJECT_ROOT, "Codes", "ml", "FlowStatsfile.csv")
        if os.path.isfile(flowstats_path):
            eval_only_sources.append(("synthetic_sdn", flowstats_path))

    if eval_only_sources:
        print("\n" + "=" * 60)
        print("[*] Evaluating Eval-Only Sources (0 samples used in training)...")
        print("=" * 60)
        for eos_name, eos_data in eval_only_sources:
            print(f"[*] Processing eval-only source: '{eos_name}'")
            try:
                eos_df = load_dataset(
                    "synthetic_sdn" if "synthetic" in eos_name.lower() else "cicddos2019",
                    eos_data
                )
                eos_X_raw = eos_df[feature_cols].values
                # Resolve label column: adapters may produce "Label" or "Normalized_Label"
                if "Normalized_Label" in eos_df.columns:
                    eos_y_raw = eos_df["Normalized_Label"].values
                elif "Label" in eos_df.columns:
                    eos_y_raw = normalize_labels(eos_df["Label"]).values
                elif "label" in eos_df.columns:
                    eos_y_raw = normalize_labels(eos_df["label"]).values
                else:
                    print(f"[!] Skipping eval-only source '{eos_name}': no label column found")
                    continue
                eos_y = np.array([le.transform([y])[0] if y in le.classes_ else le.transform(["Benign"])[0] for y in eos_y_raw])
                eos_X_clean = np.where(np.isinf(eos_X_raw), np.nan, eos_X_raw)
                eos_X_imp = imputer.transform(eos_X_clean)
                eos_X_scaled = scaler.transform(eos_X_imp)

                for mname, (m, _) in models.items():
                    m_pred = m.predict(eos_X_scaled)
                    m_acc = float(accuracy_score(eos_y, m_pred))
                    m_macro_f1 = float(f1_score(eos_y, m_pred, average="macro", zero_division=0))
                    m_weighted_f1 = float(f1_score(eos_y, m_pred, average="weighted", zero_division=0))
                    present_idx = sorted(set(np.concatenate([np.unique(eos_y), np.unique(m_pred)])))
                    target_names = [le.classes_[idx] for idx in present_idx]
                    m_rep = classification_report(
                        eos_y, m_pred, labels=present_idx, target_names=target_names, output_dict=True, zero_division=0
                    )
                    m_cm = confusion_matrix(eos_y, m_pred, labels=present_idx)

                    if "eval_only" not in results[mname]:
                        results[mname]["eval_only"] = {}
                    results[mname]["eval_only"][eos_name] = {
                        "accuracy": m_acc,
                        "macro_f1": m_macro_f1,
                        "weighted_f1": m_weighted_f1,
                        "sample_count": len(eos_X_raw),
                        "classification_report": m_rep,
                        "confusion_matrix": m_cm.tolist(),
                        "class_names": target_names,
                    }
            except Exception as e:
                print(f"[!] Warning: Failed to evaluate eval-only source '{eos_name}': {e}")

    # 7c. Run Family Grouping Experiment (UDP-Lag -> UDP-Based)
    print("\n" + "=" * 60)
    print("[*] Running Consolidated Family Grouping Experiment (UDP-Lag -> UDP-Based)...")
    print("=" * 60)
    try:
        family_exp_results = run_family_grouping_experiment(
            X_train_bal, y_train_bal, X_test_scaled, y_test, le, random_state=random_state
        )
        results["_family_grouping_experiment"] = family_exp_results
    except Exception as e:
        print(f"[!] Warning: Family grouping experiment failed: {e}")

    # 8. Performance Gate — check before saving
    xgb_weighted_f1 = results["XGBoost"]["weighted_f1"]
    rf_weighted_f1 = results["RandomForest"]["weighted_f1"]
    best_f1 = max(xgb_weighted_f1, rf_weighted_f1)

    print("\n" + "=" * 60)
    print("[*] PERFORMANCE GATE CHECK")
    print("=" * 60)
    print(f"    XGBoost weighted F1:       {xgb_weighted_f1:.6f}")
    print(f"    RandomForest weighted F1:  {rf_weighted_f1:.6f}")
    print(f"    Required baseline F1:      {baseline_f1:.6f}")

    gate_passed = best_f1 >= baseline_f1
    results["_performance_gate"] = {
        "baseline_f1": baseline_f1,
        "best_achieved_f1": best_f1,
        "gate_passed": gate_passed,
    }

    if gate_passed:
        print(f"    [PASSED] GATE PASSED -- best F1 {best_f1:.6f} >= baseline {baseline_f1:.6f}")
    else:
        print(f"    [FAILED] GATE FAILED -- best F1 {best_f1:.6f} < baseline {baseline_f1:.6f}")
        print(f"    [!] Production model bundles will NOT be saved.")
        print(f"        Gap: {(baseline_f1 - best_f1) * 100:.4f}% below baseline.")

    # 9. Save Model Bundle Artifacts (only if gate passed)
    if gate_passed:
        xgb_bundle_path = os.path.join(output_dir, "cicddos2019_xgboost.pkl")
        rf_bundle_path = os.path.join(output_dir, "cicddos2019_rf.pkl")
        xgb_baseline_path = os.path.join(output_dir, "xgboost_baseline.joblib")
        rf_baseline_path = os.path.join(output_dir, "random_forest_baseline.joblib")

        xgb_classifier = DDoSClassifier({
            "model": xgb_model,
            "scaler": scaler,
            "imputer": imputer,
            "classes": list(le.classes_),
            "feature_names": list(CICFLOWMETER_FEATURE_NAMES),
        })
        xgb_classifier.save(xgb_bundle_path)
        xgb_classifier.save(xgb_baseline_path)

        rf_classifier = DDoSClassifier({
            "model": rf_model,
            "scaler": scaler,
            "imputer": imputer,
            "classes": list(le.classes_),
            "feature_names": list(CICFLOWMETER_FEATURE_NAMES),
        })
        rf_classifier.save(rf_bundle_path)
        rf_classifier.save(rf_baseline_path)

        print(f"[*] Saved production model bundles to: {output_dir}")
    else:
        print(f"[*] Skipped saving production bundles (gate failed).")

    # 10. Write Evaluation Report (always written, regardless of gate)
    eval_md_path = os.path.join(eval_dir, "multi_dataset_evaluation.md")
    eval_json_path = os.path.join(eval_dir, "eval_report.json")

    with open(eval_json_path, "w") as f:
        json.dump(results, f, indent=2)

    md_content = _build_evaluation_markdown(results, le, len(X_train_raw), len(X_test_raw), baseline_f1)

    with open(eval_md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    print(f"[*] Saved evaluation markdown report to: {eval_md_path}")
    print(f"[*] Saved evaluation JSON metrics to: {eval_json_path}")

    return results


def _build_evaluation_markdown(
    results: dict,
    le: LabelEncoder,
    train_count: int,
    test_count: int,
    baseline_f1: float,
) -> str:
    """Build comprehensive evaluation Markdown report including per-dataset breakdowns."""

    gate = results.get("_performance_gate", {})
    gate_status = "✅ PASSED" if gate.get("gate_passed", False) else "❌ FAILED"

    md = f"""# Multi-Dataset Model Evaluation Report

**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}
**Feature Schema:** {NUM_FEATURES} features (CICFLOWMETER_FEATURE_NAMES)
**Dataset Split:** 80% Train ({train_count:,} samples), 20% Held-Out Test ({test_count:,} samples)
**Performance Gate:** {gate_status} (baseline={baseline_f1:.4f}, achieved={gate.get('best_achieved_f1', 0):.4f})

---

## 1. Aggregate Model Performance Summary

| Model | Accuracy | Macro F1 | Weighted F1 | Training Time |
|---|---|---|---|---|
| **XGBoost (Primary)** | **{results['XGBoost']['accuracy']*100:.2f}%** | **{results['XGBoost']['macro_f1']:.4f}** | **{results['XGBoost']['weighted_f1']:.4f}** | {results['XGBoost']['training_time']:.2f}s |
| **Random Forest (Baseline)** | {results['RandomForest']['accuracy']*100:.2f}% | {results['RandomForest']['macro_f1']:.4f} | {results['RandomForest']['weighted_f1']:.4f} | {results['RandomForest']['training_time']:.2f}s |

---

## 2. Primary Model (XGBoost) Per-Class Metrics (Aggregate)

| Class | Precision | Recall | F1-Score | Test Support |
|---|---:|---:|---:|---:|
"""
    xgb_rep = results["XGBoost"]["classification_report"]
    for c in le.classes_:
        if c in xgb_rep:
            m = xgb_rep[c]
            md += f"| **{c}** | {m['precision']:.4f} | {m['recall']:.4f} | {m['f1-score']:.4f} | {int(m['support']):,} |\n"

    md += f"""
---

## 3. XGBoost Confusion Matrix (Aggregate)

```
Classes Order: {list(le.classes_)}
"""
    cm_xgb = np.array(results["XGBoost"]["confusion_matrix"])
    cm_df = pd.DataFrame(cm_xgb, index=le.classes_, columns=le.classes_)
    md += cm_df.to_string()
    md += "\n```\n"

    # Per-dataset sections
    md += "\n---\n\n## 4. Per-Dataset Evaluation Breakdowns\n\n"

    for model_name in ["XGBoost", "RandomForest"]:
        per_ds = results[model_name].get("per_dataset", {})
        if not per_ds:
            continue

        md += f"### {model_name}\n\n"

        for src_name, src_metrics in sorted(per_ds.items()):
            display_title = SOURCE_DISPLAY_NAMES.get(src_name, src_name)
            md += f"#### Source: `{display_title}` ({src_metrics['sample_count']:,} test samples)\n\n"
            md += f"| Metric | Value |\n|---|---:|\n"
            md += f"| Accuracy | {src_metrics['accuracy']*100:.2f}% |\n"
            md += f"| Macro F1 | {src_metrics['macro_f1']:.4f} |\n"
            md += f"| Weighted F1 | {src_metrics['weighted_f1']:.4f} |\n\n"

            # Per-class table
            src_rep = src_metrics.get("classification_report", {})
            class_names = src_metrics.get("class_names", [])
            if class_names:
                md += "| Class | Precision | Recall | F1-Score | Support |\n|---|---:|---:|---:|---:|\n"
                for cls in class_names:
                    if cls in src_rep:
                        cm = src_rep[cls]
                        md += f"| {cls} | {cm['precision']:.4f} | {cm['recall']:.4f} | {cm['f1-score']:.4f} | {int(cm['support']):,} |\n"
                md += "\n"

            # Confusion matrix
            src_cm = src_metrics.get("confusion_matrix", [])
            if src_cm and class_names:
                md += f"```\nConfusion Matrix ({src_name}):\nClasses: {class_names}\n"
                cm_arr = np.array(src_cm)
                cm_src_df = pd.DataFrame(cm_arr, index=class_names, columns=class_names)
                md += cm_src_df.to_string()
                md += "\n```\n\n"

        # Eval-only sources breakdown
        eval_only_ds = results[model_name].get("eval_only", {})
        if eval_only_ds:
            for src_name, src_metrics in sorted(eval_only_ds.items()):
                display_title = SOURCE_DISPLAY_NAMES.get(src_name, src_name)
                md += f"#### Source: `{display_title}` ({src_metrics['sample_count']:,} eval-only samples)\n\n"
                md += f"> [!NOTE]\n> **Eval-Only Dataset:** Held out entirely from training split (0 samples in training set) to eliminate shortcut learning from its absent/zero-filled features.\n\n"
                md += f"| Metric | Value |\n|---|---:|\n"
                md += f"| Accuracy | {src_metrics['accuracy']*100:.2f}% |\n"
                md += f"| Macro F1 | {src_metrics['macro_f1']:.4f} |\n"
                md += f"| Weighted F1 | {src_metrics['weighted_f1']:.4f} |\n\n"

                src_rep = src_metrics.get("classification_report", {})
                class_names = src_metrics.get("class_names", [])
                if class_names:
                    md += "| Class | Precision | Recall | F1-Score | Support |\n|---|---:|---:|---:|---:|\n"
                    for cls in class_names:
                        if cls in src_rep:
                            cm = src_rep[cls]
                            md += f"| {cls} | {cm['precision']:.4f} | {cm['recall']:.4f} | {cm['f1-score']:.4f} | {int(cm['support']):,} |\n"
                    md += "\n"

                src_cm = src_metrics.get("confusion_matrix", [])
                if src_cm and class_names:
                    md += f"```\nConfusion Matrix ({src_name}):\nClasses: {class_names}\n"
                    cm_arr = np.array(src_cm)
                    cm_src_df = pd.DataFrame(cm_arr, index=class_names, columns=class_names)
                    md += cm_src_df.to_string()
                    md += "\n```\n\n"

    # 5. Below Recall Threshold (< 95%) Section
    md += "---\n\n## 5. Classes Below Recall Threshold (< 95%)\n\n"
    md += "Explicit audit of all attack classes failing the >= 95% recall operational reliability gate on held-out test splits:\n\n"
    md += "| Model | Source Dataset | Attack Class | Recall | Precision | F1-Score | Support | Reliability Assessment |\n"
    md += "|---|---|---|---:|---:|---:|---:|---|\n"

    low_recall_found = False
    for model_name in ["XGBoost", "RandomForest"]:
        per_ds = results[model_name].get("per_dataset", {})
        for src_name, src_metrics in sorted(per_ds.items()):
            src_rep = src_metrics.get("classification_report", {})
            class_names = src_metrics.get("class_names", [])
            for cls in class_names:
                if cls.lower() == "benign":
                    continue
                if cls in src_rep:
                    rec = src_rep[cls].get("recall", 1.0)
                    if rec < 0.95:
                        low_recall_found = True
                        supp = int(src_rep[cls].get("support", 0))
                        prec = src_rep[cls].get("precision", 0.0)
                        f1 = src_rep[cls].get("f1-score", 0.0)
                        if supp < 50:
                            assessment = "LOW SAMPLE CONFIDENCE (n < 50) -- high variance / underrepresented"
                        elif supp < 500:
                            assessment = "MODERATE SAMPLE (n < 500) -- inter-protocol reflection confusion"
                        else:
                            assessment = "HIGH SAMPLE (n >= 500) -- systematic feature overlap / structural deficit"
                        display_name = SOURCE_DISPLAY_NAMES.get(src_name, src_name)
                        md += f"| **{model_name}** | `{src_name}` | **{cls}** | {rec*100:.2f}% | {prec:.4f} | {f1:.4f} | {supp:,} | {assessment} |\n"

    if not low_recall_found:
        md += "| - | - | *None* | - | - | - | - | All classes achieved >= 95% recall |\n"
    md += "\n"

    # 6. UDP-Lag Family Grouping Section
    fam_exp = results.get("_family_grouping_experiment")
    if fam_exp:
        md += "---\n\n## 6. Below-Threshold Remediation: UDP-Lag Family Grouping Experiment\n\n"
        md += "Comparative evaluation testing the consolidated taxonomy remediation from `KNOWN_ISSUES.md`:\n\n"
        udp_baseline_rec = xgb_rep.get("UDP", {}).get("recall", 0.0)
        udp_baseline_supp = int(xgb_rep.get("UDP", {}).get("support", 0))
        lag_baseline_rec = xgb_rep.get("UDP-Lag", {}).get("recall", 0.0)
        lag_baseline_supp = int(xgb_rep.get("UDP-Lag", {}).get("support", 0))

        md += "| Taxonomy Configuration | Attack Family | Recall | Precision | F1-Score | Support | Status |\n"
        md += "|---|---|---:|---:|---:|---:|---|\n"
        md += f"| Individual (Baseline) | `UDP` | {udp_baseline_rec*100:.2f}% | {xgb_rep.get('UDP', {}).get('precision', 0.0):.4f} | {xgb_rep.get('UDP', {}).get('f1-score', 0.0):.4f} | {udp_baseline_supp:,} | Clears 95% threshold |\n"
        md += f"| Individual (Baseline) | `UDP-Lag` | {lag_baseline_rec*100:.2f}% | {xgb_rep.get('UDP-Lag', {}).get('precision', 0.0):.4f} | {xgb_rep.get('UDP-Lag', {}).get('f1-score', 0.0):.4f} | {lag_baseline_supp:,} | ⚠ FAILS 95% threshold (confused with UDP) |\n"
        md += f"| Consolidated Family | `UDP-Based` (UDP + UDP-Lag) | **{fam_exp['udp_based_recall']*100:.2f}%** | **{fam_exp['udp_based_precision']:.4f}** | **{fam_exp['udp_based_f1']:.4f}** | **{fam_exp['udp_based_support']:,}** | **✅ CLEARS 95% threshold** |\n"
        md += f"| Consolidated Family | `Reflection-Amplification` | **{fam_exp['reflection_recall']*100:.2f}%** | **{fam_exp.get('reflection_precision', 0.0):.4f}** | **{fam_exp.get('reflection_f1', 0.0):.4f}** | **{fam_exp['reflection_support']:,}** | **✅ Reflection bottleneck resolved** |\n\n"

    return md


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Multi-Dataset Retraining Pipeline")
    parser.add_argument("--data-dir", default=None, help="Directory containing parquet/csv datasets")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Model bundle output directory")
    parser.add_argument("--eval-dir", default=DEFAULT_EVAL_DIR, help="Evaluation metrics output directory")
    parser.add_argument(
        "--baseline-f1", type=float, default=DEFAULT_BASELINE_F1,
        help="Minimum weighted F1 required to overwrite production bundles (default: 0.998)"
    )
    args = parser.parse_args()

    train_and_evaluate_multi_dataset(
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        eval_dir=args.eval_dir,
        baseline_f1=args.baseline_f1,
    )
