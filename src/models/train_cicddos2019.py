# -*- coding: utf-8 -*-
"""
CICDDoS2019 Multi-Class Model Training & Evaluation Pipeline — Step 2.

Features:
  - Ingests all 17 parquet files from Codes/ml/datasets/
  - Applies approved label normalization map (13 classes)
  - Performs deduplication to eliminate cross-day synthetic leakage
  - Stratified 80/20 train/test split
  - Class balancing: subsampling majority classes (cap at 25,000) and
    SMOTE/oversampling minority classes (floor at 2,500)
  - Trains primary XGBoost classifier + Random Forest baseline
  - Generates detailed evaluation metrics: Confusion Matrix, Classification Report,
    Per-Class Precision / Recall / F1-Score, and logs them to docs/eval/
"""
import os
import sys
import json
import time
import argparse
from pathlib import Path

# Ensure workspace root is in sys.path
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import numpy as np
import pandas as pd
from typing import Dict, Tuple, List, Optional

from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from xgboost import XGBClassifier
from imblearn.over_sampling import SMOTE, RandomOverSampler

from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES, NUM_FEATURES
from src.models.classifier import CICDDOS2019_CLASSES, LABEL_NORMALIZATION, DDoSClassifier


DEFAULT_DATA_DIR = r"Codes\ml\datasets"
DEFAULT_OUTPUT_DIR = "models"
DEFAULT_EVAL_DIR = "docs/eval"


def load_and_preprocess_dataset(data_dir: str = DEFAULT_DATA_DIR) -> pd.DataFrame:
    """Load all 17 parquet files, apply column cleaning & label normalization."""
    print(f"[*] Scanning parquet files in: {data_dir}")
    parquet_files = sorted([f for f in os.listdir(data_dir) if f.endswith(".parquet")])
    if not parquet_files:
        raise FileNotFoundError(f"No parquet files found in {data_dir}")

    dfs = []
    total_raw_rows = 0
    for fname in parquet_files:
        fpath = os.path.join(data_dir, fname)
        df_f = pd.read_parquet(fpath)
        total_raw_rows += len(df_f)

        # Standardize column names (strip whitespace)
        df_f.columns = [c.strip() for c in df_f.columns]
        dfs.append(df_f)

    full_df = pd.concat(dfs, ignore_index=True)
    print(f"[*] Loaded {len(parquet_files)} files: {total_raw_rows:,} raw rows")

    # Locate and sanitize label column
    label_col = [c for c in full_df.columns if c.lower() == "label"][0]
    full_df[label_col] = full_df[label_col].astype(str).str.strip()

    # Apply approved normalization map
    full_df["Normalized_Label"] = full_df[label_col].map(lambda x: LABEL_NORMALIZATION.get(x, x))

    # Keep only the canonical 77 CICFlowMeter feature columns + target label
    feature_cols = [c for c in CICFLOWMETER_FEATURE_NAMES if c in full_df.columns]
    if len(feature_cols) != NUM_FEATURES:
        raise ValueError(
            f"Feature mismatch: found {len(feature_cols)} of {NUM_FEATURES} expected features."
        )

    # Filter out any classes not in canonical 13-class taxonomy
    canonical_set = set(CICDDOS2019_CLASSES)
    valid_mask = full_df["Normalized_Label"].isin(canonical_set)
    filtered_df = full_df[valid_mask][feature_cols + ["Normalized_Label"]].copy()
    print(f"[*] Canonical taxonomy rows: {len(filtered_df):,} across {filtered_df['Normalized_Label'].nunique()} classes")

    # Deduplication across feature rows to eliminate leakage
    print("[*] Performing feature-row deduplication...")
    pre_dedup = len(filtered_df)
    filtered_df = filtered_df.drop_duplicates(subset=feature_cols).reset_index(drop=True)
    print(f"[*] Deduplication: removed {pre_dedup - len(filtered_df):,} duplicates ({len(filtered_df):,} unique rows remaining)")

    return filtered_df


def prepare_balanced_training_data(
    X_train: np.ndarray,
    y_train: np.ndarray,
    label_encoder: LabelEncoder,
    majority_cap: int = 25000,
    minority_floor: int = 2500,
    random_state: int = 42
) -> Tuple[np.ndarray, np.ndarray]:
    """Applies majority subsampling and minority SMOTE/oversampling."""
    print(f"[*] Initial train set class counts:")
    unique, counts = np.unique(y_train, return_counts=True)
    for u, c in zip(unique, counts):
        print(f"    - {label_encoder.classes_[u]:15s}: {c:>7,}")

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

    print(f"[*] Post-subsampling train set size: {len(y_sub):,}")

    # Step 2: Oversample minority classes to minority_floor
    # Check counts per class
    u_sub, c_sub = np.unique(y_sub, return_counts=True)
    sampling_strategy = {}
    for u, c in zip(u_sub, c_sub):
        if c < minority_floor:
            sampling_strategy[u] = minority_floor

    if sampling_strategy:
        print(f"[*] Oversampling minority classes {list(sampling_strategy.keys())} to floor {minority_floor}...")
        # Try SMOTE first with adaptive k_neighbors, fallback to RandomOverSampler
        min_class_size = min(c_sub)
        if min_class_size > 5:
            k_neighbors = min(5, min_class_size - 1)
            smote = SMOTE(sampling_strategy=sampling_strategy, k_neighbors=k_neighbors, random_state=random_state)
            X_bal, y_bal = smote.fit_resample(X_sub, y_sub)
        else:
            ros = RandomOverSampler(sampling_strategy=sampling_strategy, random_state=random_state)
            X_bal, y_bal = ros.fit_resample(X_sub, y_sub)
    else:
        X_bal, y_bal = X_sub, y_sub

    print(f"[*] Final balanced train set size: {len(y_bal):,}")
    return X_bal, y_bal


def train_and_evaluate(
    data_dir: str = DEFAULT_DATA_DIR,
    output_dir: str = DEFAULT_OUTPUT_DIR,
    eval_dir: str = DEFAULT_EVAL_DIR,
    random_state: int = 42,
) -> dict:
    """End-to-end training and evaluation pipeline."""
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(eval_dir, exist_ok=True)

    # 1. Load data
    df = load_and_preprocess_dataset(data_dir)
    X_raw = df[CICFLOWMETER_FEATURE_NAMES].values
    y_raw = df["Normalized_Label"].values

    # 2. Encode labels
    le = LabelEncoder()
    le.fit(CICDDOS2019_CLASSES)
    y = le.transform(y_raw)

    # 3. Stratified 80/20 train/test split
    print("[*] Performing 80/20 stratified train/test split...")
    X_train_raw, X_test_raw, y_train, y_test = train_test_split(
        X_raw, y, test_size=0.2, random_state=random_state, stratify=y
    )
    print(f"[*] Train set: {len(X_train_raw):,} samples | Test set: {len(X_test_raw):,} samples")

    # 4. Impute & scale
    print("[*] Imputing missing/infinite values & scaling features...")
    # Replace Inf with NaN
    X_train_clean = np.where(np.isinf(X_train_raw), np.nan, X_train_raw)
    X_test_clean = np.where(np.isinf(X_test_raw), np.nan, X_test_raw)

    imputer = SimpleImputer(strategy="median")
    X_train_imp = imputer.fit_transform(X_train_clean)
    X_test_imp = imputer.transform(X_test_clean)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_imp)
    X_test_scaled = scaler.transform(X_test_imp)

    # 5. Class balancing
    X_train_bal, y_train_bal = prepare_balanced_training_data(
        X_train_scaled, y_train, le, majority_cap=25000, minority_floor=2500, random_state=random_state
    )

    # 6. Train Models
    print("\n" + "=" * 60)
    print("[*] 1/2 Training Primary XGBoost Classifier...")
    print("=" * 60)
    t0 = time.time()
    xgb_model = XGBClassifier(
        n_estimators=100,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        n_jobs=-1,
        random_state=random_state,
        eval_metric="mlogloss",
    )
    xgb_model.fit(X_train_bal, y_train_bal)
    xgb_train_time = time.time() - t0
    print(f"[*] XGBoost training completed in {xgb_train_time:.2f}s")

    print("\n" + "=" * 60)
    print("[*] 2/2 Training Baseline Random Forest Classifier...")
    print("=" * 60)
    t0 = time.time()
    rf_model = RandomForestClassifier(
        n_estimators=100,
        max_depth=15,
        n_jobs=-1,
        random_state=random_state,
    )
    rf_model.fit(X_train_bal, y_train_bal)
    rf_train_time = time.time() - t0
    print(f"[*] Random Forest training completed in {rf_train_time:.2f}s")

    # 7. Evaluate on held-out test set
    print("\n" + "=" * 60)
    print("[*] EVALUATING MODELS ON HELD-OUT TEST SET (No data leakage)")
    print("=" * 60)

    results = {}
    models = {
        "XGBoost": xgb_model,
        "RandomForest": rf_model,
    }

    for name, model in models.items():
        y_pred = model.predict(X_test_scaled)
        acc = float(accuracy_score(y_test, y_pred))
        macro_f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
        weighted_f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
        report_dict = classification_report(
            y_test, y_pred, target_names=le.classes_, output_dict=True, zero_division=0
        )
        cm = confusion_matrix(y_test, y_pred)

        results[name] = {
            "accuracy": acc,
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "classification_report": report_dict,
            "confusion_matrix": cm.tolist(),
        }

        print(f"\n--- {name} Test Performance ---")
        print(f"Accuracy:    {acc * 100:.2f}%")
        print(f"Macro F1:    {macro_f1:.4f}")
        print(f"Weighted F1: {weighted_f1:.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=le.classes_, digits=4, zero_division=0))

    # 8. Save Model Artifacts
    xgb_bundle_path = os.path.join(output_dir, "cicddos2019_xgboost.pkl")
    rf_bundle_path = os.path.join(output_dir, "cicddos2019_rf.pkl")

    xgb_classifier = DDoSClassifier({
        "model": xgb_model,
        "scaler": scaler,
        "imputer": imputer,
        "classes": list(le.classes_),
        "feature_names": list(CICFLOWMETER_FEATURE_NAMES),
    })
    xgb_classifier.save(xgb_bundle_path)
    print(f"[*] Saved XGBoost model bundle to: {xgb_bundle_path}")

    rf_classifier = DDoSClassifier({
        "model": rf_model,
        "scaler": scaler,
        "imputer": imputer,
        "classes": list(le.classes_),
        "feature_names": list(CICFLOWMETER_FEATURE_NAMES),
    })
    rf_classifier.save(rf_bundle_path)
    print(f"[*] Saved Random Forest model bundle to: {rf_bundle_path}")

    # 9. Generate and write Markdown Evaluation Report
    eval_md_path = os.path.join(eval_dir, "cicddos2019_evaluation.md")
    eval_json_path = os.path.join(eval_dir, "eval_report.json")

    with open(eval_json_path, "w") as f:
        json.dump(results, f, indent=2)

    # Format Markdown
    md_content = f"""# CICDDoS2019 Model Evaluation Report — Step 2

**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S')}  
**Taxonomy:** 13 Canonical Classes (SSDP dropped per known limitation, TFTP & Portmap included)  
**Dataset Split:** 80% Train ({len(X_train_raw):,} samples), 20% Held-Out Test ({len(X_test_raw):,} samples)  
**Deduplication:** Applied across all 77 features prior to splitting to eliminate cross-day synthetic leakage.

---

## 1. Summary Performance Comparison

| Model | Accuracy | Macro F1 | Weighted F1 | Training Time |
|---|---|---|---|---|
| **XGBoost (Primary)** | **{results['XGBoost']['accuracy']*100:.2f}%** | **{results['XGBoost']['macro_f1']:.4f}** | **{results['XGBoost']['weighted_f1']:.4f}** | {xgb_train_time:.2f}s |
| **Random Forest (Baseline)** | {results['RandomForest']['accuracy']*100:.2f}% | {results['RandomForest']['macro_f1']:.4f} | {results['RandomForest']['weighted_f1']:.4f} | {rf_train_time:.2f}s |

---

## 2. XGBoost Per-Class Performance Breakdown

| Class | Precision | Recall | F1-Score | Test Support |
|---|---:|---:|---:|---:|
"""
    xgb_rep = results["XGBoost"]["classification_report"]
    for c in le.classes_:
        metrics = xgb_rep[c]
        md_content += f"| **{c}** | {metrics['precision']:.4f} | {metrics['recall']:.4f} | {metrics['f1-score']:.4f} | {int(metrics['support']):,} |\n"

    md_content += f"""
---

## 3. XGBoost Confusion Matrix

```
Classes Order: {list(le.classes_)}
"""
    cm_xgb = np.array(results["XGBoost"]["confusion_matrix"])
    cm_df = pd.DataFrame(cm_xgb, index=le.classes_, columns=le.classes_)
    md_content += cm_df.to_string()
    md_content += "\n```\n"

    with open(eval_md_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    print(f"[*] Saved evaluation markdown report to: {eval_md_path}")
    print(f"[*] Saved evaluation JSON metrics to: {eval_json_path}")

    return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train CICDDoS2019 ML models")
    parser.add_argument("--data-dir", default=DEFAULT_DATA_DIR, help="Path to parquet datasets")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Output directory for model bundles")
    parser.add_argument("--eval-dir", default=DEFAULT_EVAL_DIR, help="Evaluation output directory")
    args = parser.parse_args()

    train_and_evaluate(args.data_dir, args.output_dir, args.eval_dir)
