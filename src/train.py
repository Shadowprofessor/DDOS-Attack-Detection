# -*- coding: utf-8 -*-
"""
Production Training Entry Point for DDoS Classifier Ensemble.
Supports multi-dataset inputs, unidirectional flow augmentation, stratified splits,
separate train/test datasets (zero-leakage SMOTE), balanced class-weighting,
hyperparameter overrides, and generates full evaluation reports and confusion matrices.
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path

# Ensure workspace root is in sys.path
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.utils.class_weight import compute_sample_weight
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, f1_score
from xgboost import XGBClassifier

from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES, NUM_FEATURES
from src.models.classifier import CICDDOS2019_CLASSES, DDoSClassifier


def _load_df(path: str) -> pd.DataFrame:
    if path.endswith(".parquet"):
        return pd.read_parquet(path)
    elif path.endswith(".csv"):
        return pd.read_csv(path, low_memory=False)
    else:
        raise ValueError(f"Unsupported dataset format: {path}")


def run_training(
    dataset_path: str = None,
    train_dataset_path: str = None,
    test_dataset_path: str = None,
    models_to_train: list = None,
    test_split: float = 0.20,
    stratify_col: str = "Label",
    class_weight: str = "balanced",
    random_state: int = 42,
    rf_max_depth: int = 16,
    rf_n_estimators: int = 100,
    xgb_max_depth: int = 6,
    xgb_n_estimators: int = 100,
    output_dir: str = "models/retrained",
    report_dir: str = "docs/eval/retrain_phase3",
):
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(report_dir, exist_ok=True)

    le = LabelEncoder()
    le.fit(CICDDOS2019_CLASSES)

    if train_dataset_path and test_dataset_path:
        print(f"[*] Loading separate train dataset from: {train_dataset_path}")
        train_df = _load_df(train_dataset_path)
        print(f"[*] Loading separate test dataset from: {test_dataset_path}")
        test_df = _load_df(test_dataset_path)

        # Filter canonical
        train_df = train_df[train_df["Label"].isin(CICDDOS2019_CLASSES)].copy()
        test_df = test_df[test_df["Label"].isin(CICDDOS2019_CLASSES)].copy()

        feature_cols = [c for c in CICFLOWMETER_FEATURE_NAMES if c in train_df.columns]
        if len(feature_cols) != NUM_FEATURES:
            raise ValueError(f"Expected {NUM_FEATURES} features, found {len(feature_cols)}")

        X_train_raw = train_df[feature_cols].values
        y_train = le.transform(train_df["Label"].values)
        X_test_raw = test_df[feature_cols].values
        y_test = le.transform(test_df["Label"].values)

        print(f"[*] Train set: {len(X_train_raw):,} samples | Test set (100% real): {len(X_test_raw):,} samples")

    elif dataset_path:
        print(f"[*] Loading dataset from: {dataset_path}")
        t0 = time.time()
        df = _load_df(dataset_path)
        print(f"[*] Dataset loaded in {time.time() - t0:.2f}s: {len(df):,} rows")

        label_col = "Label" if "Label" in df.columns else ("Normalized_Label" if "Normalized_Label" in df.columns else None)
        if not label_col:
            raise KeyError("Could not find 'Label' or 'Normalized_Label' in dataset columns.")

        valid_mask = df[label_col].isin(CICDDOS2019_CLASSES)
        df = df[valid_mask].copy()

        feature_cols = [c for c in CICFLOWMETER_FEATURE_NAMES if c in df.columns]
        if len(feature_cols) != NUM_FEATURES:
            raise ValueError(f"Expected {NUM_FEATURES} features, found {len(feature_cols)}")

        X_raw = df[feature_cols].values
        y_raw = df[label_col].values
        y = le.transform(y_raw)

        print(f"[*] Performing {int((1-test_split)*100)}/{int(test_split*100)} stratified train/test split...")
        X_train_raw, X_test_raw, y_train, y_test = train_test_split(
            X_raw, y, test_size=test_split, random_state=random_state, stratify=y
        )
        print(f"[*] Train set: {len(X_train_raw):,} samples | Test set: {len(X_test_raw):,} samples")
    else:
        raise ValueError("Must provide either --dataset or both --train-dataset and --test-dataset.")

    # Impute missing & infinite values (fit on train only!)
    print("[*] Imputing missing/infinite values & standard scaling (fit on train only)...")
    X_train_clean = np.where(np.isinf(X_train_raw), np.nan, X_train_raw)
    X_test_clean = np.where(np.isinf(X_test_raw), np.nan, X_test_raw)

    imputer = SimpleImputer(strategy="median")
    X_train_imp = imputer.fit_transform(X_train_clean)
    X_test_imp = imputer.transform(X_test_clean)

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train_imp)
    X_test_scaled = scaler.transform(X_test_imp)

    # Compute sample weights if balanced
    sample_weights = None
    if class_weight == "balanced":
        print("[*] Computing balanced sample weights for training...")
        sample_weights = compute_sample_weight("balanced", y_train)

    trained_models = {}
    eval_results = {}

    # 1. Random Forest
    if "rf" in models_to_train or "randomforest" in models_to_train:
        print("\n" + "=" * 70)
        print(f"[*] Training Random Forest Classifier (trees={rf_n_estimators}, max_depth={rf_max_depth})...")
        print("=" * 70)
        t_rf0 = time.time()
        rf = RandomForestClassifier(
            n_estimators=rf_n_estimators,
            max_depth=rf_max_depth,
            class_weight="balanced" if class_weight == "balanced" else None,
            n_jobs=-1,
            random_state=random_state,
        )
        rf.fit(X_train_scaled, y_train, sample_weight=sample_weights)
        rf_time = time.time() - t_rf0
        print(f"[*] Random Forest trained in {rf_time:.2f}s")

        trained_models["RandomForest"] = rf
        rf_pred = rf.predict(X_test_scaled)
        rf_proba = rf.predict_proba(X_test_scaled)
        eval_results["RandomForest"] = {
            "accuracy": float(accuracy_score(y_test, rf_pred)),
            "macro_f1": float(f1_score(y_test, rf_pred, average="macro", zero_division=0)),
            "weighted_f1": float(f1_score(y_test, rf_pred, average="weighted", zero_division=0)),
            "classification_report": classification_report(
                y_test, rf_pred, target_names=le.classes_, output_dict=True, zero_division=0
            ),
            "confusion_matrix": confusion_matrix(y_test, rf_pred).tolist(),
            "probabilities": rf_proba,
            "training_time": rf_time,
        }

    # 2. XGBoost
    if "xgboost" in models_to_train or "xgb" in models_to_train:
        print("\n" + "=" * 70)
        print(f"[*] Training XGBoost Classifier (trees={xgb_n_estimators}, max_depth={xgb_max_depth})...")
        print("=" * 70)
        t_xgb0 = time.time()
        xgb = XGBClassifier(
            n_estimators=xgb_n_estimators,
            max_depth=xgb_max_depth,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            n_jobs=-1,
            random_state=random_state,
            eval_metric="mlogloss",
        )
        xgb.fit(X_train_scaled, y_train, sample_weight=sample_weights)
        xgb_time = time.time() - t_xgb0
        print(f"[*] XGBoost trained in {xgb_time:.2f}s")

        trained_models["XGBoost"] = xgb
        xgb_pred = xgb.predict(X_test_scaled)
        xgb_proba = xgb.predict_proba(X_test_scaled)
        eval_results["XGBoost"] = {
            "accuracy": float(accuracy_score(y_test, xgb_pred)),
            "macro_f1": float(f1_score(y_test, xgb_pred, average="macro", zero_division=0)),
            "weighted_f1": float(f1_score(y_test, xgb_pred, average="weighted", zero_division=0)),
            "classification_report": classification_report(
                y_test, xgb_pred, target_names=le.classes_, output_dict=True, zero_division=0
            ),
            "confusion_matrix": confusion_matrix(y_test, xgb_pred).tolist(),
            "probabilities": xgb_proba,
            "training_time": xgb_time,
        }

    # 3. Ensemble Evaluation (RF 0.65 + XGB 0.35)
    if "RandomForest" in eval_results and "XGBoost" in eval_results:
        rf_p = eval_results["RandomForest"]["probabilities"]
        xgb_p = eval_results["XGBoost"]["probabilities"]
        ens_p = 0.65 * rf_p + 0.35 * xgb_p
        ens_pred = np.argmax(ens_p, axis=1)

        eval_results["Ensemble"] = {
            "accuracy": float(accuracy_score(y_test, ens_pred)),
            "macro_f1": float(f1_score(y_test, ens_pred, average="macro", zero_division=0)),
            "weighted_f1": float(f1_score(y_test, ens_pred, average="weighted", zero_division=0)),
            "classification_report": classification_report(
                y_test, ens_pred, target_names=le.classes_, output_dict=True, zero_division=0
            ),
            "confusion_matrix": confusion_matrix(y_test, ens_pred).tolist(),
        }

    # Print Full Tables for User
    print("\n" + "=" * 80)
    print("STEP 14.6c METRICS RESULTS REPORT")
    print("=" * 80)

    for m_name in ["RandomForest", "XGBoost", "Ensemble"]:
        if m_name not in eval_results:
            continue
        res = eval_results[m_name]
        rep = res["classification_report"]
        print(f"\n=== {m_name} -- Combined Held-Out Test Set ===")
        print(f"{'Class':<12} | {'Precision':<9} | {'Recall':<9} | {'F1':<9} | {'Support':<8} | {'>=0.95 Recall?'}")
        print("-" * 65)
        for cls in CICDDOS2019_CLASSES:
            if cls in rep:
                c_prec = rep[cls]["precision"]
                c_rec = rep[cls]["recall"]
                c_f1 = rep[cls]["f1-score"]
                c_supp = int(rep[cls]["support"])
                pass_str = "YES" if c_rec >= 0.95 else ("FAIL" if cls != "Benign" else "N/A")
                print(f"{cls:<12} | {c_prec:<9.4f} | {c_rec:<9.4f} | {c_f1:<9.4f} | {c_supp:<8,d} | {pass_str}")
        print("-" * 65)
        ov_acc = res["accuracy"]
        macro_f1 = res["macro_f1"]
        print(f"{'OVERALL':<12} | {'':<9} | {ov_acc:<9.4f} | {res['weighted_f1']:<9.4f} | {len(y_test):<8,d} |")
        print(f"{'MACRO F1':<12} | {'':<9} | {'':<9} | {macro_f1:<9.4f} | {'':<8} |")

        # Confusion Matrix
        cm = np.array(res["confusion_matrix"])
        print(f"\nConfusion Matrix ({m_name}):")
        cm_df = pd.DataFrame(cm, index=CICDDOS2019_CLASSES, columns=CICDDOS2019_CLASSES)
        print(cm_df.to_string())

    # Save retrained models in output_dir
    print(f"\n[*] Saving retrained model bundles to {output_dir}...")
    if "RandomForest" in trained_models:
        rf_bundle = DDoSClassifier({
            "model": trained_models["RandomForest"],
            "scaler": scaler,
            "imputer": imputer,
            "classes": list(le.classes_),
            "feature_names": list(CICFLOWMETER_FEATURE_NAMES),
        })
        rf_path = os.path.join(output_dir, "cicddos2019_rf.pkl")
        rf_bundle.save(rf_path)
        print(f"[*] Saved RF to: {rf_path}")

    if "XGBoost" in trained_models:
        xgb_bundle = DDoSClassifier({
            "model": trained_models["XGBoost"],
            "scaler": scaler,
            "imputer": imputer,
            "classes": list(le.classes_),
            "feature_names": list(CICFLOWMETER_FEATURE_NAMES),
        })
        xgb_path = os.path.join(output_dir, "cicddos2019_xgboost.pkl")
        xgb_bundle.save(xgb_path)
        print(f"[*] Saved XGBoost to: {xgb_path}")

    # Remove non-serializable probabilities before saving eval report
    clean_eval = {}
    for k, v in eval_results.items():
        clean_eval[k] = {ik: iv for ik, iv in v.items() if ik != "probabilities"}

    report_path = os.path.join(report_dir, "eval_report.json")
    with open(report_path, "w") as f:
        json.dump(clean_eval, f, indent=2)
    print(f"[*] Saved evaluation report to: {report_path}")

    return eval_results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Retrain DDoS Models")
    parser.add_argument("--dataset", default=None, help="Path to single dataset (.parquet or .csv)")
    parser.add_argument("--train-dataset", default=None, help="Path to separate train dataset")
    parser.add_argument("--test-dataset", default=None, help="Path to separate test dataset")
    parser.add_argument("--models", nargs="+", default=["rf", "xgboost"], help="Models to train: rf, xgboost")
    parser.add_argument("--test-split", type=float, default=0.20, help="Test split fraction (default: 0.20)")
    parser.add_argument("--stratify", default="Label", help="Stratify column name")
    parser.add_argument("--class-weight", default="balanced", help="Class weighting scheme: balanced or none")
    parser.add_argument("--random-state", type=int, default=42, help="Random state seed")
    parser.add_argument("--rf-max-depth", type=int, default=16, help="Random Forest max depth")
    parser.add_argument("--rf-n-estimators", type=int, default=100, help="Random Forest n_estimators")
    parser.add_argument("--xgb-max-depth", type=int, default=6, help="XGBoost max depth")
    parser.add_argument("--xgb-n-estimators", type=int, default=100, help="XGBoost n_estimators")
    parser.add_argument("--output-dir", default="models/retrained/", help="Output directory for trained models")
    parser.add_argument("--report-dir", default="docs/eval/retrain_phase3/", help="Directory for eval reports")

    args = parser.parse_args()

    run_training(
        dataset_path=args.dataset,
        train_dataset_path=args.train_dataset,
        test_dataset_path=args.test_dataset,
        models_to_train=[m.lower() for m in args.models],
        test_split=args.test_split,
        stratify_col=args.stratify,
        class_weight=args.class_weight,
        random_state=args.random_state,
        rf_max_depth=args.rf_max_depth,
        rf_n_estimators=args.rf_n_estimators,
        xgb_max_depth=args.xgb_max_depth,
        xgb_n_estimators=args.xgb_n_estimators,
        output_dir=args.output_dir,
        report_dir=args.report_dir,
    )
