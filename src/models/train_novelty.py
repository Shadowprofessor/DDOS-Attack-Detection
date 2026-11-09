# -*- coding: utf-8 -*-
"""
Train + calibrate the Layer-2 zero-day novelty detector (IsolationForest).

Fits on BENIGN flow rows only, then calibrates the decision threshold on a held-out
BENIGN set to a target false-positive rate (default 1%). Features are aligned to the
77 CICFlowMeter columns the scoring service serves, so the saved artifact drops in.

Regenerate the shipped artifact:
    python -m src.models.train_novelty \
        --data data/combined_training_set.parquet \
        --val  data/test_real_v2.parquet \
        --target-fpr 0.01 --out models/novelty_detector.joblib
"""
import argparse
import sys

import numpy as np
import pandas as pd

from src.models.anomaly_novelty import NoveltyDetector

try:
    from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES
except Exception:  # pragma: no cover
    CICFLOWMETER_FEATURE_NAMES = None


def _load(path: str) -> pd.DataFrame:
    if path.endswith(".parquet"):
        return pd.read_parquet(path)
    return pd.read_csv(path)


def _benign_matrix(df: pd.DataFrame, feats, label_col: str, benign_label: str) -> np.ndarray:
    rows = df[df[label_col].astype(str).str.strip().str.lower() == benign_label.lower()]
    present = [c for c in feats if c in rows.columns]
    X = rows[present].replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(dtype=float)
    return X, present


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Train + calibrate IsolationForest novelty detector.")
    ap.add_argument("--data", required=True, help="Training file (parquet or csv) with a label column.")
    ap.add_argument("--val", default=None, help="Validation file for threshold calibration (benign rows).")
    ap.add_argument("--label-col", default="Label")
    ap.add_argument("--benign-label", default="Benign")
    ap.add_argument("--target-fpr", type=float, default=0.01)
    ap.add_argument("--n-estimators", type=int, default=200)
    ap.add_argument("--out", default="models/novelty_detector.joblib")
    args = ap.parse_args(argv)

    feats = CICFLOWMETER_FEATURE_NAMES
    train_df = _load(args.data)
    if feats is None:
        feats = [c for c in train_df.columns if c != args.label_col]
    X_train, used = _benign_matrix(train_df, feats, args.label_col, args.benign_label)
    if len(X_train) == 0:
        print(f"[!] no benign rows (label == '{args.benign_label}') in {args.data}")
        return 2

    # Calibration benign set: separate --val file, else hold out 20% of training benign.
    if args.val:
        X_val, _ = _benign_matrix(_load(args.val), used, args.label_col, args.benign_label)
    else:
        rng = np.random.default_rng(42)
        idx = rng.permutation(len(X_train))
        cut = int(len(idx) * 0.8)
        X_val = X_train[idx[cut:]]
        X_train = X_train[idx[:cut]]

    det = NoveltyDetector(n_estimators=args.n_estimators)
    det.feature_names = list(used)
    det.fit(X_train)
    thr = det.calibrate_threshold(X_val, target_fpr=args.target_fpr)

    # Report the realized benign FPR on the calibration set.
    realized_fpr = float(det.is_novel(X_val).mean())
    det.save(args.out)
    print(f"[+] Novelty detector: fit on {len(X_train):,} benign rows, {len(used)} features.")
    print(f"[+] Calibrated threshold={thr:.4f} for target FPR={args.target_fpr:.1%} "
          f"-> realized benign FPR on val={realized_fpr:.2%}")
    print(f"[+] Saved -> {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
