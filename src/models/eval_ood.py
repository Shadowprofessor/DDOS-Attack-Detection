# -*- coding: utf-8 -*-
"""
Leave-one-attack-class-out (LOCO) evaluation of the supervised OOD / zero-day signal.

For each attack class c:
  1. train a classifier on all classes EXCEPT c  (c is the simulated zero-day),
  2. isotonic-calibrate its probabilities on a held-out KNOWN validation split,
  3. calibrate tau to a target false-OOD rate on known validation,
  4. on the held-out class c, report:
       - % flagged OOD                 (correctly spotted as unknown)
       - % caught as another attack     (wrong family, but still flagged attack)
       - % MISSED as Benign             (the dangerous number)
     plus AUROC for known-vs-held-out separability.

Run:
    python -m src.models.eval_ood --data data/combined_training_set.parquet \
        --target-false-ood 0.02 --per-class-cap 4000
"""
import argparse
import sys

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import roc_auc_score
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from src.models.ood_detector import ood_scores_from_proba, calibrate_tau

try:  # sklearn >= 1.6 removed cv="prefit" in favour of FrozenEstimator
    from sklearn.frozen import FrozenEstimator

    def _calibrate_prefit(base, Xc, yc):
        return CalibratedClassifierCV(FrozenEstimator(base), method="isotonic").fit(Xc, yc)
except Exception:  # pragma: no cover - older sklearn
    def _calibrate_prefit(base, Xc, yc):
        return CalibratedClassifierCV(base, method="isotonic", cv="prefit").fit(Xc, yc)

try:
    from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES
except Exception:  # pragma: no cover
    CICFLOWMETER_FEATURE_NAMES = None


def _subsample(df, label_col, cap, seed=42):
    parts = []
    for lbl, g in df.groupby(label_col):
        parts.append(g.sample(n=min(len(g), cap), random_state=seed))
    return pd.concat(parts).sample(frac=1.0, random_state=seed).reset_index(drop=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Leave-one-class-out OOD evaluation.")
    ap.add_argument("--data", default="data/combined_training_set.parquet")
    ap.add_argument("--label-col", default="Label")
    ap.add_argument("--benign-label", default="Benign")
    ap.add_argument("--target-false-ood", type=float, default=0.02)
    ap.add_argument("--per-class-cap", type=int, default=4000)
    ap.add_argument("--out", default="docs/EVAL_NOTES.md")
    args = ap.parse_args(argv)

    df = pd.read_parquet(args.data) if args.data.endswith(".parquet") else pd.read_csv(args.data)
    feats = [c for c in (CICFLOWMETER_FEATURE_NAMES or []) if c in df.columns] or \
            [c for c in df.columns if c != args.label_col]
    df = _subsample(df, args.label_col, args.per_class_cap)
    df[feats] = df[feats].replace([np.inf, -np.inf], np.nan).fillna(0.0)

    attack_classes = [c for c in df[args.label_col].unique() if c != args.benign_label]
    rng = np.random.default_rng(42)
    rows = []

    for c in sorted(attack_classes):
        known = df[df[args.label_col] != c]
        held = df[df[args.label_col] == c]
        # split known into train / calib / val
        idx = rng.permutation(len(known))
        n = len(idx)
        tr, ca, va = idx[: int(.6 * n)], idx[int(.6 * n): int(.8 * n)], idx[int(.8 * n):]
        le = LabelEncoder().fit(known[args.label_col])
        Xtr, ytr = known.iloc[tr][feats].to_numpy(float), le.transform(known.iloc[tr][args.label_col])
        base = XGBClassifier(
            n_estimators=80, max_depth=6, tree_method="hist", device="cpu",
            n_jobs=-1, eval_metric="mlogloss", verbosity=0,
        ).fit(Xtr, ytr)
        cal = _calibrate_prefit(
            base, known.iloc[ca][feats].to_numpy(float), le.transform(known.iloc[ca][args.label_col])
        )

        val_scores = ood_scores_from_proba(cal.predict_proba(known.iloc[va][feats].to_numpy(float)))
        tau = calibrate_tau(val_scores, args.target_false_ood)

        held_X = held[feats].to_numpy(float)
        held_scores = ood_scores_from_proba(cal.predict_proba(held_X))
        held_pred = le.inverse_transform(cal.predict(held_X))
        is_ood = held_scores >= tau
        not_ood = ~is_ood
        pct_ood = 100.0 * is_ood.mean()
        pct_benign = 100.0 * ((held_pred == args.benign_label) & not_ood).mean()
        pct_other = 100.0 * ((held_pred != args.benign_label) & not_ood).mean()
        auroc = roc_auc_score(
            np.r_[np.zeros(len(val_scores)), np.ones(len(held_scores))],
            np.r_[val_scores, held_scores],
        )
        rows.append((c, len(held), pct_ood, pct_other, pct_benign, auroc))
        print(f"{c:<10} n={len(held):>6}  OOD={pct_ood:5.1f}%  other-attack={pct_other:5.1f}%  "
              f"MISSED-benign={pct_benign:5.1f}%  AUROC={auroc:.3f}")

    arr = np.array([[r[2], r[3], r[4], r[5]] for r in rows])
    mean = arr.mean(axis=0)
    print(f"\nMEAN       OOD={mean[0]:.1f}%  other-attack={mean[1]:.1f}%  "
          f"MISSED-benign={mean[2]:.1f}%  AUROC={mean[3]:.3f}")

    # Emit a markdown table for EVAL_NOTES.md
    md = ["", f"### LOCO OOD evaluation (target false-OOD = {args.target_false_ood:.0%}, "
              f"per-class cap = {args.per_class_cap})", "",
          "| Held-out class | n | flagged OOD | caught as other attack | **missed as Benign** | AUROC |",
          "|---|---:|---:|---:|---:|---:|"]
    for c, n, o, ot, b, a in rows:
        md.append(f"| {c} | {n} | {o:.1f}% | {ot:.1f}% | **{b:.1f}%** | {a:.3f} |")
    md.append(f"| **mean** | | {mean[0]:.1f}% | {mean[1]:.1f}% | **{mean[2]:.1f}%** | {mean[3]:.3f} |")
    print("\n".join(md))
    return 0


if __name__ == "__main__":
    sys.exit(main())
