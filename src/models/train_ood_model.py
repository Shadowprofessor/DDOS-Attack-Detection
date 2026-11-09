# -*- coding: utf-8 -*-
"""
Train the deployed OOD model: an isotonic-calibrated XGBoost + a tau calibrated to a
target false-OOD rate. This is the SAME methodology the LOCO eval uses, and it backs
/score/flow directly — so the README OOD numbers describe what actually runs.

    python -m src.models.train_ood_model --target-false-ood 0.02 --out models/ood_model.joblib
    # held-out variant for the unseen-class demo:
    python -m src.models.train_ood_model --holdout LDAP --out models/ood_model_heldout_LDAP.joblib
"""
import argparse
import sys

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from src.models.ood_detector import OODDetector, ood_scores_from_proba, calibrate_tau
from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES

try:
    from sklearn.frozen import FrozenEstimator

    def _calibrate(base, Xc, yc):
        return CalibratedClassifierCV(FrozenEstimator(base), method="isotonic").fit(Xc, yc)
except Exception:  # pragma: no cover
    def _calibrate(base, Xc, yc):
        return CalibratedClassifierCV(base, method="isotonic", cv="prefit").fit(Xc, yc)


def _cap(df, cap, seed=42):
    return pd.concat(
        [g.sample(n=min(len(g), cap), random_state=seed) for _, g in df.groupby("Label")]
    ).reset_index(drop=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/combined_training_set.parquet")
    ap.add_argument("--val", default="data/test_real_v2.parquet")
    ap.add_argument("--holdout", default=None, help="attack class to EXCLUDE from training")
    ap.add_argument("--target-false-ood", type=float, default=0.02)
    ap.add_argument("--per-class-cap", type=int, default=8000)
    ap.add_argument("--out", default="models/ood_model.joblib")
    a = ap.parse_args(argv)

    feats = list(CICFLOWMETER_FEATURE_NAMES)
    df = pd.read_parquet(a.data)
    df[feats] = df[feats].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    if a.holdout:
        df = df[df.Label != a.holdout]
    df = _cap(df, a.per_class_cap)
    labels = sorted(df.Label.unique())
    le = LabelEncoder().fit(labels)

    idx = np.random.default_rng(42).permutation(len(df))
    cut = int(0.8 * len(idx))
    tr, ca = df.iloc[idx[:cut]], df.iloc[idx[cut:]]
    base = XGBClassifier(n_estimators=150, max_depth=7, tree_method="hist", device="cpu",
                         n_jobs=-1, eval_metric="mlogloss", verbosity=0)
    base.fit(tr[feats].to_numpy(float), le.transform(tr.Label))
    cal = _calibrate(base, ca[feats].to_numpy(float), le.transform(ca.Label))

    val = pd.read_parquet(a.val)
    val[feats] = val[feats].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    val = _cap(val[val.Label.isin(labels)], a.per_class_cap)
    vs = ood_scores_from_proba(cal.predict_proba(val[feats].to_numpy(float)))
    tau = calibrate_tau(vs, a.target_false_ood)
    realized = float((vs >= tau).mean())

    OODDetector(tau=tau, target_false_ood=a.target_false_ood, model=cal, feature_names=feats,
                classes=list(le.classes_)).save(a.out)
    print(f"[+] OOD model: {len(labels)} classes"
          f"{' (holdout=' + a.holdout + ')' if a.holdout else ''}, "
          f"tau={tau:.4f} target_false_ood={a.target_false_ood:.0%} realized={realized:.2%} -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
