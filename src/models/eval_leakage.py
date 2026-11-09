# -*- coding: utf-8 -*-
"""
Leakage before/after comparison for the supervised classifier.

BEFORE (leaky): random stratified 80/20 split WITHIN one extraction — duplicate /
near-duplicate synthetic flows leak across train and test, inflating metrics.
AFTER  (leakage-safe): train on one extraction, test on a SEPARATE extraction
(`data/test_real_v2.parquet`), with exact-duplicate rows removed across the boundary.

NOTE on "by-capture": the merged parquets carry no capture/day id, so a literal
per-capture GroupShuffle isn't reconstructable from them; the separate-extraction
train/test files are the available leakage-safe proxy (different CICFlowMeter runs).
See docs/EVAL_NOTES.md.

Run: python -m src.models.eval_leakage --cap 12000
"""
import argparse
import sys

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES


def _prep(df, feats):
    df = df.copy()
    df[feats] = df[feats].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return df


def _cap_per_class(df, cap, seed=42):
    parts = [g.sample(n=min(len(g), cap), random_state=seed) for _, g in df.groupby("Label")]
    return pd.concat(parts).reset_index(drop=True)


def _metrics(y_true, y_pred, labels, benign="Benign"):
    yt, yp = np.array(y_true), np.array(y_pred)
    macro_f = f1_score(yt, yp, labels=labels, average="macro", zero_division=0)
    mask = yt == benign
    benign_fpr = float((yp[mask] != benign).mean()) if mask.any() else float("nan")
    # Binary attack-vs-benign (attack = positive).
    yt_bin, yp_bin = (yt != benign).astype(int), (yp != benign).astype(int)
    detection = recall_score(yt_bin, yp_bin, zero_division=0)      # attack detection rate
    bin_f1 = f1_score(yt_bin, yp_bin, zero_division=0)
    return {"macro_f1": macro_f, "benign_fpr": benign_fpr,
            "detection": float(detection), "bin_f1": float(bin_f1)}


def _fit_eval(Xtr, ytr, Xte, yte, labels):
    le = LabelEncoder().fit(labels)
    clf = XGBClassifier(n_estimators=120, max_depth=7, tree_method="hist", device="cpu",
                        n_jobs=-1, eval_metric="mlogloss", verbosity=0)
    clf.fit(Xtr, le.transform(ytr))
    pred = le.inverse_transform(clf.predict(Xte))
    return _metrics(yte, pred, labels)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", default="data/combined_training_set.parquet")
    ap.add_argument("--test", default="data/test_real_v2.parquet")
    ap.add_argument("--cap", type=int, default=12000, help="per-class row cap for tractability")
    ap.add_argument("--out", default="docs/EVAL_NOTES.md")
    args = ap.parse_args(argv)

    feats = [c for c in CICFLOWMETER_FEATURE_NAMES]
    pool = _prep(pd.read_parquet(args.train), feats)
    pool = _cap_per_class(pool, args.cap)
    labels = sorted(pool["Label"].unique())

    # BEFORE: leaky random split within one extraction.
    tr, te = train_test_split(pool, test_size=0.2, stratify=pool["Label"], random_state=42)
    before = _fit_eval(tr[feats].to_numpy(float), tr["Label"].to_numpy(),
                       te[feats].to_numpy(float), te["Label"].to_numpy(), labels)

    # AFTER: separate-extraction test, exact-duplicate rows removed across the boundary.
    import hashlib

    def _rowhash(arr):
        return hashlib.md5(np.ascontiguousarray(arr, dtype=np.float64).tobytes(), usedforsecurity=False).hexdigest()

    test_df = _prep(pd.read_parquet(args.test), feats)
    test_df = test_df[test_df["Label"].isin(labels)]
    test_df = _cap_per_class(test_df, args.cap)
    train_keys = {_rowhash(r) for r in pool[feats].round(6).to_numpy()}
    keep = [_rowhash(r) not in train_keys for r in test_df[feats].round(6).to_numpy()]
    dup = len(test_df) - int(sum(keep))
    test_df = test_df[keep]
    after = _fit_eval(pool[feats].to_numpy(float), pool["Label"].to_numpy(),
                      test_df[feats].to_numpy(float), test_df["Label"].to_numpy(), labels)

    md = ["", "## 4. Leakage before/after (supervised)", "",
          f"Per-class cap {args.cap}; exact-duplicate test rows removed across the boundary "
          f"({dup:,} overlaps found). Binary = attack-vs-benign (the headline); macro-F1 = per-class.", "",
          "| Split | binary detection rate | binary benign FPR | binary F1 | per-class macro-F1 |",
          "|---|---:|---:|---:|---:|",
          f"| BEFORE — random in-file (leaky) | {before['detection']:.3f} | {before['benign_fpr']:.2%} "
          f"| {before['bin_f1']:.3f} | {before['macro_f1']:.3f} |",
          f"| AFTER — separate extraction (leakage-safe) | {after['detection']:.3f} | {after['benign_fpr']:.2%} "
          f"| {after['bin_f1']:.3f} | {after['macro_f1']:.3f} |"]
    text = "\n".join(md)
    print(text)
    print(f"\n[delta binary-F1 = {after['bin_f1']-before['bin_f1']:+.3f} | "
          f"delta macro-F1 = {after['macro_f1']-before['macro_f1']:+.3f}]")
    with open(args.out, "a", encoding="utf-8") as f:
        f.write(text + f"\n\n_delta binary-F1 = {after['bin_f1']-before['bin_f1']:+.3f}, "
                       f"delta macro-F1 = {after['macro_f1']-before['macro_f1']:+.3f}. The leakage-safe "
                       "(AFTER) numbers are the honest ones._\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
