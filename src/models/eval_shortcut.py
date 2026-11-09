# -*- coding: utf-8 -*-
"""
Shortcut-feature audit: is the (same-dataset) leakage-safe performance driven by genuine
attack signal or by CICFlowMeter artefacts?

Trains on `combined_training_set`, tests on the deduped `test_real_v2` (leakage-safe),
reports the top-20 features by XGBoost gain AND permutation importance, then retrains
WITHOUT the flagged artefact features and re-reports binary + per-class metrics.

Note: `Destination Port` and timestamp/ID fields are NOT in the 77-feature set, so they
cannot leak. The artefact candidates that ARE present are the TCP-handshake / timing ones
below (they can encode tool-specific fingerprints rather than attack behaviour).

Run: python -m src.models.eval_shortcut --cap 10000
"""
import argparse
import hashlib
import sys

import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance
from sklearn.metrics import f1_score, recall_score
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES

ARTEFACTS = ["Flow Duration", "Fwd Header Length", "Bwd Header Length",
             "Init Fwd Win Bytes", "Init Bwd Win Bytes"]


def _cap(df, cap, seed=42):
    return pd.concat([g.sample(n=min(len(g), cap), random_state=seed)
                      for _, g in df.groupby("Label")]).reset_index(drop=True)


def _prep(df, feats):
    df = df.copy()
    df[feats] = df[feats].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return df


def _rowhash(a):
    return hashlib.md5(np.ascontiguousarray(a, dtype=np.float64).tobytes(), usedforsecurity=False).hexdigest()


def _binary(yt, yp, labels, benign="Benign"):
    yt, yp = np.array(yt), np.array(yp)
    macro = f1_score(yt, yp, labels=labels, average="macro", zero_division=0)
    ytb, ypb = (yt != benign).astype(int), (yp != benign).astype(int)
    det = recall_score(ytb, ypb, zero_division=0)
    f1b = f1_score(ytb, ypb, zero_division=0)
    bfpr = float((yp[yt == benign] != benign).mean()) if (yt == benign).any() else float("nan")
    return {"detection": float(det), "benign_fpr": bfpr, "bin_f1": float(f1b), "macro_f1": float(macro)}


def _fit(feats, tr, te, labels):
    le = LabelEncoder().fit(labels)
    clf = XGBClassifier(n_estimators=150, max_depth=7, tree_method="hist", device="cpu",
                        n_jobs=-1, eval_metric="mlogloss", verbosity=0)
    clf.fit(tr[feats].to_numpy(float), le.transform(tr["Label"]))
    pred = le.inverse_transform(clf.predict(te[feats].to_numpy(float)))
    return clf, le, _binary(te["Label"].to_numpy(), pred, labels)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", default="data/combined_training_set.parquet")
    ap.add_argument("--test", default="data/test_real_v2.parquet")
    ap.add_argument("--cap", type=int, default=10000)
    ap.add_argument("--perm-n", type=int, default=4000)
    ap.add_argument("--out", default="docs/EVAL_NOTES.md")
    a = ap.parse_args(argv)

    feats = list(CICFLOWMETER_FEATURE_NAMES)
    pool = _cap(_prep(pd.read_parquet(a.train), feats), a.cap)
    labels = sorted(pool["Label"].unique())
    test = _prep(pd.read_parquet(a.test), feats)
    test = test[test["Label"].isin(labels)]
    test = _cap(test, a.cap)
    # dedup test rows that exactly match a train row (leakage-safe)
    keys = {_rowhash(r) for r in pool[feats].round(6).to_numpy()}
    dup = int(sum(_rowhash(r) in keys for r in test[feats].round(6).to_numpy()))
    test = test[[_rowhash(r) not in keys for r in test[feats].round(6).to_numpy()]]

    # --- full model + importances ---
    clf, le, m_all = _fit(feats, pool, test, labels)
    gain = clf.get_booster().get_score(importance_type="gain")
    gain = {feats[int(k[1:])]: v for k, v in gain.items()}  # f0 -> name
    top_gain = sorted(gain.items(), key=lambda x: -x[1])[:20]

    sub = test.sample(n=min(a.perm_n, len(test)), random_state=1)
    perm = permutation_importance(clf, sub[feats].to_numpy(float), le.transform(sub["Label"]),
                                  n_repeats=3, random_state=1, n_jobs=-1)
    top_perm = sorted(zip(feats, perm.importances_mean), key=lambda x: -x[1])[:20]

    # --- retrain without artefacts ---
    feats_clean = [f for f in feats if f not in ARTEFACTS]
    _, _, m_clean = _fit(feats_clean, pool, test, labels)

    def line(tag, m):
        return (f"| {tag} | {m['detection']:.3f} | {m['benign_fpr']:.2%} "
                f"| {m['bin_f1']:.3f} | {m['macro_f1']:.3f} |")

    md = ["", "## 5. Shortcut-feature audit (leakage-safe, same-dataset)", "",
          f"Train=combined_training_set, test=test_real_v2 (deduped: {dup:,} exact-dup rows removed). "
          f"`Destination Port` / timestamps are not in the 77 features.", "",
          "**Top-20 by XGBoost gain:** " + ", ".join(f"{k}" for k, _ in top_gain), "",
          "**Top-20 by permutation importance:** " + ", ".join(f"{k}" for k, _ in top_perm), "",
          f"**Flagged artefacts removed:** {', '.join(ARTEFACTS)}", "",
          "| Model | binary detection | binary benign FPR | binary F1 | per-class macro-F1 |",
          "|---|---:|---:|---:|---:|",
          line("All 77 features", m_all),
          line(f"Without {len(ARTEFACTS)} artefacts", m_clean)]
    text = "\n".join(md)
    print(text)
    print(f"\n[artefact removal -> binary F1 {m_all['bin_f1']:.3f}->{m_clean['bin_f1']:.3f}, "
          f"macro-F1 {m_all['macro_f1']:.3f}->{m_clean['macro_f1']:.3f}]")
    with open(a.out, "a", encoding="utf-8") as f:
        f.write(text + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
