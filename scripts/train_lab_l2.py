# -*- coding: utf-8 -*-
"""v5.3.0: retrain L2 (XGBoost, the model /score/flow uses) on CIC-DDoS2019 + labelled lab traffic.

    python scripts/train_lab_l2.py                 # train + evaluate on CIC test and DEV lab runs
    python scripts/train_lab_l2.py --heldout run4  # ALSO evaluate on the held-out run (final step only)

Fixed BEFORE any held-out number existed (no tuning on held-out data):
* recipe: XGBoost, 120 trees, depth 7, hist, the same as `src/models/eval_leakage.py`; per-class caps
  (CIC 12,000, lab 5,000) so no class dominates;
* evaluation sets, reported SEPARATELY and never averaged:
  CIC = `data/test_real_v2.parquet` (a separate CICFlowMeter extraction: leakage-safe);
  DEV lab = runs 2+3; HELD-OUT lab = run4 (only with --heldout);
* models compared: `before` (the deployed artifact), `control` (CIC only, same recipe), `after`
  (CIC + lab train1, same recipe);
* deploy rule (CIC only, so the held-out run cannot influence it): `after` replaces `before` iff on
  CIC its macro-F1 drops by <= 0.05 and its benign FPR rises by <= 1 percentage point.

Caveat: lab train and lab test come from the same generator and network, so lab numbers can be
inflated by generator bias even though configurations and seeds differ.
"""
from __future__ import annotations

import argparse
import json
import pickle
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

FEATS = None
OUT = REPO / "docs" / "eval" / "l2_retrain"
DEPLOYED = REPO / "models" / "cicddos2019_xgboost.pkl"
NEW = REPO / "models" / "l2_cic_lab_xgboost.pkl"
VICTIM = "10.99.0.10"


def feats():
    global FEATS
    if FEATS is None:
        from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES

        FEATS = list(CICFLOWMETER_FEATURE_NAMES)
    return FEATS


def cap(df: pd.DataFrame, n: int, seed: int = 42) -> pd.DataFrame:
    return pd.concat([g.sample(n=min(len(g), n), random_state=seed) for _, g in df.groupby("Label")]).reset_index(drop=True)


def lab_frame(run: str, catalog: str) -> pd.DataFrame:
    """Flows of one lab run, labelled by the scenario that produced them (ground truth)."""
    from lab.library import CATALOGS, load_scenarios
    from src.eval.lab_analysis import flows_from_pcap

    run_dir = REPO / "data" / "lab_runs" / run
    cache = run_dir / "l2_flows.pkl"
    if cache.is_file():
        return pickle.loads(cache.read_bytes())
    scs = load_scenarios(CATALOGS[catalog])
    rows = []
    for r in json.loads((run_dir / "manifest.json").read_text())["runs"]:
        label = scs[r["scenario"]].label
        if label is None:
            continue  # the OOD probe has no class
        for f in flows_from_pcap(run_dir / r["pcap"]):
            if VICTIM not in (f["src"], f["dst"]):
                continue
            row = {c: float(f["features"].get(c, 0.0) or 0.0) for c in feats()}
            row.update(Label=label, scenario=r["scenario"], run=run)
            rows.append(row)
    df = pd.DataFrame(rows)
    cache.write_bytes(pickle.dumps(df))
    return df


def clean(X: pd.DataFrame) -> np.ndarray:
    return X[feats()].replace([np.inf, -np.inf], np.nan).fillna(0.0).to_numpy(np.float32)


def train(df: pd.DataFrame):
    from sklearn.preprocessing import LabelEncoder
    from xgboost import XGBClassifier

    le = LabelEncoder().fit(df["Label"])
    clf = XGBClassifier(n_estimators=120, max_depth=7, tree_method="hist", device="cpu", n_jobs=-1,
                        eval_metric="mlogloss", verbosity=0, random_state=42)
    clf.fit(clean(df), le.transform(df["Label"]))
    return {"model": clf, "scaler": None, "imputer": None, "classes": list(le.classes_), "feature_names": feats()}


def predict(bundle: dict, df: pd.DataFrame) -> np.ndarray:
    X = clean(df)
    if bundle.get("imputer") is not None:
        X = bundle["imputer"].transform(X)
    if bundle.get("scaler") is not None:
        X = bundle["scaler"].transform(X)
    idx = bundle["model"].predict(X)
    return np.array([bundle["classes"][int(i)] for i in np.asarray(idx).ravel()])


# One coarse taxonomy for every model: the deployed artifact merged reflection classes into
# "UDP-Reflection-Amplification", so native class names would not compare like with like.
COARSE = {"UDP-Lag": "UDP", **{k: "Reflection" for k in ("NTP", "DNS", "LDAP", "MSSQL", "NetBIOS", "SNMP", "Portmap",
                                                       "TFTP", "UDP-Reflection-Amplification")}}


def coarse(a: np.ndarray) -> np.ndarray:
    return np.array([COARSE.get(x, x) for x in a])


def metrics(y: np.ndarray, p: np.ndarray) -> dict:
    out = _metrics(coarse(y), coarse(p))
    native = _metrics(y, p)
    out["native_macro_f1"], out["native_per_class"] = native["macro_f1"], native["per_class"]
    return out


def _metrics(y: np.ndarray, p: np.ndarray) -> dict:
    from sklearn.metrics import f1_score, precision_recall_fscore_support

    labels = sorted(set(y))
    pr, rc, f1, sup = precision_recall_fscore_support(y, p, labels=labels, zero_division=0)
    benign = y == "Benign"
    attack = ~benign
    return {
        "n": int(len(y)),
        "macro_f1": round(float(f1_score(y, p, labels=labels, average="macro", zero_division=0)), 4),
        "benign_fpr": round(float((p[benign] != "Benign").mean()), 4) if benign.any() else None,
        "attack_detection": round(float((p[attack] != "Benign").mean()), 4) if attack.any() else None,
        "per_class": {lab: {"precision": round(float(a), 4), "recall": round(float(b), 4), "f1": round(float(c), 4),
                            "support": int(d)} for lab, a, b, c, d in zip(labels, pr, rc, f1, sup)},
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--train-runs", default="train1")
    ap.add_argument("--dev-runs", default="run2,run3")
    ap.add_argument("--heldout", default=None, help="held-out run, e.g. run4 (final evaluation only)")
    a = ap.parse_args()
    import joblib

    cic_tr = cap(pd.read_parquet(REPO / "data" / "combined_training_set.parquet"), 12000)
    cic_te = pd.read_parquet(REPO / "data" / "test_real_v2.parquet")
    lab_tr = pd.concat([lab_frame(r, "train") for r in a.train_runs.split(",")])
    print("CIC train", cic_tr["Label"].value_counts().to_dict(), "\nlab train", lab_tr["Label"].value_counts().to_dict(), flush=True)
    before = joblib.load(DEPLOYED)
    control = train(cic_tr)
    after = train(pd.concat([cic_tr, cap(lab_tr, 5000)], ignore_index=True))
    sets = {"CIC test_real_v2 (leakage-safe)": cic_te,
            "DEV lab " + a.dev_runs: pd.concat([lab_frame(r, "main") for r in a.dev_runs.split(",")])}
    if a.heldout:
        sets["HELD-OUT lab " + a.heldout] = lab_frame(a.heldout, "main")
    report = {"recipe": "XGBoost 120 trees, depth 7, hist; caps CIC 12000 / lab 5000 per class",
              "metric_note": "macro_f1 / per_class use one coarse family taxonomy for every model (COARSE); "
                             "benign_fpr and attack_detection are taxonomy-free; native_* use each set's own labels",
              "classes": {"before": before["classes"], "control": control["classes"], "after": after["classes"]},
              "train_rows": {"cic": int(len(cic_tr)), "lab": int(len(cap(lab_tr, 5000)))}, "results": {}}
    for name, df in sets.items():
        y = df["Label"].to_numpy()
        report["results"][name] = {m: metrics(y, predict(b, df)) for m, b in
                                   (("before", before), ("control", control), ("after", after))}
        r = report["results"][name]
        print(name, {m: (r[m]["macro_f1"], r[m]["benign_fpr"], r[m]["attack_detection"]) for m in r}, flush=True)
    cic = report["results"]["CIC test_real_v2 (leakage-safe)"]
    d_f1 = cic["after"]["macro_f1"] - cic["before"]["macro_f1"]
    d_fpr = (cic["after"]["benign_fpr"] or 0) - (cic["before"]["benign_fpr"] or 0)
    report["deploy_rule"] = {"cic_macro_f1_change": round(d_f1, 4), "cic_benign_fpr_change": round(d_fpr, 4),
                             "deploy": bool(d_f1 >= -0.05 and d_fpr <= 0.01)}
    joblib.dump(after, NEW)
    OUT.mkdir(parents=True, exist_ok=True)
    name = "results_heldout.json" if a.heldout else "results_dev.json"
    (OUT / name).write_text(json.dumps(report, indent=2), encoding="utf-8")
    print("deploy rule:", report["deploy_rule"], "\nwrote", OUT / name, "and", NEW)


if __name__ == "__main__":
    main()
