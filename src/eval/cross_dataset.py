# -*- coding: utf-8 -*-
"""
Cross-dataset evaluation: models trained on CIC-DDoS2019, tested on CICIoT2023 (v4.4.0).

Option B (approved): CICIoT2023 ships its own 46-column, packet-window feature CSVs, not
CICFlowMeter flows. We map the columns that have a CICFlowMeter counterpart
(`CICIOT2023_COLUMN_ALIAS_MAP`) and fill the rest with one of three imputation strategies:

* ``zero``           - unmapped features = 0 (the registry default).
* ``benign_median``  - unmapped features = the CIC-DDoS2019 *Benign* training median
                       (label-agnostic, conservative).
* ``production``     - the live scoring path: unmapped features are left out and
                       `EnsembleClassifier._normalize_features` fills them from per-class medians
                       picked by a protocol/flag heuristic. This can make results look better than
                       a real cross-dataset test, because the heuristic sees protocol/flags.

Many mapped columns are only approximately equivalent (window averages vs per-flow totals),
so these numbers measure robustness to a *feature-schema shift*, not true generalisation with
the same extractor. See docs/eval/cross_dataset.md.

Binary task: attack vs benign. Family task: CICIoT2023 SYN flood -> "Syn", UDP flood -> "UDP"
(or the UDP-family classes listed in UDP_FAMILY).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Sequence

import numpy as np
import pandas as pd

from src.features.dataset_registry import CICIOT2023_COLUMN_ALIAS_MAP, normalize_label
from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES

REPO = Path(__file__).resolve().parent.parent.parent
DEFAULT_DIR = REPO / "data" / "ciciot2023"
DEFAULT_FILES = ("BenignTraffic.csv", "DDoS-SYN_Flood.csv", "DDoS-UDP_Flood.csv")
STRATEGIES = ("zero", "benign_median", "production")
UDP_FAMILY = frozenset({"UDP", "UDP-Lag", "UDP-Reflection-Amplification", "Reflection-Amplification",
                        "DNS", "NTP", "SNMP", "TFTP", "MSSQL", "NetBIOS", "LDAP", "Portmap"})
SEED = 20231101
PER_CLASS = 2000

# A scorer takes one feature dict and returns (label, confidence, ood_flag).
Scorer = Callable[[Dict[str, float]], "tuple[str, float, bool]"]


@dataclass
class Sample:
    frame: pd.DataFrame      # mapped CICFlowMeter-named columns only (unmapped absent)
    labels: List[str]        # normalised labels (Benign / Syn / UDP)
    manifest: Dict[str, dict]


def mapped_features() -> List[str]:
    """CICFlowMeter features that receive a value from CICIoT2023 (deduplicated, schema order)."""
    targets = {v for k, v in CICIOT2023_COLUMN_ALIAS_MAP.items() if v in CICFLOWMETER_FEATURE_NAMES}
    return [f for f in CICFLOWMETER_FEATURE_NAMES if f in targets]


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_sample(directory: Path = DEFAULT_DIR, files: Sequence[str] = DEFAULT_FILES,
                per_class: int = PER_CLASS, seed: int = SEED) -> Sample:
    frames, labels, manifest = [], [], {}
    rng = np.random.default_rng(seed)
    for name in files:
        path = Path(directory) / name
        raw = pd.read_csv(path)
        raw.columns = [str(c).strip() for c in raw.columns]
        n = min(per_class, len(raw))
        idx = np.sort(rng.choice(len(raw), size=n, replace=False))
        part = raw.iloc[idx]
        lab = [normalize_label(x) for x in part["label"]]
        mapped = {}
        for src, dst in CICIOT2023_COLUMN_ALIAS_MAP.items():
            if src in part.columns and dst in CICFLOWMETER_FEATURE_NAMES and dst not in mapped:
                mapped[dst] = pd.to_numeric(part[src], errors="coerce").astype(float).values
        frames.append(pd.DataFrame(mapped))
        labels.extend(lab)
        manifest[name] = {"sha256": _sha256(path), "rows": int(len(raw)), "sampled": int(n)}
    frame = pd.concat(frames, ignore_index=True).replace([np.inf, -np.inf], np.nan).fillna(0.0)
    return Sample(frame=frame, labels=labels, manifest=manifest)


def build_feature_dicts(sample: Sample, strategy: str,
                        benign_medians: Optional[Dict[str, float]] = None) -> Iterable[Dict[str, float]]:
    if strategy not in STRATEGIES:
        raise ValueError(f"unknown strategy {strategy!r}")
    cols = list(sample.frame.columns)
    values = sample.frame.to_numpy(dtype=float)
    for row in values:
        d = {c: float(v) for c, v in zip(cols, row)}
        if strategy == "zero":
            for f in CICFLOWMETER_FEATURE_NAMES:
                d.setdefault(f, 0.0)
        elif strategy == "benign_median":
            meds = benign_medians or {}
            for f in CICFLOWMETER_FEATURE_NAMES:
                d.setdefault(f, float(meds.get(f, 0.0)))
        yield d  # "production": unmapped features absent -> ensemble's own imputation


def _prf(tp: int, fp: int, fn: int) -> Dict[str, float]:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f, 4)}


def family_ok(true: str, pred: str) -> bool:
    if true == "Syn":
        return pred == "Syn"
    if true == "UDP":
        return pred in UDP_FAMILY
    return pred == "Benign"


def evaluate(sample: Sample, scorer: Scorer, strategy: str,
             benign_medians: Optional[Dict[str, float]] = None) -> dict:
    preds, oods = [], []
    for d in build_feature_dicts(sample, strategy, benign_medians):
        label, _conf, ood = scorer(d)
        preds.append(label)
        oods.append(bool(ood))
    y = sample.labels
    is_att = [t != "Benign" for t in y]
    pr_att = [p != "Benign" for p in preds]
    tp = sum(a and b for a, b in zip(is_att, pr_att))
    fp = sum((not a) and b for a, b in zip(is_att, pr_att))
    fn = sum(a and (not b) for a, b in zip(is_att, pr_att))
    tn = sum((not a) and (not b) for a, b in zip(is_att, pr_att))
    per_class = {}
    for cls in sorted(set(y)):
        idx = [i for i, t in enumerate(y) if t == cls]
        dist: Dict[str, int] = {}
        for i in idx:
            dist[preds[i]] = dist.get(preds[i], 0) + 1
        per_class[cls] = {
            "n": len(idx),
            "detected_as_attack": round(sum(pr_att[i] for i in idx) / len(idx), 4),
            "correct_family": round(sum(family_ok(cls, preds[i]) for i in idx) / len(idx), 4),
            "ood_flag_rate": round(sum(oods[i] for i in idx) / len(idx), 4),
            "predicted": dict(sorted(dist.items(), key=lambda kv: -kv[1])[:5]),
        }
    return {
        "strategy": strategy,
        "n": len(y),
        "binary_attack": _prf(tp, fp, fn),
        "benign_fpr": round(fp / (fp + tn), 4) if fp + tn else None,
        "accuracy_binary": round((tp + tn) / len(y), 4),
        "per_class": per_class,
        "ood_flag_rate": round(sum(oods) / len(oods), 4),
    }


def run(scorer: Scorer, benign_medians: Optional[Dict[str, float]] = None, directory: Path = DEFAULT_DIR,
        per_class: int = PER_CLASS, seed: int = SEED, strategies: Sequence[str] = STRATEGIES) -> dict:
    sample = load_sample(directory, per_class=per_class, seed=seed)
    mapped = mapped_features()
    return {
        "dataset": "CICIoT2023 (Neto et al., 2023) - Benign / DDoS-SYN_Flood / DDoS-UDP_Flood CSV sample",
        "trained_on": "CIC-DDoS2019",
        "seed": seed,
        "per_class": per_class,
        "manifest": sample.manifest,
        "features_mapped": len(mapped),
        "features_total": len(CICFLOWMETER_FEATURE_NAMES),
        "mapped_feature_names": mapped,
        "results": [evaluate(sample, scorer, s, benign_medians) for s in strategies],
        "baseline_protocol_rule": evaluate(sample, protocol_baseline_scorer, "zero"),
    }


def render_markdown(report: dict) -> str:
    """Results tables generated from results.json (so docs never drift from the data)."""
    rows = ["| Imputation of unmapped features | Attack precision | Attack recall | Attack F1 | Benign FPR | "
            "Benign kept | SYN flood -> Syn | UDP flood -> UDP family | OOD flag rate |",
            "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    named = {"zero": "zero (registry default)", "benign_median": "CIC-DDoS2019 Benign median",
             "production": "production path (heuristic class medians)"}
    items = [(named.get(r["strategy"], r["strategy"]), r) for r in report["results"]]
    items.append(("**baseline: protocol/flag rule (no ML)**", report["baseline_protocol_rule"]))
    for name, r in items:
        pc, b = r["per_class"], r["binary_attack"]
        rows.append(f"| {name} | {b['precision']:.3f} | {b['recall']:.3f} | {b['f1']:.3f} | "
                    f"{r['benign_fpr']:.1%} | {pc['Benign']['correct_family']:.1%} | {pc['Syn']['correct_family']:.1%} | "
                    f"{pc['UDP']['correct_family']:.1%} | {r['ood_flag_rate']:.1%} |")
    rows += ["", "Top predicted labels per true class:", "",
             "| Imputation | Benign | SYN flood | UDP flood |", "|---|---|---|---|"]
    for name, r in items[:-1]:
        cells = [", ".join(f"{k} {v}" for k, v in r["per_class"][c]["predicted"].items()) for c in ("Benign", "Syn", "UDP")]
        rows.append(f"| {name} | " + " | ".join(cells) + " |")
    return "\n".join(rows) + "\n"


def protocol_baseline_scorer(d: Dict[str, float]):
    """Trivial non-ML rule: TCP with SYN flags -> Syn, UDP -> UDP, else Benign.

    Reported next to the ensemble: if this rule scores about as well, the test set is too easy
    to say much about the models' generalisation."""
    proto = int(d.get("Protocol", 0))
    if proto == 6 and d.get("SYN Flag Count", 0) > 0:
        return "Syn", 1.0, False
    if proto == 17:
        return "UDP", 1.0, False
    return "Benign", 1.0, False


def ensemble_scorer() -> "tuple[Scorer, Dict[str, float]]":  # pragma: no cover - needs model artifacts
    """Real scorer: the calibrated RF+XGB ensemble + supervised OOD detector (as /score/flow uses)."""
    from src.models.ensemble import CLASS_MEDIANS_PATH, get_default_ensemble
    from src.models.ood_detector import OODDetector

    ens = get_default_ensemble()
    for cand in (REPO / "models" / "ood_model.joblib", REPO / "models" / "ood_detector.json"):
        if cand.is_file():
            ood = OODDetector.load(str(cand))
            break
    else:
        ood = OODDetector()
    medians = json.loads(Path(CLASS_MEDIANS_PATH).read_text(encoding="utf-8")).get("Benign", {})

    def score(d: Dict[str, float]):
        label, conf, _ = ens.score_flow(d, feature_completeness=None)
        a = ood.assess_features(d) if ood.is_model_backed else ood.assess(float(conf))
        return label, float(conf), bool(a.get("ood_suspected"))

    return score, medians


def main() -> None:  # pragma: no cover - CLI
    import argparse

    ap = argparse.ArgumentParser(description="CIC-DDoS2019 -> CICIoT2023 cross-dataset evaluation")
    ap.add_argument("--per-class", type=int, default=PER_CLASS)
    ap.add_argument("--out", default=str(REPO / "docs" / "eval" / "cross_dataset" / "results.json"))
    args = ap.parse_args()
    scorer, medians = ensemble_scorer()
    report = run(scorer, medians, per_class=args.per_class)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    for r in report["results"] + [report["baseline_protocol_rule"]]:
        print(r["strategy"], r["binary_attack"], "benign_fpr", r["benign_fpr"],
              {k: v["correct_family"] for k, v in r["per_class"].items()})


if __name__ == "__main__":  # pragma: no cover
    main()
