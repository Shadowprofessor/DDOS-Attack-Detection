# -*- coding: utf-8 -*-
"""v4.4.0 cross-dataset harness (CIC-DDoS2019 -> CICIoT2023, Option B column mapping)."""
import json
import os
from pathlib import Path

import pandas as pd
import pytest

from src.eval import cross_dataset as cd
from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES

REPO = Path(__file__).resolve().parent.parent
RESULTS = REPO / "docs" / "eval" / "cross_dataset" / "results.json"
DATA = REPO / "data" / "ciciot2023"


def _rows(label, proto, syn, n):
    return pd.DataFrame({"Header_Length": [20.0] * n, "Protocol Type": [proto] * n, "Rate": [100.0 + i for i in range(n)],
                         "syn_count": [syn] * n, "AVG": [60.0] * n, "Tot size": [60.0] * n, "label": [label] * n})


@pytest.fixture
def csv_dir(tmp_path):
    _rows("BenignTraffic", 6, 0, 30).to_csv(tmp_path / "BenignTraffic.csv", index=False)
    _rows("DDoS-SYN_Flood", 6, 90, 30).to_csv(tmp_path / "DDoS-SYN_Flood.csv", index=False)
    _rows("DDoS-UDP_Flood", 17, 0, 30).to_csv(tmp_path / "DDoS-UDP_Flood.csv", index=False)
    return tmp_path


def test_mapping_coverage_is_reported_honestly():
    mapped = cd.mapped_features()
    assert "Protocol" in mapped and "SYN Flag Count" in mapped
    assert len(mapped) == len(set(mapped)) < len(CICFLOWMETER_FEATURE_NAMES)
    assert all(m in CICFLOWMETER_FEATURE_NAMES for m in mapped)


def test_sampling_is_deterministic_and_manifested(csv_dir):
    a = cd.load_sample(csv_dir, per_class=10, seed=7)
    b = cd.load_sample(csv_dir, per_class=10, seed=7)
    c = cd.load_sample(csv_dir, per_class=10, seed=8)
    assert a.frame.equals(b.frame) and a.labels == b.labels
    assert not a.frame.equals(c.frame)
    assert sorted(set(a.labels)) == ["Benign", "Syn", "UDP"]
    m = a.manifest["DDoS-SYN_Flood.csv"]
    assert m["rows"] == 30 and m["sampled"] == 10 and len(m["sha256"]) == 64


def test_imputation_strategies(csv_dir):
    s = cd.load_sample(csv_dir, per_class=3, seed=1)
    zero = next(iter(cd.build_feature_dicts(s, "zero")))
    assert len(zero) == 77 and zero["Flow IAT Max"] == 0.0
    med = next(iter(cd.build_feature_dicts(s, "benign_median", {"Flow IAT Max": 42.0})))
    assert med["Flow IAT Max"] == 42.0 and med["Protocol"] == 6.0
    prod = next(iter(cd.build_feature_dicts(s, "production")))
    assert "Flow IAT Max" not in prod and prod["Protocol"] == 6.0  # left for the ensemble to impute
    with pytest.raises(ValueError):
        list(cd.build_feature_dicts(s, "bogus"))


def test_metrics_against_a_known_scorer(csv_dir):
    s = cd.load_sample(csv_dir, per_class=10, seed=3)

    def scorer(d):  # perfect on Syn, calls UDP "NTP" (UDP family), flags 1 in 10 benign
        if d["Protocol"] == 17:
            return "NTP", 0.9, True
        if d["SYN Flag Count"] > 0:
            return "Syn", 0.9, False
        return ("UDP" if d["Flow Packets/s"] == min_benign else "Benign"), 0.9, False

    min_benign = min(v for v, lab in zip(s.frame["Flow Packets/s"], s.labels) if lab == "Benign")
    r = cd.evaluate(s, scorer, "zero")
    assert r["n"] == 30 and r["benign_fpr"] == 0.1
    assert r["binary_attack"]["recall"] == 1.0
    assert r["per_class"]["UDP"]["correct_family"] == 1.0 and r["per_class"]["UDP"]["ood_flag_rate"] == 1.0
    assert r["per_class"]["Syn"]["correct_family"] == 1.0
    assert r["per_class"]["Benign"]["detected_as_attack"] == 0.1


def test_family_rules():
    assert cd.family_ok("Syn", "Syn") and not cd.family_ok("Syn", "UDP")
    assert cd.family_ok("UDP", "DNS") and not cd.family_ok("UDP", "Syn")
    assert cd.family_ok("Benign", "Benign") and not cd.family_ok("Benign", "UDP")


def test_run_includes_baseline_and_all_strategies(csv_dir):
    r = cd.run(lambda d: ("Benign", 1.0, False), {}, directory=csv_dir, per_class=5)
    assert [x["strategy"] for x in r["results"]] == list(cd.STRATEGIES)
    assert r["baseline_protocol_rule"]["per_class"]["Syn"]["correct_family"] == 1.0
    assert r["trained_on"] == "CIC-DDoS2019" and r["features_total"] == 77


@pytest.mark.skipif(not (RESULTS.is_file() and DATA.is_dir()), reason="needs data/ciciot2023 + committed results")
def test_reported_baseline_reproduces_from_seed():
    """The committed report must be reproducible: re-run the (model-free) baseline exactly."""
    rep = json.loads(RESULTS.read_text(encoding="utf-8"))
    s = cd.load_sample(DATA, per_class=rep["per_class"], seed=rep["seed"])
    assert {k: v["sha256"] for k, v in s.manifest.items()} == {k: v["sha256"] for k, v in rep["manifest"].items()}
    again = cd.evaluate(s, cd.protocol_baseline_scorer, "zero")
    assert again == rep["baseline_protocol_rule"]


@pytest.mark.skipif(os.environ.get("DDOS_RUN_SLOW") != "1" or not RESULTS.is_file(),
                    reason="slow: set DDOS_RUN_SLOW=1 with model artifacts present")
def test_reported_ensemble_numbers_reproduce():  # pragma: no cover - artifact + time dependent
    rep = json.loads(RESULTS.read_text(encoding="utf-8"))
    scorer, medians = cd.ensemble_scorer()
    again = cd.run(scorer, medians, per_class=rep["per_class"], seed=rep["seed"])
    assert again["results"] == rep["results"]


def test_markdown_rendered_from_results(csv_dir):
    r = cd.run(lambda d: ("Benign", 1.0, False), {}, directory=csv_dir, per_class=5)
    md = cd.render_markdown(r)
    assert md.count("\n|") >= 7 and "baseline: protocol/flag rule" in md
    assert "production path" in md


@pytest.mark.skipif(not RESULTS.is_file(), reason="results not generated")
def test_doc_table_matches_results_json():
    """docs/eval/cross_dataset.md must embed exactly the table generated from results.json."""
    doc = (REPO / "docs" / "eval" / "cross_dataset.md").read_text(encoding="utf-8")
    block = doc.split("<!-- RESULTS:START -->")[1].split("<!-- RESULTS:END -->")[0].strip()
    assert block == cd.render_markdown(json.loads(RESULTS.read_text(encoding="utf-8"))).strip()
