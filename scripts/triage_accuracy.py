# -*- coding: utf-8 -*-
"""Triage accuracy vs lab ground truth (v5.4.0): Lightning vs the rule analyst vs the ML (L2).

    python scripts/triage_accuracy.py --flows <dir of <run>__<scenario>.pkl> [--llm]

Ground truth is known because we chose each scenario's attack. For every DEV (runs 2+3) and
HELD-OUT (run4) scenario:
* rules   - the L3 rule analyst on the scenario's aggregate;
* llm     - the L3 analyst through Nemotron (only with --llm and NVIDIA_API_KEY; one call each);
* ml      - the majority L2 label over the scenario's scored flows (cached lab-analysis scores).
Metrics, reported separately for DEV and HELD-OUT (never averaged):
* attack type correct - the verdict names the scenario's attack (keyword check, below);
* family correct      - its playbook family equals the scenario's expected family;
* false alarm rate    - share of benign scenarios (benign, flash crowd) given an attack verdict.
"""
from __future__ import annotations

import argparse
import json
import pickle
import re
import sys
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
OUT = REPO / "docs" / "eval" / "triage" / "results.json"

# what a correct attack-type name must contain (case-insensitive)
ATTACK_RE = {
    "syn_flood": r"\bsyn\b", "udp_flood": r"\budp\b", "ntp_reflection_sim": r"ntp|reflect", "dns_reflection_sim": r"\bdns\b",
    "icmp_flood": r"icmp", "tcp_ack_flood": r"\back\b", "tcp_rst_flood": r"\brst\b|reset", "land_attack": r"\bland\b",
    "http_low_and_slow": r"slow", "novel_ood_mix": r"multi|unclassified|zero[- ]?day|novel|mixed|ood",
}
BENIGN = {"benign_baseline", "flash_crowd"}


def is_benign_verdict(text: str) -> bool:
    return bool(re.search(r"benign|flash crowd|no attack|insufficient", text or "", re.I))


def score(rows):
    att = [r for r in rows if r["scenario"] not in BENIGN]
    ben = [r for r in rows if r["scenario"] in BENIGN]
    out = {}
    for who in ("rules", "llm", "ml"):
        a = [r for r in att if r.get(who) is not None]
        b = [r for r in ben if r.get(who) is not None]
        if not a and not b:
            continue
        out[who] = {
            "n_attacks": len(a), "n_benign": len(b),
            "attack_type_correct": round(sum(r[f"{who}_type_ok"] for r in a) / len(a), 3) if a else None,
            "family_correct": round(sum(r[f"{who}_family_ok"] for r in a) / len(a), 3) if a else None,
            "false_alarm_rate": round(sum(not is_benign_verdict(r[who]) for r in b) / len(b), 3) if b else None,
        }
    return out


def main() -> None:  # pragma: no cover - needs the lab flows / models / optional key
    from lab.library import load_scenarios
    from src.agent.schemas import IncidentAggregate
    from src.agent.threat_analyst import ThreatAnalyst, rule_based_analysis
    from src.eval.lab_analysis import build_aggregate, model_fingerprint
    from src.ir.playbooks import family_from_text

    ap = argparse.ArgumentParser()
    ap.add_argument("--flows", required=True)
    ap.add_argument("--llm", action="store_true")
    ap.add_argument("--keep-llm", action="store_true", help="reuse the LLM verdicts already in results.json (no new calls)")
    a = ap.parse_args()
    prev = {}
    if a.keep_llm and OUT.is_file():
        for st in json.loads(OUT.read_text()).get("sets", {}).values():
            for r0 in st["rows"]:
                if r0.get("llm"):
                    prev[(r0["run"], r0["scenario"])] = (r0["llm"], r0.get("llm_source"))
    from src.eval.lab_analysis import L2_MODE
    from src.models.ensemble import get_default_ensemble

    ens = get_default_ensemble()
    scs = load_scenarios()
    fp = model_fingerprint()
    llm = ThreatAnalyst() if a.llm else None
    result = {"model_fingerprint": fp, "sets": {}}
    for label, runs in (("DEV (runs 2+3)", ("run2", "run3")), ("HELD-OUT (run4)", ("run4",))):
        rows = []
        for run in runs:
            manifest = json.loads((REPO / "data" / "lab_runs" / run / "manifest.json").read_text())
            for r in manifest["runs"]:
                sid = r["scenario"]
                pk = Path(a.flows) / f"{run}__{sid}.pkl"
                if not pk.is_file():
                    continue
                flows = [f for f in pickle.loads(pk.read_bytes()) if f["dst"] == "10.99.0.10"]
                if not flows:
                    continue
                t0, t1 = min(f["start"] for f in flows), max(f["end"] for f in flows)
                agg = IncidentAggregate.model_validate(build_aggregate(sid, flows, t0, max(1.0, t1 - t0)))
                row = {"scenario": sid, "run": run, "expected_family": scs[sid].expected.family}
                row["rules"] = rule_based_analysis(agg).attack_type
                cache = REPO / "data" / "lab_runs" / run / "scores" / fp / f"{sid}.json"
                if cache.is_file():
                    labels = Counter(s["label"] for s in json.loads(cache.read_text()) if s["label"] != "unscored")
                else:  # score up to 300 evenly spaced flows directly (same mode as /score/flow)
                    step = max(1, len(flows) // 300)
                    labels = Counter(ens.score_flow(f["features"], mode=L2_MODE, feature_completeness=None)[0]
                                     for f in flows[::step][:300])
                row["ml"] = labels.most_common(1)[0][0] if labels else None
                if (run, sid) in prev:
                    row["llm"], row["llm_source"] = prev[(run, sid)]
                elif llm is not None:
                    res = llm.analyze(agg)
                    row["llm"] = res.analysis.attack_type
                    row["llm_source"] = res.source
                for who in ("rules", "llm", "ml"):
                    v = row.get(who)
                    if v is None:
                        continue
                    row[f"{who}_type_ok"] = bool(sid in ATTACK_RE and re.search(ATTACK_RE[sid], v, re.I))
                    row[f"{who}_family_ok"] = family_from_text(v) == row["expected_family"]
                rows.append(row)
                print(label, sid, {k: row.get(k) for k in ("rules", "llm", "ml")}, flush=True)
        result["sets"][label] = {"rows": rows, "metrics": score(rows)}
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(result, indent=2), encoding="utf-8")
    for k, v in result["sets"].items():
        print(k, json.dumps(v["metrics"]))


if __name__ == "__main__":
    main()
