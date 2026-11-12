# -*- coding: utf-8 -*-
"""
Detection-time report from REAL data (v5.0.1).

    python scripts/detection_latency.py data/lab_runs/run2 [--per-scenario 200]

1. Processing latency: micro-benchmarks each stage on real lab flows (deterministic sample,
   >= 1,000 flows) after a warm-up, using time.perf_counter_ns:
     L1  = threshold detector + signature filter + low-and-slow detector (as /score/flow calls them)
     L2  = calibrated RF + XGBoost ensemble (EnsembleClassifier.score_flow)
     OOD = supervised OOD detector (assess_features)
     L3  = rule-based analyst on a per-incident aggregate (once per incident, not per flow)
   End-to-end per flow = L1 + L2 + OOD for that flow. Reports p50/p95/p99 in milliseconds.
2. MTTD per scenario and layer from the actual lab run:
     L1/L2/OOD: first flagged flow, from the per-flow scores cached by src/eval/lab_analysis.py
     (data/lab_runs/<run>/scores/). L2/OOD were scored on every k-th flow, so they are upper bounds.
     L3: the run's victim-directed flows are replayed into growing windows (1 s steps) until the
     rule analyst names an attack.
   A layer that never fired is reported as "not detected"; no number is filled in.
Writes docs/eval/latency/results.json and the generated tables in docs/DETECTION_LATENCY.md.
"""
from __future__ import annotations

import json
import math
import os
import platform
import statistics
import sys
import time
import warnings
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))
OUT_JSON = REPO / "docs" / "eval" / "latency" / "results.json"
DOC = REPO / "docs" / "DETECTION_LATENCY.md"
LAYERS = ("L1", "L2", "OOD")


# ----------------------------------------------------------------------------- statistics
def percentiles(samples_ns: Sequence[int]) -> Dict[str, float]:
    """p50/p95/p99/mean/max in milliseconds (nearest-rank percentiles)."""
    if not samples_ns:
        return {"n": 0}
    s = sorted(samples_ns)
    n = len(s)

    def rank(p: float) -> float:
        return s[min(n - 1, max(0, math.ceil(p / 100.0 * n) - 1))] / 1e6  # nearest-rank

    return {"n": n, "p50_ms": round(rank(50), 4), "p95_ms": round(rank(95), 4), "p99_ms": round(rank(99), 4),
            "mean_ms": round(statistics.fmean(s) / 1e6, 4), "max_ms": round(s[-1] / 1e6, 4)}


def bench(stages: Dict[str, Callable[[Any], Any]], items: Sequence[Any], warmup: int = 50,
          clock: Callable[[], int] = time.perf_counter_ns) -> Dict[str, Dict[str, float]]:
    """Time every stage on every item (stages run in order per item). Adds an end_to_end row."""
    for it in list(items)[:warmup]:
        for fn in stages.values():
            fn(it)
    per: Dict[str, List[int]] = {k: [] for k in stages}
    e2e: List[int] = []
    for it in items:
        total = 0
        for name, fn in stages.items():
            t0 = clock()
            fn(it)
            dt = clock() - t0
            per[name].append(dt)
            total += dt
        e2e.append(total)
    out = {k: percentiles(v) for k, v in per.items()}
    out["end_to_end_per_flow"] = percentiles(e2e)
    return out


# ----------------------------------------------------------------------------- MTTD
def first_alerts(flows_sorted: List[dict], scores: List[dict], t0: float) -> Dict[str, Optional[float]]:
    """Seconds from scenario start to the first flow each layer flagged (None = not detected).
    `scores` are aligned with `flows_sorted` (sorted by flow end), as cached by lab_analysis."""
    first: Dict[str, Optional[float]] = {k: None for k in LAYERS}
    for f, s in zip(flows_sorted, scores):
        for layer in LAYERS:
            if first[layer] is None and s.get(layer):
                first[layer] = round(f["end"] - t0, 3)
    return first


def l3_first_alert(flows: List[dict], t0: float, t_end: float, target: Optional[str],
                   step_s: float = 1.0) -> Dict[str, Any]:
    """Grow the incident window from the scenario start in `step_s` steps; return the first time the
    rule analyst names an attack (None = not detected within the run)."""
    from src.agent.schemas import IncidentAggregate
    from src.agent.threat_analyst import rule_based_analysis
    from src.eval.lab_analysis import build_aggregate

    victim = [f for f in flows if (target is None or f["dst"] == target)]
    victim.sort(key=lambda f: f["end"])
    t, i, seen = t0 + step_s, 0, []
    while t <= t_end + step_s:
        while i < len(victim) and victim[i]["end"] <= t:
            seen.append(victim[i])
            i += 1
        if seen:
            agg = build_aggregate("mttd", seen, t0, t - t0)
            try:
                a = rule_based_analysis(IncidentAggregate.model_validate(agg))
            except Exception:
                a = None
            if a is not None and not a.attack_type.startswith("Benign"):
                return {"t_s": round(t - t0, 2), "attack_type": a.attack_type}
        t += step_s
    return {"t_s": None, "attack_type": None}


# ----------------------------------------------------------------------------- hardware
def hardware() -> Dict[str, Any]:
    info: Dict[str, Any] = {"os": f"{platform.system()} {platform.release()}", "machine": platform.machine(),
                            "processor": platform.processor() or "unknown", "logical_cpus": os.cpu_count(),
                            "python": platform.python_version()}
    if platform.system() == "Windows":  # total RAM without extra dependencies
        try:
            import ctypes

            class MS(ctypes.Structure):
                _fields_ = [("dwLength", ctypes.c_ulong), ("dwMemoryLoad", ctypes.c_ulong),
                            ("ullTotalPhys", ctypes.c_ulonglong), ("ullAvailPhys", ctypes.c_ulonglong),
                            ("ullTotalPageFile", ctypes.c_ulonglong), ("ullAvailPageFile", ctypes.c_ulonglong),
                            ("ullTotalVirtual", ctypes.c_ulonglong), ("ullAvailVirtual", ctypes.c_ulonglong),
                            ("ullAvailExtendedVirtual", ctypes.c_ulonglong)]
            m = MS()
            m.dwLength = ctypes.sizeof(MS)
            ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(m))
            info["ram_gb"] = round(m.ullTotalPhys / 2**30, 1)
        except Exception:
            pass
    try:
        import subprocess
        gpu = subprocess.run(["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"], capture_output=True,
                             text=True, timeout=10).stdout.strip()
        if gpu:
            info["gpu"] = gpu.splitlines()[0]
    except Exception:
        pass
    return info


# ----------------------------------------------------------------------------- real run (CLI)
def _real_stages():  # pragma: no cover - needs model artifacts
    from src.features.l7_lowslow import LowSlowDetector
    from src.features.signature_filter import SignatureFilter
    from src.features.threshold_detector import ThresholdDetector
    from src.models.ensemble import get_default_ensemble
    from src.models.ood_detector import OODDetector

    from src.eval.lab_analysis import L2_MODE

    thr, sig, lows, ens = ThresholdDetector(window_seconds=10.0), SignatureFilter(), LowSlowDetector(), get_default_ensemble()
    p = REPO / "models" / "ood_model.joblib"
    ood = OODDetector.load(str(p)) if p.is_file() else OODDetector()

    def l1(f):
        ft = f["features"]
        thr.record_flow(ft, src_ip=f["src"], dst_ip=f["dst"], timestamp=f["end"])
        sig.inspect_flow_features(ft, src_ip=f["src"], dst_ip=f["dst"])
        lows.observe({"src_ip": f["src"], "src_port": f.get("sport"), "dst_ip": f["dst"],
                      "dst_port": f.get("dport") or 80,
                      "duration_sec": float(ft.get("Flow Duration", 0.0)) / 1e6,
                      "fwd_bytes": float(ft.get("Fwd Packets Length Total", 0.0) or 0.0), "header_complete": True,
                      "bwd_packets": ft.get("Total Backward Packets")},
                     now=f["end"])

    def l2(f):
        ens.score_flow(f["features"], mode=L2_MODE, feature_completeness=None)

    def oodf(f):
        if ood.is_model_backed:
            ood.assess_features(f["features"])

    return {"L1": l1, "L2": l2, "OOD": oodf}, ood.is_model_backed


def main() -> None:  # pragma: no cover - CLI
    import argparse

    from src.agent.schemas import IncidentAggregate
    from src.agent.threat_analyst import rule_based_analysis
    from src.eval.lab_analysis import build_aggregate, flows_from_pcap

    ap = argparse.ArgumentParser(description="Detection latency + MTTD from a real lab run")
    ap.add_argument("run_dirs", nargs="+")
    ap.add_argument("--per-scenario", type=int, default=200)
    args = ap.parse_args()
    from src.eval.lab_analysis import model_fingerprint

    fp = model_fingerprint()
    pairs = []
    for rd in args.run_dirs:
        run_dir = Path(rd)
        for run in json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))["runs"]:
            pairs = [(d, r) for d, r in pairs if r["scenario"] != run["scenario"]] + [(run_dir, run)]  # later run wins

    sample, aggregates, mttd = [], [], []
    for run_dir, run in pairs:
        flows = flows_from_pcap(run_dir / run["pcap"])
        flows_sorted = sorted(flows, key=lambda f: f["end"])
        step = max(1, len(flows_sorted) // args.per_scenario)
        sample += flows_sorted[::step][: args.per_scenario]
        target = (run.get("generator") or {}).get("target")
        aggregates.append(build_aggregate(run["scenario"], [f for f in flows if f["dst"] == target] or flows,
                                          run["started_at"], max(1.0, run["ended_at"] - run["started_at"])))
        cache = run_dir / "scores" / fp / f"{run['scenario']}.json"
        scores = json.loads(cache.read_text()) if cache.is_file() else []
        firsts = first_alerts(flows_sorted, scores, run["started_at"]) if len(scores) == len(flows_sorted) else \
            {k: "no cached scores" for k in LAYERS}
        ml_every = None
        if scores:
            idx = [i for i, s in enumerate(scores) if s.get("label") != "unscored"]
            ml_every = (idx[1] - idx[0]) if len(idx) > 1 else 1
        l3 = l3_first_alert(flows, run["started_at"], run["ended_at"], target)
        mttd.append({"scenario": run["scenario"], "run": run_dir.name, "flows": len(flows), "ml_scored_every_k_flows": ml_every,
                     **{f"{k}_first_alert_s": v for k, v in firsts.items()},
                     "L3_first_alert_s": l3["t_s"], "L3_attack_type": l3["attack_type"],
                     "scenario_duration_s": round(run["ended_at"] - run["started_at"], 1)})
        print(mttd[-1], flush=True)

    stages, ood_model = _real_stages()
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        lat = bench(stages, sample, warmup=50)
        l3_lat = bench({"L3_rule": lambda a: rule_based_analysis(IncidentAggregate.model_validate(a))},
                       [a for a in aggregates for _ in range(150)], warmup=20)["L3_rule"]
    warn_kinds = sorted({f"{w.category.__name__}: {str(w.message)[:160]}" for w in caught})
    report = {"run": ",".join(sorted({d.name for d, _ in pairs})), "model_fingerprint": fp, "hardware": hardware(), "flows_benchmarked": len(sample),
              "ood_model_backed": ood_model, "processing_latency": lat, "l3_rule_per_incident": l3_lat,
              "warnings_during_benchmark": warn_kinds, "mttd": mttd}
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if DOC.is_file():
        doc = DOC.read_text(encoding="utf-8")
        a, b = "<!-- LATENCY:START -->", "<!-- LATENCY:END -->"
        if a in doc and b in doc:
            DOC.write_text(doc.split(a)[0] + a + "\n" + render_markdown(report) + b + doc.split(b)[1], encoding="utf-8")
    print("wrote", OUT_JSON)


def _fmt(v) -> str:
    if v is None:
        return "not detected"
    if isinstance(v, str):
        return v
    return f"{v:.1f}"


def render_markdown(r: dict) -> str:
    h = r["hardware"]
    lines = [f"Measured on **{h.get('processor')}** ({h.get('logical_cpus')} logical CPUs"
             + (f", {h['ram_gb']} GB RAM" if h.get("ram_gb") else "") + (f", GPU {h['gpu']}" if h.get("gpu") else "")
             + f"), {h.get('os')}, Python {h.get('python')}. {r['flows_benchmarked']} real flows from lab run "
             f"`{r['run']}` (deterministic sample across all scenarios), 50 warm-up flows excluded.", "",
             "| Stage | Unit | n | p50 (ms) | p95 (ms) | p99 (ms) | mean (ms) |", "|---|---|---:|---:|---:|---:|---:|"]
    names = {"L1": "L1 rules (threshold + signature + low-and-slow)", "L2": "L2 ML ensemble (RF + XGBoost)",
             "OOD": "OOD detector", "end_to_end_per_flow": "**End-to-end per flow (L1+L2+OOD)**"}
    for k in ("L1", "L2", "OOD", "end_to_end_per_flow"):
        s = r["processing_latency"][k]
        lines.append(f"| {names[k]} | per flow | {s['n']} | {s['p50_ms']} | {s['p95_ms']} | {s['p99_ms']} | {s['mean_ms']} |")
    s = r["l3_rule_per_incident"]
    lines.append(f"| L3 rule analyst | per incident | {s['n']} | {s['p50_ms']} | {s['p95_ms']} | {s['p99_ms']} | {s['mean_ms']} |")
    lines += ["", "**MTTD per scenario** (seconds from scenario start to the first alert at that layer; "
              "\"not detected\" = that layer never fired during the run):", "",
              "| Scenario | L1 | L2 (ML)* | OOD* | L3 (rules) | L3 verdict | Duration (s) |",
              "|---|---:|---:|---:|---:|---|---:|"]
    for m in r["mttd"]:
        lines.append(f"| `{m['scenario']}` | {_fmt(m['L1_first_alert_s'])} | {_fmt(m['L2_first_alert_s'])} | "
                     f"{_fmt(m['OOD_first_alert_s'])} | {_fmt(m['L3_first_alert_s'])} | {m['L3_attack_type'] or '—'} | "
                     f"{m['scenario_duration_s']} |")
    lines += ["", "\\* L2/OOD were scored on every k-th flow in the lab analysis (k shown in `results.json`), so "
              "their first-alert times are upper bounds."]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":  # pragma: no cover
    main()
