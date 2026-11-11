# -*- coding: utf-8 -*-
"""v5.0.1 detection-latency benchmark: runs on a tiny synthetic set so CI stays fast."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "detection_latency", Path(__file__).resolve().parent.parent / "scripts" / "detection_latency.py")
dl = importlib.util.module_from_spec(spec)
spec.loader.exec_module(dl)

T0 = 1000.0


def syn_flows(n=300, start=T0 + 2):
    return [{"src": f"10.99.0.{100 + i % 50}", "dst": "10.99.0.10", "proto": 6, "dport": 443, "sport": 40000 + i,
             "packets": 1, "bytes": 0.0, "fwd_bytes": 0.0, "syn": 1.0, "start": start + i * 0.01,
             "end": start + i * 0.01, "features": {"Protocol": 6, "SYN Flag Count": 1}} for i in range(n)]


def test_percentiles_nearest_rank():
    p = dl.percentiles([i * 1_000_000 for i in range(1, 101)])  # 1..100 ms
    assert p["n"] == 100 and p["p50_ms"] == 50.0 and p["p95_ms"] == 95.0 and p["p99_ms"] == 99.0
    assert dl.percentiles([]) == {"n": 0}


def test_bench_runs_real_l1_on_synthetic_flows_and_sums_end_to_end():
    from src.features.signature_filter import SignatureFilter
    from src.features.threshold_detector import ThresholdDetector

    thr, sig = ThresholdDetector(window_seconds=10.0), SignatureFilter()
    stages = {
        "L1": lambda f: (thr.record_flow(f["features"], src_ip=f["src"], dst_ip=f["dst"], timestamp=f["end"]),
                         sig.inspect_flow_features(f["features"], src_ip=f["src"], dst_ip=f["dst"])),
        "stub_ml": lambda f: sum(range(50)),
    }
    out = dl.bench(stages, syn_flows(60), warmup=5)
    assert out["L1"]["n"] == 60 and out["end_to_end_per_flow"]["n"] == 60
    assert out["end_to_end_per_flow"]["mean_ms"] >= out["L1"]["mean_ms"]


def test_bench_with_fake_clock_is_exact():
    ticks = iter(range(0, 10**9, 1_000_000))  # every clock() call advances 1 ms
    out = dl.bench({"a": lambda x: None, "b": lambda x: None}, [1, 2, 3], warmup=0, clock=lambda: next(ticks))
    assert out["a"]["p50_ms"] == 1.0 and out["end_to_end_per_flow"]["p50_ms"] == 2.0


def test_first_alerts_per_layer_and_not_detected():
    flows = sorted(syn_flows(10), key=lambda f: f["end"])
    scores = [{"L1": i >= 3, "L2": False, "OOD": i == 7, "label": "x"} for i in range(10)]
    first = dl.first_alerts(flows, scores, T0)
    assert first["L1"] == round(flows[3]["end"] - T0, 3) and first["OOD"] == round(flows[7]["end"] - T0, 3)
    assert first["L2"] is None  # never fired -> reported as "not detected", no number filled


def test_l3_first_alert_window_bound_and_miss():
    hit = dl.l3_first_alert(syn_flows(300), T0, T0 + 10, "10.99.0.10")
    assert hit["t_s"] is not None and 2.0 <= hit["t_s"] <= 6.0 and "SYN" in hit["attack_type"].upper()
    web = [{**f, "proto": 6, "syn": 0.0, "dport": 80, "packets": 10, "bytes": 6000.0} for f in syn_flows(20)]
    assert dl.l3_first_alert(web, T0, T0 + 10, "10.99.0.10")["t_s"] is None


def test_markdown_says_not_detected():
    r = {"hardware": {"processor": "x", "logical_cpus": 4, "os": "y", "python": "3"}, "run": "t",
         "flows_benchmarked": 1000, "processing_latency": {k: dl.percentiles([1_000_000]) for k in
                                                          ("L1", "L2", "OOD", "end_to_end_per_flow")},
         "l3_rule_per_incident": dl.percentiles([2_000_000]),
         "mttd": [{"scenario": "syn_flood", "L1_first_alert_s": 1.0, "L2_first_alert_s": None,
                   "OOD_first_alert_s": 3.2, "L3_first_alert_s": 5.0, "L3_attack_type": "TCP SYN flood",
                   "scenario_duration_s": 60.0}]}
    md = dl.render_markdown(r)
    assert "| `syn_flood` | 1.0 | not detected | 3.2 | 5.0 |" in md
