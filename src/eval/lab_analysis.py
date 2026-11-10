# -*- coding: utf-8 -*-
"""
Purple-team lab analysis (v4.6.1): run captured lab pcaps through the REAL detection stack.

For each scenario run recorded by `lab/traffic/orchestrate.py` (data/lab_runs/<run>/manifest.json):
  pcap -> FlowExtractor (CICFlowMeter features) -> per flow:
    L1  = threshold detector violation OR signature-filter match
    L2  = ensemble verdict != Benign
    OOD = supervised OOD detector suspects the flow
  L3  = rule-based analyst on an aggregate built from the scenario's flows (no LLM).
Outputs: per-scenario layer hits vs expectations, MTTD, benign false positives, a coverage matrix
and an ATT&CK Navigator layer.

MTTD here = (last-packet time of the first flagged flow) - (scenario start). It assumes a flow is
exported the moment its last packet is seen. A live CICFlowMeter-style exporter adds its idle /
active timeout on top (60 s / 120 s by default), and this is reported next to the number.
"""
from __future__ import annotations

import json
import math
from collections import Counter
from pathlib import Path
from typing import Callable, Dict, List, Optional

REPO = Path(__file__).resolve().parent.parent.parent
OUT_DIR = REPO / "docs" / "purple_team"
IDLE_TIMEOUT_S = 60.0

# per-flow scorer: features, src, dst, ts -> {"L1": bool, "L2": bool, "OOD": bool, "label": str}
FlowScorer = Callable[[Dict, str, str, float], Dict]


def _entropy(counts: Counter) -> float:
    n = sum(counts.values())
    return -sum((c / n) * math.log2(c / n) for c in counts.values() if c) if n else 0.0


def build_aggregate(sid: str, flows: List[dict], t0: float, window_s: float) -> dict:
    """IncidentAggregate (dict) from extracted flow records (src, dst, proto, dport, pkts, bytes, flags)."""
    if not flows:
        return {"incident_id": f"lab-{sid}", "window_start": t0, "window_seconds": max(1, int(window_s))}
    pk = sum(f["packets"] for f in flows)
    by_src = Counter()
    for f in flows:
        by_src[f["src"]] += f["packets"]
    proto = Counter()
    for f in flows:
        proto[{6: "tcp", 17: "udp", 1: "icmp"}.get(f["proto"], "other")] += f["packets"]
    ports = Counter(str(f["dport"]) for f in flows if f["dport"])
    syn = sum(f["syn"] for f in flows)
    tcp_pk = proto.get("tcp", 0) or 1
    sizes = sorted(f["bytes"] / max(1, f["packets"]) for f in flows)
    w = max(1.0, window_s)
    http = [f for f in flows if f["dport"] in (80, 443)]
    slow = [f for f in http if (f["end"] - f["start"]) >= 10.0
            and f.get("fwd_bytes", f["bytes"]) / max(1e-6, f["end"] - f["start"]) <= 50.0]  # LowSlowDetector rule
    l7 = {"http_rps": round(len(http) / w, 3), "slow_connections": len(slow)} if http else None
    return {
        "incident_id": f"lab-{sid}", "window_start": t0, "window_seconds": int(min(3600, max(1, w))), "l7": l7,
        "pps": pk / w, "bps": sum(f["bytes"] for f in flows) * 8 / w, "flow_count": len(flows),
        "unique_src_ips": len(by_src), "src_ip_entropy": round(_entropy(by_src), 3),
        "top_src_ips": [{"key": k, "share": round(v / pk, 4)} for k, v in by_src.most_common(10)],
        "dst_ips": sorted({f["dst"] for f in flows})[:10],
        "dst_ports": [{"key": k, "share": round(v / len(flows), 4)} for k, v in ports.most_common(10)],
        "protocol_mix": {k: round(v / pk, 4) for k, v in proto.items()},
        "tcp_flag_ratios": {"syn": round(min(1.0, syn / tcp_pk), 4)},
        "packet_size_p50": sizes[len(sizes) // 2], "packet_size_p95": sizes[int(len(sizes) * 0.95) - 1 if len(sizes) > 1 else 0],
    }


ML_SAMPLE = 1500  # ML/OOD scored on at most this many flows per scenario (evenly spaced in time)


def analyse_run(run: dict, expected: dict, flows: List[dict], scorer: FlowScorer, ml_sample: int = ML_SAMPLE) -> dict:
    """flows: dicts with src,dst,proto,dport,packets,bytes,syn,start,end,features.

    L1 runs on every flow (cheap, rate-based). L2/OOD run on every k-th flow in time order when
    there are more than `ml_sample` flows. The sampling is recorded in the result."""
    t0 = run["started_at"]
    hits = {"L1": 0, "L2": 0, "OOD": 0}
    first: Dict[str, Optional[float]] = {"L1": None, "L2": None, "OOD": None}
    labels = Counter()
    flagged = 0
    every = max(1, math.ceil(len(flows) / ml_sample)) if ml_sample else 1
    ml_scored = 0
    for i, f in enumerate(sorted(flows, key=lambda x: x["end"])):
        take_ml = i % every == 0
        ml_scored += take_ml
        r = scorer(f["features"], f["src"], f["dst"], f["end"], **({} if take_ml else {"ml": False}))
        labels[r.get("label", "?")] += 1
        any_hit = False
        for layer in ("L1", "L2", "OOD"):
            if r.get(layer):
                hits[layer] += 1
                any_hit = True
                if first[layer] is None:
                    first[layer] = f["end"]
        flagged += any_hit
    from src.agent.schemas import IncidentAggregate
    from src.agent.threat_analyst import rule_based_analysis
    from src.ir.playbooks import family_from_text

    target = (run.get("generator") or {}).get("target")
    to_victim = [f for f in flows if f["dst"] == target] if target else flows  # incidents are per victim
    agg = build_aggregate(run["scenario"], to_victim, t0, max(1.0, run["ended_at"] - t0))
    try:
        l3 = rule_based_analysis(IncidentAggregate.model_validate(agg))
        l3_attack, l3_family = l3.attack_type, family_from_text(l3.attack_type)
    except Exception as e:  # malformed aggregate (e.g. no flows)
        l3_attack, l3_family = f"error: {type(e).__name__}", "other"
    l3_hit = not l3_attack.startswith("Benign") and not l3_attack.startswith("error")
    detected_at = [t for t in first.values() if t is not None]
    incident = l3_hit or bool(detected_at)
    n = len(flows)
    observed_layers = [k for k in ("L1", "L2", "OOD") if hits[k]] + (["L3"] if l3_hit else [])
    exp_layers = expected.get("layers") or []
    res = {
        "scenario": run["scenario"], "flows": n, "flagged_flows": flagged, "ml_scored_flows": ml_scored,
        "ml_sample_every": every,
        "flagged_rate": round(flagged / n, 4) if n else None,
        "layer_hits": hits, "observed_layers": observed_layers,
        "expected_incident": expected.get("incident"), "observed_incident": incident,
        "expected_family": expected.get("family"), "l3_attack_type": l3_attack, "l3_family": l3_family,
        "family_match": (l3_family == expected.get("family")) if expected.get("incident") else None,
        "expected_layers": exp_layers, "missing_layers": [x for x in exp_layers if x not in observed_layers],
        "mttd_s": round(min(detected_at) - t0, 2) if detected_at else None,
        "mttd_with_idle_export_s": round(min(detected_at) - t0 + IDLE_TIMEOUT_S, 2) if detected_at else None,
        "mttd_budget_s": expected.get("max_mttd_s"),
        "top_labels": dict(labels.most_common(5)),
        "aggregate_flows_to_victim": len(to_victim), "l7_slow_connections": (agg.get("l7") or {}).get("slow_connections"),
        "packets_sent": (run.get("generator") or {}).get("packets"),
        "stopped_by": (run.get("generator") or {}).get("stopped_by"),
    }
    if expected.get("incident"):
        res["outcome"] = "detected" if incident and res["family_match"] else ("partial" if incident else "missed")
    else:
        res["outcome"] = "false_positive" if incident else "clean"
    return res


def flows_from_pcap(pcap: Path) -> List[dict]:  # pragma: no cover - needs scapy + a pcap
    from src.features.flow_extractor import FlowExtractor

    out = []
    for fl in FlowExtractor().process_pcap(str(pcap)):
        k = fl.flow_key
        src = fl.fwd_src_ip
        dst = k[1] if k[0] == src else k[0]
        payload = fl.to_flow_features()
        feats = payload.get("features", payload)
        out.append({"src": src, "dst": dst, "proto": fl.protocol, "dport": int(feats.get("Destination Port", 0) or 0),
                    "packets": int(fl.fwd_packet_count + fl.bwd_packet_count),
                    "bytes": float(feats.get("Fwd Packets Length Total", 0) or 0) + float(feats.get("Bwd Packets Length Total", 0) or 0),
                    "fwd_bytes": float(feats.get("Fwd Packets Length Total", 0) or 0),
                    "syn": float(feats.get("SYN Flag Count", 0) or 0), "start": fl.start_time,
                    "end": fl.last_active_time, "features": feats})
    return out


def real_scorer() -> FlowScorer:  # pragma: no cover - needs model artifacts
    from src.features.signature_filter import SignatureFilter
    from src.features.threshold_detector import ThresholdDetector
    from src.models.ensemble import get_default_ensemble
    from src.models.ood_detector import OODDetector

    from src.features.l7_lowslow import LowSlowDetector

    thr, sig, ens = ThresholdDetector(window_seconds=10.0), SignatureFilter(), get_default_ensemble()
    lows = LowSlowDetector()
    p = REPO / "models" / "ood_model.joblib"
    ood = OODDetector.load(str(p)) if p.is_file() else OODDetector()

    def score(feats, src, dst, ts, ml=True):
        t = thr.record_flow(feats, src_ip=src, dst_ip=dst, timestamp=ts)
        s = sig.inspect_flow_features(feats, src_ip=src, dst_ip=dst)
        ls = lows.observe({"src_ip": src, "src_port": feats.get("Source Port"), "dst_ip": dst,  # as /score/flow does
                           "dst_port": feats.get("Destination Port") or 80,
                           "duration_sec": float(feats.get("Flow Duration", 0.0)) / 1e6,
                           "fwd_bytes": float(feats.get("Fwd Packets Length Total", 0.0) or 0.0),
                           "header_complete": True}, now=ts)
        l1 = bool(t.is_violation or s.matched or ls)
        if not ml:
            return {"L1": l1, "L2": False, "OOD": False, "label": "unscored"}
        label, conf, _ = ens.score_flow(feats, feature_completeness=None)
        o = ood.assess_features(feats) if ood.is_model_backed else ood.assess(float(conf))
        return {"L1": l1, "L2": label != "Benign",
                "OOD": bool(o.get("ood_suspected")), "label": label}

    return score


def coverage_markdown(results: List[dict], containment: Optional[dict]) -> str:
    rows = ["| Scenario | Outcome | Expected | Observed layers | L3 family | Flagged flows | MTTD (s) | MTTD + 60 s export |",
            "|---|---|---|---|---|---:|---:|---:|"]
    for r in results:
        exp = (r["expected_family"] or "no incident") + (f" via {'+'.join(r['expected_layers'])}" if r["expected_layers"] else "")
        rate = "—" if r["flagged_rate"] is None else f"{r['flagged_flows']}/{r['flows']} ({r['flagged_rate']:.0%})"
        mttd = "—" if r["mttd_s"] is None else f"{r['mttd_s']:.1f}"
        mttd2 = "—" if r["mttd_with_idle_export_s"] is None else f"{r['mttd_with_idle_export_s']:.1f}"
        rows.append(f"| `{r['scenario']}` | **{r['outcome']}** | {exp} | {', '.join(r['observed_layers']) or 'none'} | "
                    f"{r['l3_family']} | {rate} | {mttd} | {mttd2} |")
    if containment:
        rows += ["", f"Containment probe to {containment['probe']} (TEST-NET-1) with a NAT path deliberately open: "
                 f"nftables drops {containment['drops_before']} → {containment['drops_after']}, packets seen on "
                 f"`{containment['uplink']}`: {containment['packets_seen_on_uplink']} → **"
                 f"{containment.get('verdict') or ('contained' if containment['contained'] else 'NOT CONTAINED')}**."]
    return "\n".join(rows) + "\n"


def navigator_layer(results: List[dict], scenarios: Dict) -> dict:
    """ATT&CK Navigator layer: per technique, the best outcome across scenarios that exercise it."""
    score = {"detected": 100, "partial": 50, "missed": 0}
    best: Dict[str, tuple] = {}
    for r in results:
        sc = scenarios.get(r["scenario"])
        if not sc or not sc.attack:
            continue
        for t in sc.mitre:
            cur = best.get(t)
            s = score.get(r["outcome"], 0)
            note = f"{r['scenario']}: {r['outcome']} ({', '.join(r['observed_layers']) or 'none'})"
            best[t] = (max(s, cur[0]) if cur else s, ((cur[1] + "; ") if cur else "") + note)
    return {
        "name": "DDoS platform: lab-measured detection coverage", "versions": {"layer": "4.5", "navigator": "5.1.0"},
        "domain": "enterprise-attack", "description": "Generated by src/eval/lab_analysis.py from Mininet lab runs.",
        "techniques": [{"techniqueID": t, "score": s, "comment": c} for t, (s, c) in sorted(best.items())],
        "gradient": {"colors": ["#ff6666", "#ffe766", "#8ec843"], "minValue": 0, "maxValue": 100},
    }


def main() -> None:  # pragma: no cover - CLI
    import argparse

    from lab.library import load_scenarios

    ap = argparse.ArgumentParser(description="Analyse Mininet lab pcaps with the real detection stack")
    ap.add_argument("run_dir")
    args = ap.parse_args()
    run_dir = Path(args.run_dir)
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    scs = load_scenarios()
    scorer = real_scorer()
    results = []
    for run in manifest.get("runs", []):
        sc = scs[run["scenario"]]
        flows = flows_from_pcap(run_dir / run["pcap"])
        results.append(analyse_run(run, sc.expected.model_dump(), flows, scorer))
        print(results[-1]["scenario"], results[-1]["outcome"], results[-1]["observed_layers"], results[-1]["mttd_s"],
              f"flows={results[-1]['flows']} ml_scored={results[-1]['ml_scored_flows']}", flush=True)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    report = {"run": run_dir.name, "switch": manifest.get("switch"), "containment": manifest.get("containment"),
              "results": results}
    (OUT_DIR / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (OUT_DIR / "navigator_layer.json").write_text(json.dumps(navigator_layer(results, scs), indent=2), encoding="utf-8")
    (OUT_DIR / "coverage.md").write_text(coverage_markdown(results, manifest.get("containment")), encoding="utf-8")
    print("wrote", OUT_DIR)


if __name__ == "__main__":  # pragma: no cover
    main()
