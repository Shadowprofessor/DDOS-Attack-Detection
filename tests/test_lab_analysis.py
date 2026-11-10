# -*- coding: utf-8 -*-
"""v4.6.1 lab analysis logic (fake scorer; no pcaps or models needed)."""
from lab.library import load_scenarios
from src.eval.lab_analysis import analyse_run, build_aggregate, coverage_markdown, navigator_layer

T0 = 1000.0


def syn_flows(n=200, start=T0 + 1):
    return [{"src": f"10.99.0.{100 + i % 50}", "dst": "10.99.0.10", "proto": 6, "dport": 443, "packets": 1,
             "bytes": 0.0, "syn": 1.0, "start": start + i * 0.01, "end": start + i * 0.01,
             "features": {"Protocol": 6, "SYN Flag Count": 1}} for i in range(n)]


def web_flows(n=50):
    return [{"src": f"10.99.0.{150 + i % 100}", "dst": "10.99.0.10", "proto": 6, "dport": 80, "packets": 10,
             "bytes": 6000.0, "syn": 1.0, "start": T0 + i, "end": T0 + i + 0.5,
             "features": {"Protocol": 6}} for i in range(n)]


def flags_attacks(after):
    def scorer(f, src, dst, ts):
        hit = f.get("SYN Flag Count") == 1 and ts >= after
        return {"L1": hit, "L2": hit, "OOD": False, "label": "Syn" if hit else "Benign"}
    return scorer


def run(sid, end=T0 + 60):
    return {"scenario": sid, "started_at": T0, "ended_at": end, "generator": {"packets": 1000, "stopped_by": "completed"}}


def test_syn_flood_detected_with_mttd_and_family():
    sc = load_scenarios()["syn_flood"]
    r = analyse_run(run("syn_flood"), sc.expected.model_dump(), syn_flows(), flags_attacks(T0 + 2))
    assert r["outcome"] == "detected" and r["l3_family"] == "syn_flood"
    assert r["observed_layers"][:2] == ["L1", "L2"] and "L3" in r["observed_layers"]
    assert 2.0 <= r["mttd_s"] < 3.0 and r["mttd_with_idle_export_s"] == r["mttd_s"] + 60


def test_flash_crowd_clean_when_nothing_flags():
    sc = load_scenarios()["flash_crowd"]
    r = analyse_run(run("flash_crowd"), sc.expected.model_dump(), web_flows(),
                    lambda f, s, d, t: {"L1": False, "L2": False, "OOD": False, "label": "Benign"})
    assert r["outcome"] == "clean" and r["mttd_s"] is None and r["flagged_rate"] == 0.0


def test_benign_flagged_is_a_false_positive():
    sc = load_scenarios()["benign_baseline"]
    r = analyse_run(run("benign_baseline"), sc.expected.model_dump(), web_flows(5),
                    lambda f, s, d, t: {"L1": False, "L2": True, "OOD": False, "label": "UDP"})
    assert r["outcome"] == "false_positive" and r["flagged_rate"] == 1.0


def test_missed_and_partial():
    sc = load_scenarios()["syn_flood"]
    miss = analyse_run(run("syn_flood"), sc.expected.model_dump(), [], flags_attacks(0))
    assert miss["outcome"] == "missed" and miss["flows"] == 0
    dns = load_scenarios()["dns_reflection_sim"]
    part = analyse_run(run("dns_reflection_sim"), dns.expected.model_dump(), syn_flows(50), flags_attacks(0))
    assert part["outcome"] == "partial" and part["family_match"] is False


def test_aggregate_shape():
    a = build_aggregate("x", syn_flows(100), T0, 10)
    assert a["unique_src_ips"] == 50 and a["protocol_mix"] == {"tcp": 1.0} and a["tcp_flag_ratios"]["syn"] == 1.0
    assert a["pps"] == 10.0 and len(a["top_src_ips"]) == 10


def test_matrix_and_navigator_layer():
    scs = load_scenarios()
    rs = [analyse_run(run("syn_flood"), scs["syn_flood"].expected.model_dump(), syn_flows(), flags_attacks(0)),
          analyse_run(run("flash_crowd"), scs["flash_crowd"].expected.model_dump(), web_flows(),
                      lambda f, s, d, t: {"L1": False, "L2": False, "OOD": False, "label": "Benign"})]
    md = coverage_markdown(rs, {"probe": "192.0.2.1", "drops_before": 0, "drops_after": 3, "uplink": "eth0",
                                "packets_seen_on_uplink": 0, "contained": True})
    assert "`syn_flood` | **detected**" in md and "`flash_crowd` | **clean**" in md and "**contained**" in md
    layer = navigator_layer(rs, scs)
    ids = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    assert ids == {"T1499.001": 100, "T1498.001": 100}
