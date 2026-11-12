# -*- coding: utf-8 -*-
"""v5.2.0 real-time MTTD join: manifest (ground truth) x bridge log (alert times)."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("live_mttd", Path(__file__).resolve().parent.parent / "scripts" / "live_mttd.py")
lm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lm)

V = "10.99.0.10"
MANIFEST = {"runs": [
    {"scenario": "benign_baseline", "started_at": 100.0, "ended_at": 160.0},
    {"scenario": "syn_flood", "started_at": 200.0, "ended_at": 260.0},
    {"scenario": "icmp_flood", "started_at": 300.0, "ended_at": 360.0},
    {"scenario": "flash_crowd", "started_at": 400.0, "ended_at": 460.0},
]}
LOG = [
    {"event": "windows_posted", "status": 200, "ack_at": 203.4, "last_window_end": 202.0, "skew_s": 0.9},
    {"event": "alert", "episode": {"id": "live-1", "dst": V, "window_start": 201.0, "opened_at": 203.3}},
    {"event": "incident_created", "status": 201, "episode_id": "live-1", "incident_id": "INC-1", "ack_at": 203.6},
    {"event": "incident_analyzed", "incident_id": "INC-1", "attack_type": "TCP SYN flood", "source": "rules"},
    {"event": "flow_scored", "dst": V, "is_attack": True, "flow_end": 215.0, "ack_at": 216.1, "label": "Syn", "basis": "ml"},
    {"event": "flow_scored", "dst": V, "is_attack": True, "flow_end": 205.0, "ack_at": 206.0, "label": "Distributed-SYN-Flood", "basis": "multi_layer"},
    {"event": "flow_scored", "dst": V, "is_attack": True, "flow_end": 120.0, "ack_at": 121.5, "label": "Unsupervised-Volumetric-Anomaly", "basis": "multi_layer"},
    {"event": "alert", "episode": {"id": "live-2", "dst": V, "window_start": 402.0, "opened_at": 404.0}},
    {"event": "alert", "episode": {"id": "live-9", "dst": "10.99.0.100", "window_start": 301.0, "opened_at": 302.0}},
]


def test_join_reports_detections_false_positives_and_not_detected():
    r = lm.analyse(MANIFEST, LOG, V, {"benign_baseline": False, "syn_flood": True, "icmp_flood": True, "flash_crowd": False},
                   offline={"syn_flood": {"L1_first_alert_s": 0.98, "run": "run2"}})
    by = {x["scenario"]: x for x in r["results"]}
    s = by["syn_flood"]
    assert (s["window_s"], s["website_s"], s["incident_s"], s["l2_s"]) == (2.0, 3.3, 3.6, 16.1)
    assert s["l3_verdict"] == "TCP SYN flood" and s["offline_l1_s"] == 0.98 and s["corroboration_s"] == 6.0
    assert by["benign_baseline"]["corroboration_s"] == 21.5 and by["benign_baseline"]["l2_s"] is None
    assert by["icmp_flood"]["alerted"] is False and by["icmp_flood"]["website_s"] is None  # other-host alert ignored
    assert by["flash_crowd"]["alerted"] is True and by["benign_baseline"]["alerted"] is False
    assert r["clock"]["min_wall_minus_packet_s"] == 0.9 and r["clock"]["post_lag_p50_s"] == 1.4
    md = lm.render(r, "live1")
    assert "| `icmp_flood` | yes | not detected | not detected |" in md
    assert "**false positive** 4.0" in md and "no alert (correct)" in md
    assert "| none (correct) | **false positive** 21.5 |" in md  # benign: corroboration FP, never called ML


def test_mttc_from_approval_to_traffic_below_threshold():
    manifest = {"runs": [{"scenario": "contain_syn_flood", "started_at": 1000.0, "ended_at": 1120.0}]}
    log = [{"event": "enforcement_queued", "action_id": "a1", "op": "apply", "target": "attacker", "approved_at": 1030.0},
           {"event": "enforcement_reported", "action_id": "a1", "state": "applied", "ts": 1031.5}]
    log += [{"event": "victim_window", "dst": V, "start": t - 1, "end": t, "pps": 1480.0 if t <= 1033 else 20.0}
            for t in range(1025, 1040)]
    rows = lm.containment(manifest, log, V)
    assert rows == [{"action_id": "a1", "target": "attacker", "scenario": "contain_syn_flood", "approval_to_applied_s": 1.5,
                     "mttc_s": 4.0, "applied_to_below_s": 2.5, "attack_start_to_contained_s": 34.0,
                     "pps_before": 1480.0, "pps_after": 20.0}]
    assert "| `contain_syn_flood` | attacker | 1.5 | 4.0 | 34.0 | 1480.0 -> 20.0 |" in lm.render_containment(rows)
    assert lm.render_containment([]) == "No lab containment was applied in this run."


def test_mttc_from_ovs_counters_reports_an_ineffective_rule_honestly():
    """live5: a one-IP rule was applied 0.58 s after approval but the switch still sent ~2,930 pps to the victim."""
    manifest = {"runs": [{"scenario": "contain_syn_flood", "started_at": 1000.0, "ended_at": 1120.0}]}
    log = [{"event": "enforcement_queued", "action_id": "a1", "op": "apply", "target": "10.99.0.144", "approved_at": 1040.0},
           {"event": "enforcement_reported", "action_id": "a1", "state": "applied", "ts": 1040.6}]
    tx = 0
    rows = []
    for k in range(30):
        ts = 1020.0 + 2 * k
        rows.append({"ts": ts, "ports": [{"port": "s1-eth1", "host": "victim", "tx_packets": tx}]})
        tx += 2 * (2990 if ts < 1040 else 2930)
    r = lm.containment_ovs(manifest, log, rows)[0]
    assert r["mttc_s"] is None and r["approval_to_applied_s"] == 0.6 and r["reduction"] < 0.05
    md = lm.render_containment([r])
    assert "| `contain_syn_flood` | 10.99.0.144 | 0.6 | not reached | not reached |" in md
    manifest_short = {"runs": [{"scenario": "contain_syn_flood", "started_at": 1000.0, "ended_at": 1050.0}]}
    rows3, tx = [], 0
    for k in range(30):  # ineffective rule, then the scenario ends: the drop at the end is NOT containment
        ts = 1020.0 + 2 * k
        rows3.append({"ts": ts, "ports": [{"port": "s1-eth1", "host": "victim", "tx_packets": tx}]})
        tx += 2 * (2930 if ts < 1050 else 0)
    assert lm.containment_ovs(manifest_short, log, rows3)[0]["mttc_s"] is None
    rows2, tx = [], 0
    for k in range(30):  # an effective rule: traffic falls to ~0 after the rule
        ts = 1020.0 + 2 * k
        rows2.append({"ts": ts, "ports": [{"port": "s1-eth1", "host": "victim", "tx_packets": tx}]})
        tx += 2 * (2990 if ts < 1042 else 5)
    e = lm.containment_ovs(manifest, log, rows2)[0]
    assert e["mttc_s"] == 4.0 and e["reduction"] > 0.8 and e["attack_start_to_contained_s"] == 44.0
