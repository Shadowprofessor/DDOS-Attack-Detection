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
