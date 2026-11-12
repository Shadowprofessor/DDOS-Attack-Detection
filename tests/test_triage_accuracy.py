# -*- coding: utf-8 -*-
"""v5.4.0 triage accuracy metric: type / family / false alarms, per verdict source."""
import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("ta", Path(__file__).resolve().parent.parent / "scripts" / "triage_accuracy.py")
ta = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ta)


def test_metrics_count_type_family_and_false_alarms():
    rows = [
        {"scenario": "syn_flood", "rules": "TCP SYN flood", "rules_type_ok": True, "rules_family_ok": True,
         "llm": "UDP flood", "llm_type_ok": False, "llm_family_ok": False},
        {"scenario": "udp_flood", "rules": "UDP flood", "rules_type_ok": True, "rules_family_ok": True,
         "llm": "Benign / flash crowd", "llm_type_ok": False, "llm_family_ok": False},
        {"scenario": "flash_crowd", "rules": "Benign / insufficient evidence", "llm": "HTTP flood (L7)"},
        {"scenario": "benign_baseline", "rules": "Benign / insufficient evidence", "llm": "Benign traffic"},
    ]
    m = ta.score(rows)
    assert m["rules"] == {"n_attacks": 2, "n_benign": 2, "attack_type_correct": 1.0, "family_correct": 1.0, "false_alarm_rate": 0.0}
    assert m["llm"]["attack_type_correct"] == 0.0 and m["llm"]["false_alarm_rate"] == 0.5
    assert "ml" not in m
    assert ta.is_benign_verdict("Benign / flash crowd") and not ta.is_benign_verdict("ICMP flood")
