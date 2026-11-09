# -*- coding: utf-8 -*-
"""
Tests for AttackCounterStore (Real Attack Counters: Happened vs. Detected).
Ensures the persistent counter strictly reproduces the authentic 6/13 scorecard.
"""

import os
import pytest
from src.mitigation.attack_counters import AttackCounterStore, BASELINE_PCAP_TESTS


def test_attack_counters_scorecard_integrity(tmp_path):
    storage_file = os.path.join(tmp_path, "test_counters.json")
    store = AttackCounterStore(filepath=storage_file)
    summary = store.get_summary()

    # 1. Total tests evaluated
    assert summary["total_tests_evaluated"] == 13
    assert summary["attacks_launched"] == 12
    assert summary["benign_launched"] == 1

    # 2. Scorecard verification: exactly 6 clean passes, 4 confidence misses, 3 routing errors
    assert summary["clean_passes"] == 6
    assert summary["confidence_misses"] == 4
    assert summary["routing_errors"] == 3

    # 3. Honest rates
    assert summary["binary_attack_recall"] == "100.0% (12/12)"
    assert summary["false_positives"] == 0
    assert summary["false_positive_rate"] == "0.0% (0/1)"
    assert summary["clean_pass_rate"] == "46.2% (6/13)"

    # 4. Check specific records
    records = summary["test_records"]
    ntp_record = next(r for r in records if r["attack_type"] == "NTP")
    assert ntp_record["verdict"] == "CLASS_ROUTING_ERROR"
    assert "UNEXPLAINED" in ntp_record["notes"]

    syn_record = next(r for r in records if r["attack_type"] == "Syn")
    assert syn_record["verdict"] == "CLASS_ROUTING_ERROR"
    assert syn_record["confidence"] == 0.7120

    benign_record = next(r for r in records if r["attack_type"] == "Benign")
    assert benign_record["verdict"] == "CLEAN_PASS"
    assert benign_record["is_attack_ground_truth"] is False
    assert benign_record["confidence"] == 0.9954


def test_attack_counters_append_and_persistence(tmp_path):
    storage_file = os.path.join(tmp_path, "test_counters_append.json")
    store = AttackCounterStore(filepath=storage_file)

    new_test = {
        "test_id": "TC-14",
        "attack_type": "DNS",
        "pcap_file": "DNS_test2.pcap",
        "target_family": "UDP-Reflection-Amplification",
        "detected_class": "UDP-Reflection-Amplification",
        "confidence": 0.9810,
        "calibrated_threshold": 0.500,
        "meets_threshold": True,
        "proposed_action_id": "11223344",
        "verdict": "CLEAN_PASS",
        "is_attack_ground_truth": True,
    }
    store.record_test(new_test)

    # Reload store
    reloaded = AttackCounterStore(filepath=storage_file)
    summary = reloaded.get_summary()
    assert summary["total_tests_evaluated"] == 14
    assert summary["clean_passes"] == 7
