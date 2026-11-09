# -*- coding: utf-8 -*-
"""
Real Attack Counters: Ground Truth (Happened) vs. Detected.

Maintains persistent counters for controlled test runs and validation harnesses:
Tracks per attack category / family:
  - attacks_launched (ground truth known attack flows sent)
  - attacks_detected (is_attack=True AND correct family AND high confidence)
  - confidence_misses (is_attack=True, correct family, but below 0.94 high-confidence bar)
  - routing_errors (misrouted into wrong family or below class threshold)
  - false_negatives (launched attacks not cleanly detected: confidence misses + routing errors)
  - false_positives (benign ground truth flagged as attack)

Pre-populated with the empirical 13-PCAP Mininet validation run (6 clean passes, 4 confidence misses,
3 routing errors, 0 false alarms, 12/12 binary attack recall) documented in docs/eval/current_state.md.
"""

import os
import json
import logging
import threading
from typing import Dict, List, Optional, Any

logger = logging.getLogger("AttackCounters")

_DEFAULT_STORAGE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "config",
    "attack_counters.json"
)

# Canonical 13-PCAP test session baseline from docs/eval/current_state.md
BASELINE_PCAP_TESTS = [
    {
        "test_id": "TC-01",
        "attack_type": "UDP",
        "pcap_file": "UDP_v2.pcap",
        "target_family": "UDP-Reflection-Amplification",
        "detected_class": "UDP-Reflection-Amplification",
        "confidence": 0.9752,
        "calibrated_threshold": 0.500,
        "meets_threshold": True,
        "proposed_action_id": "aee2a4f1",
        "verdict": "CLEAN_PASS",
        "is_attack_ground_truth": True,
    },
    {
        "test_id": "TC-02",
        "attack_type": "NetBIOS",
        "pcap_file": "NetBIOS.pcap",
        "target_family": "UDP-Reflection-Amplification",
        "detected_class": "UDP-Reflection-Amplification",
        "confidence": 0.9686,
        "calibrated_threshold": 0.500,
        "meets_threshold": True,
        "proposed_action_id": "595dbbfd",
        "verdict": "CLEAN_PASS",
        "is_attack_ground_truth": True,
    },
    {
        "test_id": "TC-03",
        "attack_type": "Portmap",
        "pcap_file": "Portmap.pcap",
        "target_family": "UDP-Reflection-Amplification",
        "detected_class": "UDP-Reflection-Amplification",
        "confidence": 0.9632,
        "calibrated_threshold": 0.500,
        "meets_threshold": True,
        "proposed_action_id": "53e71c59",
        "verdict": "CLEAN_PASS",
        "is_attack_ground_truth": True,
    },
    {
        "test_id": "TC-04",
        "attack_type": "SNMP",
        "pcap_file": "SNMP.pcap",
        "target_family": "UDP-Reflection-Amplification",
        "detected_class": "UDP-Reflection-Amplification",
        "confidence": 0.9704,
        "calibrated_threshold": 0.500,
        "meets_threshold": True,
        "proposed_action_id": "8216887d",
        "verdict": "CLEAN_PASS",
        "is_attack_ground_truth": True,
    },
    {
        "test_id": "TC-05",
        "attack_type": "TFTP",
        "pcap_file": "TFTP.pcap",
        "target_family": "UDP-Reflection-Amplification",
        "detected_class": "UDP-Reflection-Amplification",
        "confidence": 0.9667,
        "calibrated_threshold": 0.500,
        "meets_threshold": True,
        "proposed_action_id": "cc8ba79e",
        "verdict": "CLEAN_PASS",
        "is_attack_ground_truth": True,
    },
    {
        "test_id": "TC-06",
        "attack_type": "Benign",
        "pcap_file": "benign.pcap",
        "target_family": "Benign",
        "detected_class": "Benign",
        "confidence": 0.9954,
        "calibrated_threshold": 0.742,
        "meets_threshold": True,
        "proposed_action_id": None,
        "verdict": "CLEAN_PASS",
        "is_attack_ground_truth": False,
    },
    {
        "test_id": "TC-07",
        "attack_type": "DNS",
        "pcap_file": "DNS.pcap",
        "target_family": "UDP-Reflection-Amplification",
        "detected_class": "UDP-Reflection-Amplification",
        "confidence": 0.9394,
        "calibrated_threshold": 0.500,
        "meets_threshold": True,
        "proposed_action_id": "820d2b98",
        "verdict": "CONFIDENCE_MISS",
        "is_attack_ground_truth": True,
        "notes": "Missed 0.94 high-confidence bar by 0.0006",
    },
    {
        "test_id": "TC-08",
        "attack_type": "UDP-Lag",
        "pcap_file": "UDP-Lag.pcap",
        "target_family": "UDP-Reflection-Amplification",
        "detected_class": "UDP-Reflection-Amplification",
        "confidence": 0.9334,
        "calibrated_threshold": 0.500,
        "meets_threshold": True,
        "proposed_action_id": "5f85ae27",
        "verdict": "CONFIDENCE_MISS",
        "is_attack_ground_truth": True,
        "notes": "Missed 0.94 high-confidence bar by 0.0066",
    },
    {
        "test_id": "TC-09",
        "attack_type": "MSSQL",
        "pcap_file": "MSSQL.pcap",
        "target_family": "UDP-Reflection-Amplification",
        "detected_class": "UDP-Reflection-Amplification",
        "confidence": 0.9048,
        "calibrated_threshold": 0.500,
        "meets_threshold": True,
        "proposed_action_id": "0575885b",
        "verdict": "CONFIDENCE_MISS",
        "is_attack_ground_truth": True,
        "notes": "Missed 0.94 high-confidence bar by 0.0352",
    },
    {
        "test_id": "TC-10",
        "attack_type": "LDAP",
        "pcap_file": "LDAP.pcap",
        "target_family": "UDP-Reflection-Amplification",
        "detected_class": "UDP-Reflection-Amplification",
        "confidence": 0.5532,
        "calibrated_threshold": 0.500,
        "meets_threshold": True,
        "proposed_action_id": "e27dbbe5",
        "verdict": "CONFIDENCE_MISS",
        "is_attack_ground_truth": True,
        "notes": "Cleared 0.50 calibrated threshold; weak confidence 0.5532",
    },
    {
        "test_id": "TC-11",
        "attack_type": "Syn",
        "pcap_file": "Syn_pure_unidirectional.pcap",
        "target_family": "Syn",
        "detected_class": "Syn",
        "confidence": 0.7120,
        "calibrated_threshold": 0.770,
        "meets_threshold": False,
        "proposed_action_id": "587f6f21",
        "verdict": "CLASS_ROUTING_ERROR",
        "is_attack_ground_truth": True,
        "notes": "Predicted Syn with 0.7120 but fell below 0.77 class threshold",
    },
    {
        "test_id": "TC-12",
        "attack_type": "WebDDoS",
        "pcap_file": "WebDDoS.pcap",
        "target_family": "WebDDoS",
        "detected_class": "UDP-Reflection-Amplification",
        "confidence": 0.7247,
        "calibrated_threshold": 0.500,
        "meets_threshold": True,
        "proposed_action_id": "12834f6c",
        "verdict": "CLASS_ROUTING_ERROR",
        "is_attack_ground_truth": True,
        "notes": "Zero HTTP payload bytes in pcap, misrouted into reflection manifold",
    },
    {
        "test_id": "TC-13",
        "attack_type": "NTP",
        "pcap_file": "NTP_v2.pcap",
        "target_family": "NTP",
        "detected_class": "UDP-Reflection-Amplification",
        "confidence": 0.9944,
        "calibrated_threshold": 0.500,
        "meets_threshold": True,
        "proposed_action_id": "007967bb",
        "verdict": "CLASS_ROUTING_ERROR",
        "is_attack_ground_truth": True,
        "notes": "UNEXPLAINED class routing error: 5000-packet flood collapsed into UDP reflection",
    },
]


class AttackCounterStore:
    """Thread-safe persistent store for test runs: Ground Truth vs. Detected."""

    def __init__(self, filepath: Optional[str] = None):
        self.filepath = filepath or _DEFAULT_STORAGE_PATH
        self._lock = threading.Lock()
        self.test_records: List[Dict[str, Any]] = []
        self._load_or_initialize()

    def _load_or_initialize(self) -> None:
        """Load persisted counters from disk or populate with canonical baseline."""
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.test_records = data.get("test_records", [])
                    return
            except Exception as e:
                logger.warning("Could not read %s (%s), initializing baseline.", self.filepath, e)

        # Initialize with baseline tests
        self.test_records = list(BASELINE_PCAP_TESTS)
        self.save()

    def save(self) -> None:
        """Persist current records to disk."""
        os.makedirs(os.path.dirname(self.filepath), exist_ok=True)
        try:
            with open(self.filepath, "w", encoding="utf-8") as f:
                json.dump({"test_records": self.test_records}, f, indent=2)
        except Exception as e:
            logger.error("Failed to persist attack counters to %s: %s", self.filepath, e)

    def record_test(self, record: Dict[str, Any]) -> None:
        """Append a new test run record."""
        with self._lock:
            self.test_records.append(record)
            self.save()

    def get_summary(self) -> Dict[str, Any]:
        """Compute honest happened vs. detected summary."""
        with self._lock:
            total_tests = len(self.test_records)
            attacks_launched = sum(1 for r in self.test_records if r.get("is_attack_ground_truth", True))
            benign_launched = total_tests - attacks_launched

            clean_passes = sum(1 for r in self.test_records if r.get("verdict") == "CLEAN_PASS")
            confidence_misses = sum(1 for r in self.test_records if r.get("verdict") == "CONFIDENCE_MISS")
            routing_errors = sum(1 for r in self.test_records if r.get("verdict") == "CLASS_ROUTING_ERROR")

            # Binary attack detection: is it flagged as attack when it is an attack?
            # Clean passes (for attacks) + confidence misses + routing errors were all flagged as attacks
            binary_attacks_detected = sum(
                1 for r in self.test_records
                if r.get("is_attack_ground_truth", True) and r.get("detected_class") != "Benign"
            )

            # False positives: benign ground truth flagged as an attack
            false_positives = sum(
                1 for r in self.test_records
                if not r.get("is_attack_ground_truth", True) and r.get("detected_class") != "Benign"
            )

            # False negatives under strict high-confidence bar (>=0.94)
            # Attacks that were either missed or misclassified
            false_negatives = attacks_launched - (clean_passes - (1 if benign_launched > 0 and any(r["verdict"] == "CLEAN_PASS" and not r["is_attack_ground_truth"] for r in self.test_records) else 0))

            clean_pass_rate = (clean_passes / total_tests * 100.0) if total_tests > 0 else 0.0
            binary_recall = (binary_attacks_detected / attacks_launched * 100.0) if attacks_launched > 0 else 0.0
            fpr = (false_positives / benign_launched * 100.0) if benign_launched > 0 else 0.0

            return {
                "total_tests_evaluated": total_tests,
                "attacks_launched": attacks_launched,
                "benign_launched": benign_launched,
                "clean_passes": clean_passes,
                "confidence_misses": confidence_misses,
                "routing_errors": routing_errors,
                "clean_pass_rate": f"{clean_pass_rate:.1f}% ({clean_passes}/{total_tests})",
                "binary_attack_recall": f"{binary_recall:.1f}% ({binary_attacks_detected}/{attacks_launched})",
                "false_positives": false_positives,
                "false_positive_rate": f"{fpr:.1f}% ({false_positives}/{benign_launched})",
                "false_negatives": false_negatives,
                "scorecard_verdict": f"{clean_passes}/{total_tests} Clean Passes (≥0.94), {confidence_misses} Confidence-Misses, {routing_errors} Routing Errors",
                "test_records": list(self.test_records),
            }


_counter_instance: Optional[AttackCounterStore] = None
_instance_lock = threading.Lock()


def get_attack_counters() -> AttackCounterStore:
    """Global singleton accessor for AttackCounterStore."""
    global _counter_instance
    with _instance_lock:
        if _counter_instance is None:
            _counter_instance = AttackCounterStore()
        return _counter_instance
