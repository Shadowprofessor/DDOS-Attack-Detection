"""Tests for the flow-stats prediction loop in enhanced_security_controller.py.

These tests exercise the prediction + profiling + classification logic WITHOUT
requiring a live Ryu/Mininet environment by testing the data-processing code
path directly.
"""
import sys
import os

# Add the Codes directory to sys.path so imports resolve
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "Codes")))

from security.attacker_profiler import AttackerProfiler
from security.attack_type_classifier import AttackTypeClassifier
from security.threat_intelligence import ThreatIntelligence


class TestFlowStatsPredictionLoop:
    """
    Tests the data flow that was broken by the undefined `idx` variable.
    We replicate the exact logic from _flow_stats_reply_handler without
    needing the Ryu framework — we build stats_data the same way the
    controller does, then run predictions and profiling.
    """

    def setup_method(self):
        self.profiler = AttackerProfiler(high_threat_threshold=30)
        self.threat_intel = ThreatIntelligence(default_block_duration_sec=300)
        self.classifier = AttackTypeClassifier()

    def _build_stats_row(self, ip_src_str, ip_dst_str, tp_src=0, tp_dst=80,
                         ip_proto=6, icmp_code=-1, icmp_type=-1,
                         duration_sec=5, duration_nsec=500000,
                         packet_count=100, byte_count=10000):
        """Build a stats_data row in the same format the controller produces."""
        ip_src_num = int(ip_src_str.replace('.', ''))
        ip_dst_num = int(ip_dst_str.replace('.', ''))
        rate_pps = packet_count / max(duration_sec, 1)
        rate_npps = packet_count / max(duration_nsec, 1)
        rate_bps = byte_count / max(duration_sec, 1)
        rate_nbps = byte_count / max(duration_nsec, 1)
        return [
            ip_src_num, tp_src, ip_dst_num, tp_dst, ip_proto, icmp_code, icmp_type,
            duration_sec, duration_nsec, 0, 0, 0, packet_count, byte_count,
            rate_pps, rate_npps, rate_bps, rate_nbps, ip_src_str, ip_dst_str
        ]

    def _run_heuristic_predictions(self, stats_data):
        """Replicate the heuristic prediction path (no ML model)."""
        predictions = []
        for row in stats_data:
            pred = 1 if row[14] > 50 else 0  # rate_pps > 50
            predictions.append((pred, row[18], row[19], row[12], row[13]))
        return predictions

    def test_prediction_loop_with_idx_uses_enumerate(self):
        """
        The original bug: the loop used `idx` without defining it.
        This test verifies the fixed loop logic works end-to-end
        with the same data structures the controller uses.
        """
        # Build stats_data with an attack flow (high pps)
        stats_data = [
            self._build_stats_row(
                "192.168.1.100", "10.0.0.1",
                packet_count=500, byte_count=500 * 64,
                duration_sec=1, ip_proto=1, icmp_type=8
            ),
            self._build_stats_row(
                "10.0.0.5", "10.0.0.2",
                packet_count=10, byte_count=10 * 1400,
                duration_sec=60, ip_proto=6
            ),
        ]

        predictions = self._run_heuristic_predictions(stats_data)

        # Replicate the FIXED loop from the controller
        ddos_count = 0
        detected_attacks = []
        for idx, (pred, ip_src_str, ip_dst_str, pkt_cnt, byte_cnt) in enumerate(predictions):
            if pred == 1:
                ddos_count += 1

                if self.threat_intel.is_blacklisted(ip_src_str):
                    continue
                if self.threat_intel.is_blacklisted(ip_dst_str):
                    continue

                # This is the line that was crashing — now uses stats_data[idx]
                row = stats_data[idx]
                pkt_cnt = row[12]
                byte_cnt = row[13]
                dur_sec = row[7]
                ip_proto = row[4]
                tp_src = row[1]
                tp_dst = row[3]
                icmp_type = row[6]

                profile_res = self.profiler.analyze_flow(
                    ip_src_str, ip_dst_str, pkt_cnt, byte_cnt, dur_sec, ip_proto, tp_src, tp_dst
                )

                attack_type = self.classifier.classify_attack(
                    ip_proto, tp_src, tp_dst, icmp_type, pkt_cnt, byte_cnt, dur_sec
                )

                detected_attacks.append({
                    "attacker": ip_src_str,
                    "victim": ip_dst_str,
                    "attack_type": attack_type,
                    "threat_score": profile_res["threat_score"] if profile_res else 0,
                })

        # The attack flow should be detected, benign should not
        assert ddos_count == 1
        assert len(detected_attacks) == 1
        assert detected_attacks[0]["attacker"] == "192.168.1.100"
        assert detected_attacks[0]["victim"] == "10.0.0.1"
        assert "ICMP" in detected_attacks[0]["attack_type"]

    def test_mixed_attack_and_benign_flows(self):
        """Multiple flows: some attack, some benign. Verify correct indexing."""
        stats_data = [
            # Benign
            self._build_stats_row("10.0.0.1", "10.0.0.2", packet_count=5,
                                  byte_count=5 * 1400, duration_sec=30, ip_proto=6),
            # Attack (high pps)
            self._build_stats_row("192.168.1.200", "10.0.0.1", packet_count=1000,
                                  byte_count=1000 * 64, duration_sec=1, ip_proto=17,
                                  tp_dst=53),
            # Benign
            self._build_stats_row("10.0.0.3", "10.0.0.4", packet_count=20,
                                  byte_count=20 * 800, duration_sec=120, ip_proto=6),
            # Attack (high pps)
            self._build_stats_row("192.168.1.201", "10.0.0.1", packet_count=2000,
                                  byte_count=2000 * 40, duration_sec=1, ip_proto=6,
                                  tp_dst=80),
        ]

        predictions = self._run_heuristic_predictions(stats_data)
        ddos_count = 0
        attack_ips = []

        for idx, (pred, ip_src_str, ip_dst_str, pkt_cnt, byte_cnt) in enumerate(predictions):
            if pred == 1:
                ddos_count += 1
                # Verify idx correctly maps to stats_data
                row = stats_data[idx]
                assert row[18] == ip_src_str  # ip_src_str matches
                assert row[19] == ip_dst_str  # ip_dst_str matches
                attack_ips.append(ip_src_str)

        assert ddos_count == 2
        assert "192.168.1.200" in attack_ips
        assert "192.168.1.201" in attack_ips

    def test_blacklisted_source_is_skipped(self):
        """Verify blacklisted attacker IPs are skipped (not double-processed)."""
        self.threat_intel.blacklist_ip("192.168.1.100")

        stats_data = [
            self._build_stats_row("192.168.1.100", "10.0.0.1",
                                  packet_count=500, byte_count=500 * 64,
                                  duration_sec=1, ip_proto=1),
        ]
        predictions = self._run_heuristic_predictions(stats_data)

        processed = []
        for idx, (pred, ip_src_str, ip_dst_str, pkt_cnt, byte_cnt) in enumerate(predictions):
            if pred == 1:
                if self.threat_intel.is_blacklisted(ip_src_str):
                    continue
                processed.append(ip_src_str)

        assert len(processed) == 0  # Should be skipped
