"""Tests for Codes/security/attacker_profiler.py — exercises every scoring branch."""
import sys
import os

# Add the Codes directory to sys.path so imports resolve
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "Codes")))

from security.attacker_profiler import AttackerProfiler


class TestAttackerProfilerScoring:
    """Verifies that analyze_flow() runs without crash and scores correctly."""

    def setup_method(self):
        self.profiler = AttackerProfiler(high_threat_threshold=30)

    # ── Branch: null / zero IP returns None ──
    def test_null_ip_returns_none(self):
        result = self.profiler.analyze_flow("", "10.0.0.2", 100, 5000, 10, 6, 1234, 80)
        assert result is None

    def test_zero_ip_returns_none(self):
        result = self.profiler.analyze_flow("0.0.0.0", "10.0.0.2", 100, 5000, 10, 6, 1234, 80)
        assert result is None

    # ── Branch: packet_count >= 100 → score += 100 ──
    def test_packet_count_exceeds_100_full_prevention(self):
        result = self.profiler.analyze_flow(
            "192.168.1.100", "10.0.0.1",
            packet_count=150, byte_count=150 * 64,
            duration=2, ip_proto=1, tp_src=0, tp_dst=0
        )
        assert result is not None
        assert result["threat_score"] >= 100  # Capped at 100
        assert "PACKET_COUNT_EXCEEDS_100_FULL_PREVENTION" in result["anomaly_flags"]
        assert result["is_high_threat"] is True

    # ── Branch: 50 < packet_count < 100 → score += 50 ──
    def test_packet_count_exceeds_50_detection(self):
        result = self.profiler.analyze_flow(
            "192.168.1.101", "10.0.0.1",
            packet_count=75, byte_count=75 * 200,
            duration=10, ip_proto=6, tp_src=5000, tp_dst=80
        )
        assert result is not None
        assert result["threat_score"] >= 50
        assert "PACKET_COUNT_EXCEEDS_50_DETECTION" in result["anomaly_flags"]

    # ── Branch: rate_pps > 20 → score += 30 ──
    def test_high_rate_pps_over_20(self):
        # 40 packets in 1 second = 40 pps > 20, but packet_count < 50
        result = self.profiler.analyze_flow(
            "192.168.1.102", "10.0.0.1",
            packet_count=40, byte_count=40 * 200,
            duration=1, ip_proto=17, tp_src=5000, tp_dst=53
        )
        assert result is not None
        assert result["threat_score"] >= 30

    # ── Branch: 5 < rate_pps <= 20 → score += 15 ──
    def test_moderate_rate_pps_over_5(self):
        # 10 packets in 1 second = 10 pps, packet_count < 50
        result = self.profiler.analyze_flow(
            "192.168.1.103", "10.0.0.1",
            packet_count=10, byte_count=10 * 500,
            duration=1, ip_proto=6, tp_src=5000, tp_dst=443
        )
        assert result is not None
        assert result["threat_score"] >= 15

    # ── Branch: rate_pps <= 5 → score = 0 from rate (only small packet flag might add) ──
    def test_low_rate_benign_traffic(self):
        result = self.profiler.analyze_flow(
            "192.168.1.104", "10.0.0.1",
            packet_count=5, byte_count=5 * 1400,
            duration=10, ip_proto=6, tp_src=5000, tp_dst=80
        )
        assert result is not None
        # Low rate, large packets, single target → minimal score
        assert result["threat_score"] < 30
        assert result["is_high_threat"] is False

    # ── Branch: multi-target scanning → score += 25 ──
    def test_multi_target_scanning(self):
        # Same attacker hitting 3+ distinct targets
        self.profiler.analyze_flow(
            "192.168.1.105", "10.0.0.1",
            packet_count=5, byte_count=5 * 500, duration=10, ip_proto=6, tp_src=5000, tp_dst=80
        )
        self.profiler.analyze_flow(
            "192.168.1.105", "10.0.0.2",
            packet_count=5, byte_count=5 * 500, duration=10, ip_proto=6, tp_src=5001, tp_dst=80
        )
        result = self.profiler.analyze_flow(
            "192.168.1.105", "10.0.0.3",
            packet_count=5, byte_count=5 * 500, duration=10, ip_proto=6, tp_src=5002, tp_dst=80
        )
        assert result is not None
        assert "PORT_OR_HOST_SCANNING" in result["anomaly_flags"]

    # ── Branch: small packet flood → score += 20 ──
    def test_small_packet_flood(self):
        # avg packet size < 128 bytes
        result = self.profiler.analyze_flow(
            "192.168.1.106", "10.0.0.1",
            packet_count=10, byte_count=10 * 64,
            duration=10, ip_proto=1, tp_src=0, tp_dst=0
        )
        assert result is not None
        assert "SMALL_PACKET_FLOOD" in result["anomaly_flags"]

    # ── Cumulative: total_packets > 100 across multiple calls ──
    def test_cumulative_total_packets_exceeds_100(self):
        for _ in range(5):
            self.profiler.analyze_flow(
                "192.168.1.107", "10.0.0.1",
                packet_count=25, byte_count=25 * 200,
                duration=5, ip_proto=6, tp_src=5000, tp_dst=80
            )
        # After 5 calls: total_packets = 125 >= 100
        result = self.profiler.analyze_flow(
            "192.168.1.107", "10.0.0.1",
            packet_count=5, byte_count=5 * 200,
            duration=5, ip_proto=6, tp_src=5000, tp_dst=80
        )
        assert result is not None
        assert result["threat_score"] >= 50  # Should have accumulated significantly

    # ── Score capped at 100 ──
    def test_score_capped_at_100(self):
        result = self.profiler.analyze_flow(
            "192.168.1.108", "10.0.0.1",
            packet_count=200, byte_count=200 * 64,
            duration=1, ip_proto=1, tp_src=0, tp_dst=0
        )
        assert result is not None
        assert result["threat_score"] <= 100

    # ── get_profile / get_all_attackers ──
    def test_get_profile_returns_data(self):
        self.profiler.analyze_flow(
            "192.168.1.109", "10.0.0.1",
            packet_count=100, byte_count=100 * 64,
            duration=1, ip_proto=1, tp_src=0, tp_dst=0
        )
        profile = self.profiler.get_profile("192.168.1.109")
        assert profile is not None
        assert "threat_score" in profile

    def test_get_profile_unknown_ip(self):
        assert self.profiler.get_profile("99.99.99.99") is None

    def test_get_all_attackers(self):
        self.profiler.analyze_flow(
            "192.168.1.110", "10.0.0.1",
            packet_count=200, byte_count=200 * 64,
            duration=1, ip_proto=1, tp_src=0, tp_dst=0
        )
        attackers = self.profiler.get_all_attackers(min_threat=50)
        assert "192.168.1.110" in attackers
