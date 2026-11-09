# -*- coding: utf-8 -*-
"""
Tests for Attack Campaign & Multi-Flow Correlator (Phase H - H8).
Verifies:
  - Multi-flow grouping by (victim_ip, attack_family)
  - Bot count aggregation across distributed source IPs
  - Campaign expiration lifecycle
  - Generation of AI Threat Analyst Notes (both deterministic heuristic and live Nemotron)
"""

import os
import time
import pytest
from unittest.mock import patch
from src.agent.campaign_correlator import (
    CampaignCorrelator,
    normalize_attack_family,
)


def test_normalize_attack_family():
    assert normalize_attack_family("Syn") == "TCP-SYN-Flood"
    assert normalize_attack_family("NTP") == "UDP-Reflection-Amplification"
    assert normalize_attack_family("DNS") == "UDP-Reflection-Amplification"
    assert normalize_attack_family("UDP") == "UDP-Volumetric-Flood"
    assert normalize_attack_family("WebDDoS") == "HTTP-Application-Flood"
    assert normalize_attack_family("Benign") == "Benign"


def test_single_flow_campaign_heuristic():
    """Verify single-flow campaign with deterministic heuristic analyst notes."""
    # Temporarily remove API keys to test deterministic heuristic fallback
    with patch.dict(os.environ, {"NVIDIA_API_KEY": "", "OPENROUTER_API_KEY": ""}):
        correlator = CampaignCorrelator(window_seconds=60.0)
        camp = correlator.ingest_flow_alert(
            src_ip="192.168.1.10",
            victim_ip="10.0.0.2",
            attack_label="Syn",
            pps=1500.0,
            bps=90000.0,
            packet_count=5000,
            byte_count=300000,
            timestamp=100.0,
        )

        assert camp.campaign_id.startswith("CAMP-")
        assert camp.victim_ip == "10.0.0.2"
        assert camp.attack_family == "TCP-SYN-Flood"
        assert camp.bot_count == 1
        assert camp.flow_count == 1
        assert camp.status == "ACTIVE"
        assert camp.analyst_notes is not None
        assert camp.analyst_notes["source"] == "Deterministic Blue-Team Expert (Heuristic Baseline)"
        assert camp.analyst_notes["coordination_confidence"] == "LOW"
        assert "Single-Source Focused Vector" in camp.analyst_notes["assessment"]


def test_multi_source_distributed_campaign_heuristic():
    """Verify multi-source distributed campaign with deterministic heuristic analyst notes."""
    with patch.dict(os.environ, {"NVIDIA_API_KEY": "", "OPENROUTER_API_KEY": ""}):
        correlator = CampaignCorrelator(window_seconds=60.0)

        # 12 distinct bots attacking the same victim with NTP reflection
        for i in range(12):
            camp = correlator.ingest_flow_alert(
                src_ip=f"198.51.100.{i+1}",
                victim_ip="10.0.0.2",
                attack_label="NTP",
                pps=800.0,
                bps=400000.0,
                packet_count=1000,
                byte_count=500000,
                timestamp=100.0 + (i * 2.0),
            )

        assert camp.victim_ip == "10.0.0.2"
        assert camp.attack_family == "UDP-Reflection-Amplification"
        assert camp.bot_count == 12
        assert camp.flow_count == 12
        assert camp.status == "ACTIVE"
        assert camp.aggregate_pps == 800.0 * 12
        assert camp.analyst_notes is not None
        assert camp.analyst_notes["coordination_confidence"] == "VERY_HIGH"
        assert "Distributed Botnet Cluster" in camp.analyst_notes["assessment"]


def test_campaign_expiration():
    with patch.dict(os.environ, {"NVIDIA_API_KEY": "", "OPENROUTER_API_KEY": ""}):
        correlator = CampaignCorrelator(window_seconds=10.0, idle_timeout=15.0)

        # Initial flow at t=100
        c1 = correlator.ingest_flow_alert(
            src_ip="10.0.0.5",
            victim_ip="10.0.0.2",
            attack_label="UDP",
            timestamp=100.0,
        )
        camp_id_1 = c1.campaign_id

        # Next flow at t=120 (> window_seconds and > idle_timeout)
        c2 = correlator.ingest_flow_alert(
            src_ip="10.0.0.6",
            victim_ip="10.0.0.2",
            attack_label="UDP",
            timestamp=120.0,
        )

        assert c2.campaign_id != camp_id_1
        assert c2.status == "ACTIVE"
        concluded = correlator.get_concluded_campaigns()
        assert len(concluded) == 1
        assert concluded[0]["campaign_id"] == camp_id_1
        assert concluded[0]["status"] == "CONCLUDED"


def test_live_nemotron_campaign_analysis():
    """Verify live Nemotron 3 Ultra analysis when NVIDIA_API_KEY is present."""
    if not os.environ.get("NVIDIA_API_KEY") and not os.environ.get("OPENROUTER_API_KEY"):
        pytest.skip("No LLM API key present in environment")

    correlator = CampaignCorrelator(window_seconds=60.0)
    camp = correlator.ingest_flow_alert(
        src_ip="192.168.1.55",
        victim_ip="10.0.0.2",
        attack_label="Syn",
        pps=2500.0,
        bps=120000.0,
        packet_count=8000,
        byte_count=400000,
        timestamp=100.0,
    )

    assert camp.analyst_notes is not None
    assert "source" in camp.analyst_notes
    assert "assessment" in camp.analyst_notes
    assert "recommended_mitigation_scope" in camp.analyst_notes


def test_botnet_breakdown_and_timeline_expansion():
    """Verify Part 2C: per-bot breakdown, amplifier matching, timeline events, and synthetic GeoIP notice."""
    with patch.dict(os.environ, {"NVIDIA_API_KEY": "", "OPENROUTER_API_KEY": ""}):
        correlator = CampaignCorrelator(window_seconds=60.0)

        # Ingest 3 bots: 1 with DNS amplifier port, 1 with NTP, 1 standard
        camp = correlator.ingest_flow_alert(
            src_ip="198.51.100.10",
            victim_ip="10.0.0.2",
            attack_label="DNS",
            pps=1200.0,
            packet_count=500,
            byte_count=250000,
            timestamp=10.0,
            src_port=53,
        )
        camp = correlator.ingest_flow_alert(
            src_ip="198.51.100.20",
            victim_ip="10.0.0.2",
            attack_label="NTP",
            pps=800.0,
            packet_count=300,
            byte_count=180000,
            timestamp=10.5,
            src_port=123,
        )
        camp = correlator.ingest_flow_alert(
            src_ip="198.51.100.30",
            victim_ip="10.0.0.2",
            attack_label="SNMP",
            pps=400.0,
            packet_count=100,
            byte_count=60000,
            timestamp=11.2,
            src_port=161,
        )

        d = camp.to_dict()

        # 1. Bot count
        assert d["bot_count"] == 3
        assert len(d["bot_breakdown"]) == 3

        # 2. Per-bot details & amplifier detection
        bot_dns = next(b for b in d["bot_breakdown"] if b["ip"] == "198.51.100.10")
        assert bot_dns["packet_count"] == 500
        assert bot_dns["is_known_amplifier"] is True
        assert "DNS" in bot_dns["amplifier_vector"]

        bot_ntp = next(b for b in d["bot_breakdown"] if b["ip"] == "198.51.100.20")
        assert bot_ntp["is_known_amplifier"] is True
        assert "NTP" in bot_ntp["amplifier_vector"]

        # 3. Timeline events
        timeline = d["timeline"]
        assert len(timeline) >= 3
        join_events = [e for e in timeline if e["event"] == "BOT_JOINED"]
        assert len(join_events) == 3

        # 4. Ramp profile
        assert "GRADUAL" in d["ramp_profile"] or "IMMEDIATE" in d["ramp_profile"]

        # 5. Synthetic GeoIP notice (honest disclosure, no fake coordinates)
        geo = d["geo_asn_context"]
        assert geo["status"] == "OMITTED_SYNTHETIC_RANGE"
        assert geo["synthetic_network_environment"] is True
        assert "RFC 1918" in geo["notice"]

