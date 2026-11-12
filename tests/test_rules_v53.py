# -*- coding: utf-8 -*-
"""v5.3.0 L3 rule ladder (offline flow evidence + live window evidence) and explanations."""
import pytest

from src.agent.explain import explain_analysis, explain_l1_window, explain_score
from src.agent.schemas import AnalysisResult, IncidentAggregate
from src.agent.threat_analyst import rule_based_analysis
from src.ir.export import to_markdown
from src.ir.playbooks import family_from_text

V = "10.99.0.10"


def agg(**kw):
    base = {"incident_id": "t", "window_start": 0, "window_seconds": 60, "pps": 1500.0, "bps": 1e6,
            "unique_src_ips": 50, "dst_ips": [V], "protocol_mix": {"tcp": 1.0}}
    base.update(kw)
    return rule_based_analysis(IncidentAggregate.model_validate(base))


def tcp(**kw):
    t = {"tcp_flows": 30000, "half_open_share": 0.0, "bare_ack_share": 0.0, "bare_rst_share": 0.0,
         "completed_share": 0.0, "half_open_per_s": 0.0}
    t.update(kw)
    return t


@pytest.mark.parametrize("kw, attack, family", [
    ({"tcp_flows": tcp(half_open_share=1.0, half_open_per_s=611)}, "TCP SYN flood", "syn_flood"),
    ({"tcp_flag_ratios": {"syn": 0.5, "rst": 0.5}, "tcp_payload_share": 0.0}, "TCP SYN flood", "syn_flood"),  # live
    ({"tcp_flows": tcp(bare_ack_share=1.0)}, "TCP ACK flood", "other"),
    ({"tcp_flag_ratios": {"ack_only": 0.98}, "tcp_payload_share": 0.0}, "TCP ACK flood", "other"),
    ({"tcp_flows": tcp(bare_rst_share=1.0)}, "TCP RST flood", "other"),
    ({"tcp_flag_ratios": {"rst": 1.0}}, "TCP RST flood", "other"),
    ({"land_share": 1.0, "pps": 300.0, "tcp_flows": tcp(half_open_share=1.0, half_open_per_s=0.02)},
     "LAND attack (source IP equals destination IP)", "other"),
    ({"protocol_mix": {"udp": 1.0}, "src_ports": [{"key": "53", "share": 1.0}]}, "DNS reflection-amplification", "dns_amplification"),
    ({"protocol_mix": {"udp": 1.0}, "src_ports": [{"key": "123", "share": 1.0}]}, "UDP reflection-amplification (NTP)",
     "udp_reflection_amplification"),
    ({"protocol_mix": {"icmp": 1.0}}, "ICMP flood", "other"),
    ({"protocol_mix": {"tcp": 0.45, "icmp": 0.3, "udp": 0.25}}, "Unclassified multi-protocol flood (possible zero-day / novel)",
     "zero_day_ood"),
    ({"dst_ips": [f"10.99.0.{i}" for i in range(10)]}, "Carpet-bombing across 10 destinations", "other"),
])
def test_rule_ladder_names_each_attack(kw, attack, family):
    a = agg(**kw)
    assert a.attack_type == attack and family_from_text(a.attack_type) == family
    assert a.reason.startswith("L3 rules: ") and a.mitre_ids


def test_benign_http_with_complete_handshakes_stays_benign():
    a = agg(pps=96.0, unique_src_ips=100, tcp_flows=tcp(completed_share=1.0), tcp_flag_ratios={"syn": 0.1, "psh": 0.3},
            tcp_payload_share=0.4)
    assert a.attack_type.startswith("Benign") and "96 pps" in a.reason


def test_live_l1_explanation_has_the_numbers():
    w = {"start": 0, "end": 1, "dst": V, "packets": 1416, "bytes": 1416 * 84, "pps": 1416.0, "bps": 1416 * 672.0,
         "unique_src": 20, "src_entropy": 4.3, "proto_mix": {"icmp": 0.99, "tcp": 0.01}, "tcp_flags": {},
         "pkt_size": {"mean": 84}, "top_talkers": [{"ip": "10.99.0.100", "packets": 80}], "top_dst_ports": [],
         "hint": "ICMP 99%"}
    e = explain_l1_window(w, {"rules": ["CRITICAL: Packet Rate 1416.0 pps >= 500.0 (Benign Baseline: 2.02 pps, 701x)"],
                              "vector": "Rate-Based Volumetric Flood"}, 500.0, 100.0)
    assert e.reason == "L1: 1,416 pps to 10.99.0.10 >= 500 pps critical threshold; ICMP 99% of packets; 20 sources -> 1 victim; T1498.001"
    assert e.attack_type == "ICMP flood" and e.confidence is None and e.evidence[0] == "CRITICAL: Packet Rate 1416.0 pps >= 500.0"


def test_analysis_and_score_explanations():
    a = agg(tcp_flows=tcp(half_open_share=1.0, half_open_per_s=611))
    e = explain_analysis(AnalysisResult(analysis=a, source="rules", prompt_version="x"))
    assert e.detected_by == "L3 rule analyst" and e.attack_type == "TCP SYN flood" and "half-open" in e.reason
    assert explain_score(False, "Benign", 0.9, "ml") is None
    ml = explain_score(True, "Syn", 0.97, "ml", dst=V)
    assert ml.detected_by == "L2 ML ensemble" and "confidence 0.97" in ml.reason
    co = explain_score(True, "Distributed-SYN-Flood", 0.93, "multi_layer",
                       h6={"triggered_rules": ["CRITICAL: SYN Rate 620.0 syn/s >= 200.0 (Benign Baseline: 0.0 syn/s)"]})
    assert co.confidence is None and "the ML said Benign" in co.reason and "620.0 syn/s" in co.reason


def test_export_has_why_it_was_flagged():
    a = agg(protocol_mix={"icmp": 1.0})
    res = AnalysisResult(analysis=a, source="rules", prompt_version="x")
    res = res.model_copy(update={"explanation": explain_analysis(res)})
    inc = {"id": "INC-1", "title": "t", "severity": 4, "status": "new", "attack_family": "other", "created_at": 0,
           "detected_at": 0, "events": [], "actions": [], "chain": {"ok": True},
           "aggregate": {"alert_history": [{"ts": 1, "layer": "L1", "rule": "ICMP flood", "detail": "L1: 1,416 pps to 10.99.0.10 >= 500"}]},
           "analysis": res.model_dump()}
    md = to_markdown(inc)
    plain = md.replace("\\", "")  # md_escape backslash-escapes ( ) - . etc.
    assert "## Why it was flagged" in md and "L1 alert: ICMP flood (confidence n/a, rule)" in plain
    assert "L3 rule analyst: ICMP flood (confidence" in plain and "ICMP 100% of packets" in plain


def test_flow_level_syn_fin_needs_no_ack_and_benign_conversations_do_not_count_warnings():
    from src.features.signature_filter import SignatureFilter
    from src.features.threshold_detector import RateThresholdDetector, is_benign_conversation, l1_rate_counts

    sig = SignatureFilter()
    normal = {"Protocol": 6, "SYN Flag Count": 2, "FIN Flag Count": 2, "ACK Flag Count": 8,
              "Fwd Packets Length Total": 300, "Bwd Packets Length Total": 5000}
    probe = {"Protocol": 6, "SYN Flag Count": 1, "FIN Flag Count": 1, "ACK Flag Count": 0}
    assert not sig.inspect_flow_features(normal).matched  # DEV benign/flash-crowd flows matched before v5.3.0
    assert sig.inspect_flow_features(probe).signature_id == "SIG-TCP-001"
    assert is_benign_conversation(normal) and not is_benign_conversation({**normal, "Bwd Packets Length Total": 0})
    d = RateThresholdDetector()
    warn, crit = d.evaluate_rates(150, 0, 1e5, 0), d.evaluate_rates(1500, 0, 1e6, 0)
    assert not l1_rate_counts(warn, normal) and l1_rate_counts(warn, probe)
    assert l1_rate_counts(crit, normal)  # CRITICAL always counts
