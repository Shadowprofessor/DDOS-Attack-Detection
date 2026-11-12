# -*- coding: utf-8 -*-
"""v5.3.0 live L1: flash-crowd guard (benign signals + per-destination baseline) and low-and-slow."""
from src.features.flow_extractor import Packet
from src.live.state import LiveState
from src.live.stream import LiveFlows

V = "10.99.0.10"


def win(i, pps, payload=None, syn=0.0, slow=0, proto=None):
    return {"start": i, "end": i + 1, "dst": V, "packets": int(pps), "bytes": int(pps * 500), "pps": float(pps),
            "bps": pps * 4000.0, "unique_src": 100, "src_entropy": 6.6, "proto_mix": proto or {"tcp": 1.0},
            "tcp_flags": {"syn": syn, "psh": 0.2}, "syn_rate": syn * pps, "conn_rate": 10.0, "pkt_size": {"mean": 500},
            "top_talkers": [], "top_dst_ports": [], "tcp_payload": payload, "slow_conns": slow}


def kinds(ev):
    return [e["type"] for e in ev]


def test_flash_crowd_at_warning_rate_is_watched_not_alerted():
    st = LiveState()
    ev = st.ingest_window(win(0, 300, payload=0.4, syn=0.1), "t")  # real users: TCP with data
    assert kinds(ev) == ["live.window"] and ev[0]["window"]["l1"]["status"] == "WATCH"
    assert "looks like real users" in ev[0]["window"]["l1"]["rules"][0]


def test_warning_level_flood_without_benign_signals_still_alerts_and_critical_always_does():
    st = LiveState()
    assert "live.alert" in kinds(st.ingest_window(win(0, 300, payload=0.0, syn=0.9), "t"))
    st2 = LiveState()
    assert "live.alert" in kinds(st2.ingest_window(win(0, 1500, payload=0.4, syn=0.1), "t"))  # CRITICAL: never suppressed


def test_rate_that_is_normal_for_this_destination_is_watched_after_warm_up():
    st = LiveState()
    for i in range(25):  # a busy server's normal rate (no payload info, e.g. UDP service)
        st.ingest_window(win(i, 150 + (i % 3), proto={"udp": 1.0}), "t")
    ev = st.ingest_window(win(30, 155, proto={"udp": 1.0}), "t")
    assert ev[0]["window"]["l1"]["status"] == "WATCH" and "normal for this destination" in ev[0]["window"]["l1"]["rules"][0]
    assert "live.alert" in kinds(st.ingest_window(win(31, 450, proto={"udp": 1.0}), "t"))  # 3x its baseline: alert


def test_slow_connections_open_an_l7_alert():
    st = LiveState()
    ev = st.ingest_window(win(0, 25, payload=1.0, slow=150), "t")
    ep = [e for e in ev if e["type"] == "live.alert"][0]["episode"]
    assert ep["vector"] == "Low-and-slow (L7)" and ep["explanation"]["attack_type"] == "Slowloris / low-and-slow HTTP (L7)"
    assert "150 established HTTP connections" in ep["explanation"]["reason"]


def p(ts, src, sport, flags, payload=0, dst=V, dport=80):
    return Packet(timestamp=ts, src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, protocol=6, payload_len=payload,
                  header_len=40, tcp_flags=flags)


def test_slow_counts_only_open_established_trickling_connections():
    lf = LiveFlows(idle_s=60)
    # slowloris: handshake answered, a few bytes every 9 s, never closed
    for c in range(3):
        src = f"10.99.0.{100 + c}"
        lf.add(p(0.0, src, 5000 + c, 0x02))
        lf.add(p(0.001, V, 80, 0x12, dst=src, dport=5000 + c))
        for k in range(4):
            lf.add(p(1 + 9 * k, src, 5000 + c, 0x18, payload=20))
    # benign: a full request/response, then FIN (closed)
    lf.add(p(0.0, "10.99.0.150", 6000, 0x02)); lf.add(p(0.001, V, 80, 0x12, dst="10.99.0.150", dport=6000))
    lf.add(p(0.002, "10.99.0.150", 6000, 0x18, payload=300)); lf.add(p(0.01, "10.99.0.150", 6000, 0x11))
    # half-open SYN that lingers: no reply
    lf.add(p(0.0, "10.99.0.160", 7000, 0x02)); lf.add(p(20.0, "10.99.0.160", 7000, 0x02))
    assert lf.slow_counts(now=40.0) == {V: 3}
