# -*- coding: utf-8 -*-
"""v5.2.0 live sensor: growing-pcap reader, 1 s windows, live flow snapshots (no scapy, no network)."""
import struct

from src.live.pcap import PcapFormatError, PcapTail, parse_frame
from src.live.stream import LiveFlows, WindowAggregator, with_features

import pytest

ETH = b"\x00" * 12 + b"\x08\x00"


def ip(src, dst, proto, l4, payload=b""):
    total = 20 + len(l4) + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, proto, 0,
                      bytes(int(x) for x in src.split(".")), bytes(int(x) for x in dst.split(".")))
    return hdr + l4 + payload


def tcp(sport, dport, flags, payload=b""):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 8192, 0, 0), payload


def frame(src, dst, proto=6, sport=1234, dport=443, flags=0x02, payload=b""):
    if proto == 6:
        l4, pl = tcp(sport, dport, flags, payload)
    elif proto == 17:
        l4, pl = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0), payload
    else:
        l4, pl = struct.pack("!BBHHH", 8, 0, 0, 0, 0), payload
    return ETH + ip(src, dst, proto, l4, pl)


def global_header():
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)


def record(ts, data, snap=160):
    cut = data[:snap]
    return struct.pack("<IIII", int(ts), int(round((ts % 1) * 1e6)), len(cut), len(data)) + cut


def test_parse_frame_lengths_come_from_ip_header_not_snaplen():
    data = frame("10.99.0.100", "10.99.0.10", payload=b"x" * 500)
    p = parse_frame(1.0, data[:60], 1)  # truncated capture
    assert (p.src_ip, p.dst_ip, p.dst_port, p.protocol) == ("10.99.0.100", "10.99.0.10", 443, 6)
    assert p.payload_len == 500 and p.header_len == 40 and p.tcp_flags == 0x02
    u = parse_frame(1.0, frame("10.99.0.5", "10.99.0.10", proto=17, sport=123, dport=5000, payload=b"y" * 40), 1)
    assert u.protocol == 17 and u.src_port == 123 and u.payload_len == 40
    i = parse_frame(1.0, frame("10.99.0.5", "10.99.0.10", proto=1), 1)
    assert i.protocol == 1 and i.dst_port == 0
    assert parse_frame(1.0, b"\x00" * 12 + b"\x86\xdd" + b"\x00" * 40, 1) is None  # IPv6 ignored


def test_tail_reads_only_complete_records_of_a_growing_file(tmp_path):
    p = tmp_path / "x.pcap"
    r1 = record(100.25, frame("10.99.0.100", "10.99.0.10"))
    r2 = record(100.5, frame("10.99.0.101", "10.99.0.10"))
    p.write_bytes(global_header()[:10])  # tcpdump has not finished the header yet
    t = PcapTail(p)
    assert t.read() == []
    p.write_bytes(global_header() + r1 + r2[:20])  # second record torn mid-body
    got = t.read()
    assert len(got) == 1 and got[0].timestamp == pytest.approx(100.25)
    with p.open("ab") as fh:
        fh.write(r2[20:])
    got = t.read()
    assert len(got) == 1 and got[0].src_ip == "10.99.0.101" and t.packets_read == 2
    assert t.read() == []


def test_tail_missing_file_and_pcapng(tmp_path):
    assert PcapTail(tmp_path / "nope.pcap").read() == []
    ng = tmp_path / "ng.pcap"
    ng.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
    with pytest.raises(PcapFormatError):
        PcapTail(ng).read()


def pkt(ts, src="10.99.0.100", dst="10.99.0.10", proto=6, flags=0x02, sport=1000, dport=443, payload=b""):
    return parse_frame(ts, frame(src, dst, proto=proto, sport=sport, dport=dport, flags=flags, payload=payload), 1)


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def test_windows_per_destination_with_rates_mix_and_top_talkers():
    clk = Clock(1000.0)
    w = WindowAggregator(clock=clk, grace_s=2.0)
    for i in range(300):  # 300 SYNs from 30 sources in [1000, 1001)
        w.add(pkt(1000 + i / 300, src=f"10.99.0.{100 + i % 30}", sport=2000 + i))
    for i in range(5):  # victim answers
        w.add(pkt(1000.5, src="10.99.0.10", dst="10.99.0.100", flags=0x12, sport=443, dport=2000 + i))
    w.add(pkt(1001.2, src="10.99.0.100", flags=0x10))  # next window: one ACK
    out = w.emit()
    v = [x for x in out if x["dst"] == "10.99.0.10"]
    assert len(v) == 1 and v[0]["start"] == 1000.0
    x = v[0]
    assert x["pps"] == 300 and x["unique_src"] == 30 and x["proto_mix"] == {"tcp": 1.0}
    assert x["tcp_flags"]["syn"] == 1.0 and x["syn_rate"] == 300 and x["conn_rate"] == 300
    assert abs(x["src_entropy"] - 4.9069) < 1e-3 and len(x["top_talkers"]) == 5
    assert x["top_dst_ports"][0] == {"port": 443, "packets": 300} and x["bytes"] == 300 * 40
    assert any(o["dst"] == "10.99.0.100" for o in out)  # replies are windows too


def test_quiet_victim_gets_zero_windows_from_the_wall_clock_and_late_packets_are_dropped():
    clk = Clock(1000.4)
    w = WindowAggregator(clock=clk, grace_s=2.0, idle_dst_s=3.0)
    w.add(pkt(1000.1))
    assert w.emit() == []  # window [1000,1001) still open
    clk.t = 1004.5  # no packets; wall clock moves on (learned skew 0.3 s + grace 2 s)
    out = w.emit()
    assert [(o["start"], o["packets"]) for o in out] == [(1000.0, 1), (1001.0, 0)]
    w.add(pkt(1000.9))  # arrives after its window was sent: dropped
    clk.t = 1010.0
    later = w.emit()
    assert [o["start"] for o in later] == [1002.0, 1003.0] and all(o["packets"] == 0 for o in later)  # idle_dst_s
    clk.t = 1020.0
    assert w.emit() == []


def test_wsl_clock_behind_windows_does_not_close_windows_early():
    clk = Clock(5000.0)  # Windows wall clock 4000 s ahead of the packet clock
    w = WindowAggregator(clock=clk, grace_s=2.0)
    w.add(pkt(1000.2))
    clk.t = 5000.5
    assert w.emit() == []  # without skew handling this would close everything immediately
    w.add(pkt(1000.7))
    clk.t = 5003.5
    out = w.emit()
    assert out[0]["start"] == 1000.0 and out[0]["packets"] == 2


def test_live_flows_snapshot_long_flows_while_running_and_finalise_idle_ones():
    lf = LiveFlows(export_s=5.0, idle_s=15.0)
    snaps = []
    for i in range(60):  # one ICMP "flow" lasting 30 s, polled once per second as the bridge does
        t = 1000 + i * 0.5
        lf.add(pkt(t, proto=1))
        if i % 2 == 0:
            snaps += lf.poll(t)
    assert [s["final"] for s in snaps] == [False] * 5 and all(s["proto"] == 1 for s in snaps)
    durations = [with_features(s)["features"]["Flow Duration"] for s in snaps]
    assert durations == sorted(durations) and durations[-1] >= 25e6  # one growing flow, not split
    assert lf.poll(1029.0) == []  # last snapshot at 1025: < 5 s ago
    final = lf.poll(1050.0)
    assert len(final) == 1 and final[0]["final"] is True and final[0]["packets"] == 60
    assert "flow" not in with_features(final[0])
    assert lf.ex.active_flow_count == 0


def test_flow_record_direction_is_the_initiator():
    lf = LiveFlows()
    lf.add(pkt(1.0, src="10.99.0.100", dst="10.99.0.10", sport=40000, dport=443))
    lf.add(pkt(1.0001, src="10.99.0.10", dst="10.99.0.100", sport=443, dport=40000, flags=0x12))
    lf.add(pkt(2.0, src="10.99.0.101", sport=40001))  # a short flow: no snapshot, only the idle export
    assert lf.poll(8.0) == []
    (r, _) = lf.flush()
    assert (r["src"], r["dst"], r["sport"], r["dport"], r["packets"]) == ("10.99.0.100", "10.99.0.10", 40000, 443, 2)
