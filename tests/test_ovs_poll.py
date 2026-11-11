# -*- coding: utf-8 -*-
"""v5.2.0 OVS port-stats parsing (no OVS needed: sample outputs in both name and number forms)."""
from pathlib import Path

from lab.traffic.ovs_poll import parse_dump_ports, parse_show

SHOW = """OFPT_FEATURES_REPLY (xid=0x2): dpid:0000000000000001
n_tables:254, n_buffers:0
 1(s1-eth1): addr:aa:55:aa:55:00:14
     config:     0
 2(s1-eth2): addr:aa:55:aa:55:00:15
 LOCAL(s1): addr:42:51:a1:c4:97:45
"""

DUMP_NUMBERS = """OFPST_PORT reply (xid=0x4): 3 ports
  port LOCAL: rx pkts=0, bytes=0, drop=0, errs=0, frame=0, over=0, crc=0
           tx pkts=0, bytes=0, drop=0, errs=0, coll=0
  port  1: rx pkts=90123, bytes=3604920, drop=0, errs=0, frame=0, over=0, crc=0
           tx pkts=512, bytes=30720, drop=7, errs=0, coll=0
  port  2: rx pkts=?, bytes=?, drop=?, errs=?, frame=?, over=?, crc=?
           tx pkts=88000, bytes=3520000, drop=0, errs=0, coll=0
"""

DUMP_NAMES = """OFPST_PORT reply (OF1.3) (xid=0x2): 2 ports
  port  "s1-eth1": rx pkts=10, bytes=840, drop=0, errs=0, frame=0, over=0, crc=0
           tx pkts=12, bytes=1008, drop=0, errs=0, coll=0
           duration=10.512s
  port  "s1-eth2": rx pkts=3, bytes=180, drop=1, errs=0, frame=0, over=0, crc=0
           tx pkts=4, bytes=240, drop=0, errs=0, coll=0
"""


def test_show_maps_numbers_to_names():
    assert parse_show(SHOW) == {"1": "s1-eth1", "2": "s1-eth2", "LOCAL": "s1"}


def test_dump_ports_numbers_mapped_local_skipped_unknown_counters_zero():
    ports = parse_dump_ports(DUMP_NUMBERS, parse_show(SHOW), roles={"s1-eth1": "attacker"})
    assert [p["port"] for p in ports] == ["s1-eth1", "s1-eth2"]
    a, b = ports
    assert a == {"port": "s1-eth1", "host": "attacker", "rx_packets": 90123, "rx_bytes": 3604920, "rx_dropped": 0,
                 "tx_packets": 512, "tx_bytes": 30720, "tx_dropped": 7}
    assert b["rx_packets"] == 0 and b["tx_packets"] == 88000 and "host" not in b


def test_dump_ports_quoted_names_and_garbage():
    ports = parse_dump_ports(DUMP_NAMES)
    assert [(p["port"], p["rx_packets"], p["tx_packets"], p["rx_dropped"]) for p in ports] == [
        ("s1-eth1", 10, 12, 0), ("s1-eth2", 3, 4, 1)]
    assert parse_dump_ports("") == [] and parse_dump_ports("ovs-ofctl: s1 is not a bridge") == []


def test_live_demo_script_keeps_the_safety_checks():
    sh = (Path(__file__).resolve().parent.parent / "lab" / "live_demo.sh").read_text(encoding="utf-8")
    assert "--containment" in sh and "lab/KILL" in sh and "microsoft /proc/version" in sh and "id -u" in sh
    assert "lab.traffic.orchestrate" in sh  # the existing gated generator, nothing new
