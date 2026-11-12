"""v6.1.0: the replay re-writes the run's OVS samples time-shifted exactly like its packets."""
import importlib.util
import json
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _mod():
    spec = importlib.util.spec_from_file_location("pcap_replay_live", ROOT / "scripts" / "pcap_replay_live.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def test_ovs_samples_replay_in_step_with_the_packets(tmp_path):
    t0 = 1000.0
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    recs = b"".join(struct.pack("<IIII", int(t0 + dt), int(round((dt % 1) * 1e6)), 4, 4) + b"\x00" * 4 for dt in (0.0, 0.2, 0.4))
    src = tmp_path / "syn.pcap"
    src.write_bytes(hdr + recs)
    rows = [{"switch": "s1", "ts": t0 - 10, "ports": []},   # too early: dropped
            {"switch": "s1", "ts": t0 - 1, "ports": []},    # baseline just before the capture
            {"switch": "s1", "ts": t0 + 0.3, "ports": []},
            {"switch": "s1", "ts": t0 + 0.5, "ports": []},  # after the last packet, within the limit
            {"switch": "s1", "ts": t0 + 9, "ports": []}]    # beyond the limit: dropped
    out = tmp_path / "out"
    out.mkdir()
    r = _mod().replay(src, out, limit_s=0.6, ovs_rows=rows)
    got = [json.loads(x)["ts"] for x in (out / "ovs_ports.jsonl").read_text().splitlines()]
    shift = r["started_at"] - t0
    assert [round(g - shift, 3) for g in got] == [999.0, 1000.3, 1000.5]
    assert (out / "syn.pcap").stat().st_size == src.stat().st_size
