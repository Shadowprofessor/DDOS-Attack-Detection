# -*- coding: utf-8 -*-
"""Re-write recorded lab pcaps into a *growing* pcap at real-time pace (v5.2.0 test aid).

    python scripts/pcap_replay_live.py data/lab_runs/run2/syn_flood.pcap data/lab_runs/run3/icmp_flood.pcap \
        --out data/lab_runs/replay1 --gap 15 --limit-s 30

It only writes files, the way `tcpdump -U` does during a live run: no packet is sent anywhere.
Timestamps are shifted to "now", so the live bridge sees them as fresh. A manifest.json with each
scenario's start/end is written as well, so `scripts/live_mttd.py` works on replays too (label them
as replays when reporting: the traffic is recorded, only the timing is live).
"""
from __future__ import annotations

import argparse
import json
import struct
import time
from pathlib import Path

from_rec = struct.Struct("<IIII")


def records(path: Path):
    raw = path.read_bytes()
    if raw[:4] != b"\xd4\xc3\xb2\xa1":
        raise SystemExit(f"{path}: only little-endian microsecond pcaps are supported")
    off = 24
    while off + 16 <= len(raw):
        sec, usec, incl, orig = from_rec.unpack_from(raw, off)
        yield sec + usec / 1e6, raw[off + 16:off + 16 + incl], orig
        off += 16 + incl


def replay(src: Path, out: Path, limit_s: float, speed: float = 1.0) -> dict:
    raw = src.read_bytes()
    dest = out / src.name
    first = None
    t_wall0 = time.time()
    with dest.open("wb") as fh:
        fh.write(raw[:24])
        fh.flush()
        for ts, data, orig in records(src):
            if first is None:
                first = ts
            rel = (ts - first) / speed
            if rel > limit_s:
                break
            delay = t_wall0 + rel - time.time()
            if delay > 0:
                time.sleep(delay)
            new = t_wall0 + rel
            fh.write(from_rec.pack(int(new), int(round((new % 1) * 1e6)) % 1_000_000, len(data), orig) + data)
            fh.flush()
    return {"scenario": src.stem, "pcap": dest.name, "started_at": t_wall0, "ended_at": time.time(),
            "replayed_from": str(src)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcaps", nargs="+")
    ap.add_argument("--out", required=True)
    ap.add_argument("--gap", type=float, default=15.0)
    ap.add_argument("--limit-s", type=float, default=30.0, help="replay at most this many seconds of each pcap")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    manifest = {"replay": True, "runs": []}
    for i, p in enumerate(a.pcaps):
        if i:
            time.sleep(a.gap)
        r = replay(Path(p), out, a.limit_s)
        manifest["runs"].append(r)
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
        print(r["scenario"], "done", round(r["ended_at"] - r["started_at"], 1), "s", flush=True)


if __name__ == "__main__":
    main()
