# -*- coding: utf-8 -*-
"""Windows side of the live demo (v5.2.0): tail the lab pcaps and feed the running SOC platform.

    python scripts/live_bridge.py data/lab_runs/live1            # API at http://127.0.0.1:8000

The key is read from DDOS_LIVE_KEY, else the first key in DDOS_API_KEYS (never from the repo).
Only the platform's public API is used. Events and timings go to <run>/live_bridge.jsonl, which
`scripts/live_mttd.py` turns into the real-time MTTD table. Stop with Ctrl+C.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from src.live.bridge import Bridge, RequestsHttp  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description="Lab pcaps -> SOC platform, live")
    ap.add_argument("run_dir")
    ap.add_argument("--api", default=os.environ.get("DDOS_API_URL", "http://127.0.0.1:8000"))
    ap.add_argument("--sensor", default="lab-bridge")
    ap.add_argument("--flows-per-s", type=float, default=1.5,
                    help="flows sent to /score/flow per second (its default limit is 120/min per key)")
    ap.add_argument("--victim", action="append", help="only report these destination IPs (repeatable)")
    ap.add_argument("--from-start", action="store_true", help="also read pcaps already in the directory")
    ap.add_argument("--no-incidents", action="store_true", help="do not open incidents for L1 alerts")
    ap.add_argument("--duration", type=float, default=None, help="stop after N seconds")
    ap.add_argument("--reset", action="store_true", help="clear the live view before starting")
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    key = os.environ.get("DDOS_LIVE_KEY") or (os.environ.get("DDOS_API_KEYS") or "").split(",")[0].strip()
    if not key:
        raise SystemExit("set DDOS_LIVE_KEY or DDOS_API_KEYS to an analyst key")
    run = Path(args.run_dir)
    run.mkdir(parents=True, exist_ok=True)
    http = RequestsHttp(args.api, key)
    status, health = http.get("/health")
    if status != 200:
        raise SystemExit(f"platform not reachable at {args.api} (status {status}); start uvicorn first")
    print(f"platform {args.api}: {health}")
    if args.reset:
        http.post("/api/live/reset")
    b = Bridge(run, http, sensor=args.sensor, flows_per_s=args.flows_per_s, from_start=args.from_start,
               victims=set(args.victim) if args.victim else None, open_incidents=not args.no_incidents)
    print(f"watching {run} for *.pcap and ovs_ports.jsonl; log -> {b.log_path}")
    try:
        b.run(duration_s=args.duration)
    except KeyboardInterrupt:
        pass
    print("stats:", dict(b.stats))


if __name__ == "__main__":
    main()
