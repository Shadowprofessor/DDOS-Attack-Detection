# -*- coding: utf-8 -*-
"""LAB-ONLY OVS port-stats poller (v5.2.0). Runs inside WSL2 as root, next to the orchestrator.

Every `interval_s` it runs `ovs-ofctl dump-ports <switch>` (read-only: it changes nothing on the
switch) and appends one JSON line to `<run>/ovs_ports.jsonl`. The Windows bridge forwards those
lines to the platform. Counters cross over on the shared disk, so no WSL2 -> Windows network path
is needed. Port numbers are mapped to names (s1-eth1 ...) via `ovs-ofctl show` and to lab host roles
via the orchestrator's link map.
"""
from __future__ import annotations

import json
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

PORT_RE = re.compile(r'^\s*port\s+(?:"([^"]+)"|(\S+?)):\s*rx\s+(.*)$')
TX_RE = re.compile(r"^\s*tx\s+(.*)$")
SHOW_RE = re.compile(r"^\s*(\d+|LOCAL)\(([^)]+)\):")


def _kv(text: str) -> Dict[str, int]:
    out = {}
    for k, v in re.findall(r"(\w+)=([^,\s]+)", text):
        out[k] = int(v) if v.isdigit() else 0  # OVS prints "?" for unsupported counters
    return out


def parse_show(text: str) -> Dict[str, str]:
    """`ovs-ofctl show` -> {port number: port name}."""
    return {m.group(1): m.group(2) for m in (SHOW_RE.match(line) for line in text.splitlines()) if m}


def parse_dump_ports(text: str, names: Optional[Dict[str, str]] = None, roles: Optional[Dict[str, str]] = None) -> List[dict]:
    """`ovs-ofctl dump-ports` -> [{port, rx_packets, tx_packets, rx_bytes, tx_bytes, rx_dropped, tx_dropped}].
    The switch's LOCAL port is skipped (not a lab link)."""
    names, roles = names or {}, roles or {}
    ports, cur = [], None
    for line in text.splitlines():
        m = PORT_RE.match(line)
        if m:
            raw = m.group(1) or m.group(2)
            cur = None
            if raw.upper() == "LOCAL":
                continue
            name = names.get(raw, raw)
            rx = _kv(m.group(3))
            cur = {"port": name[:16], "rx_packets": rx.get("pkts", 0), "rx_bytes": rx.get("bytes", 0),
                   "rx_dropped": rx.get("drop", 0), "tx_packets": 0, "tx_bytes": 0, "tx_dropped": 0}
            if name in roles:
                cur["host"] = roles[name]
            ports.append(cur)
            continue
        t = TX_RE.match(line)
        if t and cur is not None:
            tx = _kv(t.group(1))
            cur.update(tx_packets=tx.get("pkts", 0), tx_bytes=tx.get("bytes", 0), tx_dropped=tx.get("drop", 0))
            cur = None
    return ports


def _run(args: List[str]) -> str:  # pragma: no cover - needs OVS + root
    return subprocess.run(args, capture_output=True, text=True, timeout=5, check=False).stdout


class OvsPoller:  # pragma: no cover - needs OVS + root; parsing is unit-tested
    def __init__(self, out: Path, switch: str = "s1", interval_s: float = 2.0,
                 roles: Optional[Dict[str, str]] = None, run: Callable[[List[str]], str] = _run):
        self.path, self.switch, self.interval_s = Path(out) / "ovs_ports.jsonl", switch, interval_s
        self.roles, self.run = roles or {}, run
        self._stop = threading.Event()
        self._t: Optional[threading.Thread] = None

    def start(self) -> None:
        self._t = threading.Thread(target=self._loop, name="ovs-poll", daemon=True)
        self._t.start()

    def stop(self) -> None:
        self._stop.set()
        if self._t:
            self._t.join(timeout=5)

    def _loop(self) -> None:
        names = parse_show(self.run(["ovs-ofctl", "show", self.switch]))
        first = True
        while not self._stop.is_set():
            raw = self.run(["ovs-ofctl", "dump-ports", self.switch])
            ts = time.time()
            ports = parse_dump_ports(raw, names, self.roles)
            if first:  # keep the raw text once so the parser can be checked against this OVS version
                (self.path.parent / "ovs_dump_ports_sample.txt").write_text(raw)
                first = False
            if ports:
                with self.path.open("a", encoding="utf-8") as fh:
                    fh.write(json.dumps({"switch": self.switch, "ts": ts, "ports": ports}) + "\n")
            self._stop.wait(self.interval_s)
