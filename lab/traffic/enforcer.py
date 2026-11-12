# -*- coding: utf-8 -*-
"""LAB-ONLY containment enforcer (v5.4.0). Runs as root inside WSL2, next to a live demo run:

    sudo python3 -m lab.traffic.enforcer --run data/lab_runs/live3

It applies ONLY actions a human admin already approved on the SOC website
(`PendingActionManager.approve()`). The Windows bridge copies the platform's approved-action queue to
`<run>/enforce_queue.jsonl`; this process reads it, re-checks every target, installs an OVS drop rule
on the Mininet switch and writes what happened to `<run>/enforce_status.jsonl` (the bridge reports it
back). No network path from WSL2 to the platform is needed.

Safety (all enforced here, again, whatever the queue says):
* target inside lab_scope.yaml; never the victim, the NAT/management address or a broadcast;
  port drops only on attacker / reflector / client ports, never the victim's;
* every rule has `hard_timeout = TTL` (30-3600 s): OVS removes it by itself;
* every rule carries a cookie with the 0x5AB0 prefix; the kill switch (`lab/KILL`) deletes all of
  them (and only them) and stops the enforcer;
* every action is logged to `<run>/enforcer_log.jsonl`;
* refuses to start outside WSL2 or without root.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

from lab.containment import COOKIE_PREFIX, clamp_ttl, cookie_for, validate_target

ALL_OURS = f"cookie={hex(COOKIE_PREFIX << 48)}/{hex(0xFFFF << 48)}"


class Refused(ValueError):
    pass


def build_rule(entry: dict, port_numbers: Dict[str, str], role_ports: Dict[str, str], scope=None) -> dict:
    """Validated OVS rule for one approved queue entry (pure: no OVS needed). Raises Refused."""
    kind, target, aid = entry.get("action_type"), str(entry.get("target", "")), str(entry.get("action_id", ""))
    ok, why = validate_target(kind, target, scope)
    if not ok:
        raise Refused(why)
    cookie = cookie_for(aid)
    if entry.get("cookie") and int(str(entry["cookie"]), 16) != cookie:
        raise Refused("cookie does not match the action id")
    ttl = clamp_ttl(entry.get("ttl_s"))
    if kind == "LAB_OVS_PORT_DROP":
        port_name = next((p for p, role in role_ports.items() if role == target), None)
        if port_name is None or port_name not in port_numbers:
            raise Refused(f"no switch port known for lab host '{target}'")
        if role_ports.get(port_name) == "victim":
            raise Refused("refusing to drop the victim's port")
        match = f"in_port={port_numbers[port_name]}"
    else:
        match = f"ip,nw_src={target}"
    flow = f"cookie={hex(cookie)},priority=200,{match},hard_timeout={ttl},actions=drop"
    return {"action_id": aid, "cookie": cookie, "ttl_s": ttl, "match": match, "flow": flow, "why": why}


def _run(args: List[str]) -> subprocess.CompletedProcess:  # pragma: no cover - needs OVS + root
    return subprocess.run(args, capture_output=True, text=True, timeout=10, check=False)


class Enforcer:
    def __init__(self, run_dir: Path, switch: str = "s1", run: Callable = _run, clock: Callable[[], float] = time.time,
                 kill_file: Optional[Path] = None, scope=None):
        self.run_dir, self.switch, self.run, self.clock, self.scope = Path(run_dir), switch, run, clock, scope
        self.kill_file = kill_file or Path(__file__).resolve().parent.parent / "KILL"
        self.queue_path = self.run_dir / "enforce_queue.jsonl"
        self.status_path = self.run_dir / "enforce_status.jsonl"
        self.log_path = self.run_dir / "enforcer_log.jsonl"
        self.offset = 0
        self.done: set = set()        # (action_id, op) already handled
        self.active: Dict[str, dict] = {}  # action_id -> rule (applied, not yet expired/removed)
        self._ports: Optional[Dict[str, str]] = None

    def _log(self, path: Path, rec: dict) -> None:
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"t": self.clock(), **rec}) + "\n")

    def report(self, aid: str, state: str, detail: str) -> None:
        self._log(self.status_path, {"action_id": aid, "state": state, "detail": detail[:300], "ts": self.clock()})
        self._log(self.log_path, {"event": state, "action_id": aid, "detail": detail[:300]})

    def port_numbers(self) -> Dict[str, str]:
        if not self._ports:  # retry until the switch exists (the enforcer may start before Mininet)
            from lab.traffic.ovs_poll import parse_show

            self._ports = {name: num for num, name in parse_show(self.run(["ovs-ofctl", "show", self.switch]).stdout).items()}
        return self._ports

    def role_ports(self) -> Dict[str, str]:
        mf = self.run_dir / "manifest.json"
        try:
            return json.loads(mf.read_text()).get("switch_ports") or {}
        except (OSError, ValueError):
            return {}

    def read_queue(self) -> List[dict]:
        if not self.queue_path.exists():
            return []
        with self.queue_path.open("rb") as fh:
            fh.seek(self.offset)
            chunk = fh.read()
        end = chunk.rfind(b"\n")
        if end < 0:
            return []
        self.offset += end + 1
        out = []
        for line in chunk[:end].splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    def kill_all(self, why: str) -> None:
        r = self.run(["ovs-ofctl", "del-flows", self.switch, ALL_OURS])
        self._log(self.log_path, {"event": "kill_switch", "detail": why, "rc": r.returncode})
        for aid in list(self.active):
            self.report(aid, "removed", f"kill switch: {why}")
            del self.active[aid]

    def apply(self, entry: dict) -> None:
        aid = str(entry.get("action_id"))
        try:
            rule = build_rule(entry, self.port_numbers() if entry.get("action_type") == "LAB_OVS_PORT_DROP" else {},
                              self.role_ports(), self.scope)
        except Refused as e:
            self.report(aid, "refused", str(e))
            return
        r = self.run(["ovs-ofctl", "add-flow", self.switch, rule["flow"]])
        if r.returncode != 0:
            self.report(aid, "failed", f"ovs-ofctl add-flow rc={r.returncode}: {(r.stderr or '')[:200]}")
            return
        rule["applied_at"] = self.clock()
        self.active[aid] = rule
        self.report(aid, "applied", f"{rule['flow']} ({rule['why']})")

    def remove(self, entry: dict) -> None:
        aid = str(entry.get("action_id"))
        rule = self.active.pop(aid, None)
        cookie = rule["cookie"] if rule else cookie_for(aid)
        r = self.run(["ovs-ofctl", "del-flows", self.switch, f"cookie={hex(cookie)}/-1"])
        self.report(aid, "removed" if r.returncode == 0 else "failed", f"del-flows cookie={hex(cookie)} rc={r.returncode}")

    def expire(self) -> None:
        now = self.clock()
        for aid, rule in list(self.active.items()):
            if now >= rule["applied_at"] + rule["ttl_s"] + 1:
                self.report(aid, "expired", f"hard_timeout {rule['ttl_s']} s reached; OVS removed the rule")
                del self.active[aid]

    def tick(self) -> bool:
        """One pass. Returns False when the kill switch stopped the enforcer."""
        if self.kill_file.exists() or os.environ.get("DDOS_LAB_KILL") == "1":
            self.kill_all("lab/KILL present")
            return False
        for entry in self.read_queue():
            key = (entry.get("action_id"), entry.get("op"))
            if key in self.done:
                continue
            self.done.add(key)
            (self.remove if entry.get("op") == "remove" else self.apply)(entry)
        self.expire()
        return True


def main() -> None:  # pragma: no cover - needs root + OVS
    ap = argparse.ArgumentParser(description="LAB-ONLY enforcer: applies human-approved OVS drop rules")
    ap.add_argument("--run", required=True, help="the live run directory the bridge relays into")
    ap.add_argument("--switch", default="s1")
    args = ap.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("run with sudo inside WSL2")
    if "microsoft" not in Path("/proc/version").read_text().lower():
        raise SystemExit("refusing: not WSL2")
    run = Path(args.run)
    run.mkdir(parents=True, exist_ok=True)
    import signal

    def _stop(signum, frame):  # SIGTERM from lab/live_demo.sh's trap: run the cleanup below
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, _stop)
    e = Enforcer(run, switch=args.switch)
    print(f"enforcer watching {e.queue_path} (kill switch: {e.kill_file})", flush=True)
    try:
        while e.tick():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        e.kill_all("enforcer stopped")  # never leave our rules behind
        print("enforcer stopped; all lab rules removed", flush=True)


if __name__ == "__main__":  # pragma: no cover
    main()
