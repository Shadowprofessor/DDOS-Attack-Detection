# -*- coding: utf-8 -*-
"""
Purple-team lab safety layer (v4.6.0). Every check here runs BEFORE anything is planned.

* Scope: `lab/lab_scope.yaml` is validated on load. Allowed networks must be private, at most
  a /16, and never loopback/link-local/multicast/reserved. Every host role must sit inside them.
* Targets: `check_target` refuses public (global) IPv4/IPv6 and any address outside the allowlist.
* Caps: packets/s, duration and concurrency are bounded by the scope.
* Kill switch: a file or env var. `KillSwitch.tripped()` is checked by the runner on every tick.
* Environment: refuses to run unless WSL2 *and* Mininet are detected (probes are injectable so CI
  can test the refusal paths without either).

This module only decides; it never touches the network.
"""
from __future__ import annotations

import ipaddress
import os
import shutil
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional

import yaml

REPO = Path(__file__).resolve().parent.parent
SCOPE_PATH = REPO / "lab" / "lab_scope.yaml"
MAX_PREFIX_BITS = 16  # an allowed network may be at most a /16 (IPv4) to keep the scope tight


class SafetyError(Exception):
    """A request falls outside the lab scope. Nothing was planned or sent."""


@dataclass(frozen=True)
class Caps:
    max_pps: int
    max_duration_s: int
    max_concurrent: int
    tick_s: float


@dataclass(frozen=True)
class LabScope:
    networks: tuple
    hosts: Dict[str, ipaddress.IPv4Address]
    caps: Caps
    kill_file: Path
    kill_env: str
    require_wsl2: bool
    require_mininet: bool


def _bad_kind(ip) -> Optional[str]:
    for attr, why in (("is_loopback", "loopback"), ("is_link_local", "link-local"), ("is_multicast", "multicast"),
                      ("is_unspecified", "unspecified"), ("is_reserved", "reserved")):
        if getattr(ip, attr):
            return why
    if ip.is_global or not ip.is_private:
        return "public / not private"
    return None


def _parse_network(text: str):
    try:
        net = ipaddress.ip_network(str(text), strict=True)
    except ValueError as e:
        raise SafetyError(f"invalid network {text!r}: {e}") from e
    if net.version != 4:
        raise SafetyError(f"network {net} refused: only IPv4 private lab ranges are allowed")
    if net.prefixlen < MAX_PREFIX_BITS:
        raise SafetyError(f"network {net} refused: larger than /{MAX_PREFIX_BITS}")
    why = _bad_kind(net.network_address) or _bad_kind(net.broadcast_address)
    if why:
        raise SafetyError(f"network {net} refused: {why}")
    return net


def load_scope(path: Path = SCOPE_PATH) -> LabScope:
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    nets = tuple(_parse_network(n) for n in data.get("allowed_networks") or [])
    if not nets:
        raise SafetyError("scope has no allowed_networks")
    caps_d = data.get("caps") or {}
    try:
        caps = Caps(max_pps=int(caps_d["max_pps"]), max_duration_s=int(caps_d["max_duration_s"]),
                    max_concurrent=int(caps_d["max_concurrent"]), tick_s=float(caps_d.get("tick_s", 1.0)))
    except (KeyError, TypeError, ValueError) as e:
        raise SafetyError(f"scope caps invalid: {e}") from e
    if not (0 < caps.max_pps <= 100_000 and 0 < caps.max_duration_s <= 3600 and 0 < caps.max_concurrent <= 4
            and 0 < caps.tick_s <= 5):
        raise SafetyError("scope caps out of bounds")
    hosts = {}
    for role, addr in (data.get("hosts") or {}).items():
        ip = ipaddress.ip_address(str(addr))
        if not any(ip in n for n in nets):
            raise SafetyError(f"host {role}={ip} is outside allowed_networks")
        hosts[str(role)] = ip
    ks = data.get("kill_switch") or {}
    env = data.get("environment") or {}
    return LabScope(networks=nets, hosts=hosts, caps=caps,
                    kill_file=(REPO / str(ks.get("file", "lab/KILL"))).resolve(),
                    kill_env=str(ks.get("env", "DDOS_LAB_KILL")),
                    require_wsl2=bool(env.get("require_wsl2", True)),
                    require_mininet=bool(env.get("require_mininet", True)))


def check_target(scope: LabScope, address: str):
    """Return the parsed address if it is an allowed lab target; raise SafetyError otherwise."""
    try:
        ip = ipaddress.ip_address(str(address).strip())
    except ValueError as e:
        raise SafetyError(f"target {address!r} is not an IP address") from e
    why = _bad_kind(ip)
    if why:
        raise SafetyError(f"target {ip} refused: {why}")
    if not any(ip.version == n.version and ip in n for n in scope.networks):
        raise SafetyError(f"target {ip} refused: not in allowed_networks")
    return ip


def check_profile(scope: LabScope, pps: float, duration_s: float, running: int = 0) -> None:
    c = scope.caps
    if not (0 < pps <= c.max_pps):
        raise SafetyError(f"rate {pps} pps refused: cap is {c.max_pps}")
    if not (0 < duration_s <= c.max_duration_s):
        raise SafetyError(f"duration {duration_s}s refused: cap is {c.max_duration_s}s")
    if running >= c.max_concurrent:
        raise SafetyError(f"{running} scenario(s) already running: cap is {c.max_concurrent}")


@dataclass
class KillSwitch:
    """Tripped if the kill file exists, the env var is truthy, or trip() was called (signal hook)."""

    file: Path
    env: str
    _flag: threading.Event = field(default_factory=threading.Event)

    @classmethod
    def from_scope(cls, scope: LabScope) -> "KillSwitch":
        return cls(file=scope.kill_file, env=scope.kill_env)

    def trip(self) -> None:
        self._flag.set()

    def tripped(self) -> bool:
        if self._flag.is_set() or self.file.exists():
            return True
        return os.environ.get(self.env, "").strip().lower() in ("1", "true", "yes", "on")


# ----------------------------------------------------------------------------- environment
@dataclass(frozen=True)
class EnvReport:
    wsl2: bool
    mininet: bool
    reasons: List[str]


def _read(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def default_probe() -> EnvReport:
    """Detect WSL2 (kernel string) and Mininet (installed `mn` + a Mininet-style hN-ethX interface)."""
    reasons = []
    version = _read("/proc/version").lower()
    wsl2 = "microsoft" in version and "wsl2" in version
    if not wsl2:
        reasons.append("not running under WSL2 (/proc/version)")
    has_mn = shutil.which("mn") is not None
    ifaces = []
    try:
        ifaces = os.listdir("/sys/class/net")
    except OSError:
        pass
    mn_iface = any(i.startswith("h") and "-eth" in i for i in ifaces)
    mininet = has_mn and mn_iface
    if not mininet:
        reasons.append("Mininet not detected (need `mn` on PATH and an hN-ethX interface)")
    return EnvReport(wsl2=wsl2, mininet=mininet, reasons=reasons)


def require_lab_environment(scope: LabScope, probe: Callable[[], EnvReport] = default_probe) -> EnvReport:
    rep = probe()
    missing = []
    if scope.require_wsl2 and not rep.wsl2:
        missing.append("WSL2")
    if scope.require_mininet and not rep.mininet:
        missing.append("Mininet")
    if missing:
        raise SafetyError(f"refusing to run outside the lab ({', '.join(missing)} not detected): " + "; ".join(rep.reasons))
    return rep
