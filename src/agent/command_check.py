# -*- coding: utf-8 -*-
"""Check the settings and flags an LLM answer mentions (v5.3.0).

In v5.2.0 Lightning invented a kernel setting (`net.ipv4.tcp_syn_retries2`). Before an answer is
shown, three kinds of names are checked:

* **sysctl keys** (`net.ipv4.tcp_syncookies`, ...) against a curated list of real Linux keys
  (Documentation/networking/ip-sysctl.rst and friends);
* **this repo's settings** (`DDOS_*`, `NEMOTRON_*`) against the names the code actually reads;
* **this repo's CLI flags** (`scripts/live_bridge.py --reset`, `lab.traffic.orchestrate --gap`) against
  each script's own `add_argument(...)` calls.

Names that pass are "verified"; the rest are "unverified - check before running". This checks
names, not whether a command is a good idea; every command stays a recommendation for a human.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Dict, List

REPO = Path(__file__).resolve().parent.parent.parent

# Real sysctl keys (final component), grouped by prefix. "conf" keys take any interface name.
_SYSCTL = {
    "net.ipv4": {"tcp_syncookies", "tcp_max_syn_backlog", "tcp_synack_retries", "tcp_syn_retries", "tcp_fin_timeout",
                 "tcp_tw_reuse", "tcp_max_tw_buckets", "tcp_keepalive_time", "tcp_keepalive_intvl",
                 "tcp_keepalive_probes", "tcp_rfc1337", "tcp_abort_on_overflow", "tcp_rmem", "tcp_wmem", "tcp_mem",
                 "tcp_timestamps", "tcp_sack", "tcp_challenge_ack_limit", "tcp_invalid_ratelimit", "ip_forward",
                 "ip_local_port_range", "icmp_echo_ignore_all", "icmp_echo_ignore_broadcasts",
                 "icmp_ignore_bogus_error_responses", "icmp_ratelimit", "icmp_ratemask", "tcp_orphan_retries",
                 "tcp_max_orphans", "ip_default_ttl"},
    "net.ipv4.conf": {"rp_filter", "accept_source_route", "accept_redirects", "secure_redirects", "send_redirects",
                      "log_martians", "arp_ignore", "arp_announce", "forwarding"},
    "net.ipv6.conf": {"disable_ipv6", "accept_ra", "accept_redirects", "accept_source_route", "forwarding"},
    "net.core": {"somaxconn", "netdev_max_backlog", "rmem_max", "wmem_max", "rmem_default", "wmem_default",
                 "optmem_max", "bpf_jit_enable", "netdev_budget"},
    "net.netfilter": {"nf_conntrack_max", "nf_conntrack_buckets", "nf_conntrack_tcp_timeout_established",
                      "nf_conntrack_tcp_timeout_syn_recv", "nf_conntrack_tcp_timeout_syn_sent",
                      "nf_conntrack_tcp_loose", "nf_conntrack_udp_timeout", "nf_conntrack_icmp_timeout"},
    "kernel": {"randomize_va_space", "kptr_restrict", "dmesg_restrict"},
}
SYSCTL_RE = re.compile(r"\b(?:net|kernel)\.[a-z0-9_]+(?:\.[a-z0-9_*-]+)+\b")
SETTING_RE = re.compile(r"\b(?:DDOS|NEMOTRON)_[A-Z0-9_]+\b")
SCRIPT_RE = re.compile(r"(scripts/[a-z0-9_]+\.py|lab/[a-z0-9_/]+\.(?:py|sh)|-m\s+(?:lab|src|scripts)\.[a-z0-9_.]+)")
FLAG_RE = re.compile(r"(?<![\w-])--[a-z][a-z0-9-]*")


def sysctl_ok(key: str) -> bool:
    parts = key.split(".")
    if len(parts) >= 5 and parts[1] in ("ipv4", "ipv6") and parts[2] == "conf":
        return parts[4] in _SYSCTL.get(f"net.{parts[1]}.conf", set())  # net.ipv4.conf.<if>.<key>
    return parts[-1] in _SYSCTL.get(".".join(parts[:-1]), set())


@lru_cache(maxsize=1)
def repo_settings() -> frozenset:
    """Every DDOS_*/NEMOTRON_* name that appears in the code or config (what the platform reads)."""
    names = set()
    for base in ("src", "scripts", "lab", "config"):
        for p in (REPO / base).rglob("*"):
            if p.suffix in (".py", ".yaml", ".yml", ".sh") and p.is_file():
                names.update(SETTING_RE.findall(p.read_text(encoding="utf-8", errors="ignore")))
    return frozenset(names)


def _script_path(ref: str) -> Path:
    if ref.startswith("-m"):
        mod = ref.split()[-1]
        return REPO / (mod.replace(".", "/") + ".py")
    return REPO / ref


@lru_cache(maxsize=64)
def script_flags(path: str) -> frozenset:
    p = Path(path)
    if not p.is_file():
        return frozenset()
    text = p.read_text(encoding="utf-8", errors="ignore")
    flags = set(re.findall(r"""add_argument\(\s*["'](--[a-z0-9-]+)["']""", text))
    flags.update(re.findall(r"(?<![\w-])(--[a-z][a-z0-9-]*)", text) if p.suffix == ".sh" else [])
    return frozenset(flags | {"--help"})


def check(text: str) -> Dict[str, List[str]]:
    verified, unverified = set(), set()
    for key in SYSCTL_RE.findall(text):
        key = key.rstrip(".")
        (verified if sysctl_ok(key) else unverified).add(key)
    known = repo_settings()
    for name in SETTING_RE.findall(text):
        (verified if name in known else unverified).add(name)
    for line in text.splitlines():
        m = SCRIPT_RE.search(line)
        if not m:
            continue
        path = _script_path(m.group(1))
        if not path.is_file():
            unverified.add(m.group(1))
            continue
        allowed = script_flags(str(path))
        for flag in FLAG_RE.findall(line[m.end():]):
            label = f"{m.group(1)} {flag}"
            (verified if flag in allowed else unverified).add(label)
    return {"verified": sorted(verified), "unverified": sorted(unverified)}


def annotate(text: str) -> tuple:
    """(text with a short check note appended, check result)."""
    res = check(text)
    notes = []
    if res["unverified"]:
        notes.append("⚠ Unverified — check before running: " + ", ".join(f"`{x}`" for x in res["unverified"]))
    if res["verified"]:
        notes.append("✓ Names checked against real settings / this repo: " + ", ".join(f"`{x}`" for x in res["verified"]))
    if notes:
        text = text.rstrip() + "\n\n" + "\n".join(notes)
    return text, res
