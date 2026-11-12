# -*- coding: utf-8 -*-
"""LAB-ONLY containment rules (v5.4.0): the single definition of what may be blocked in the lab.

Pure (no networking, no processes, no src/ imports) so both the platform
(`src/mitigation/lab_containment.py`) and the WSL2 enforcer (`lab/traffic/enforcer.py`) use it.

Human-approved OVS drop rules on the Mininet switch:

Two action types, both PROPOSED like every other mitigation and applied only after an admin's
`PendingActionManager.approve()`:

* ``LAB_OVS_DROP``      - drop IPv4 traffic from one lab source address (``nw_src=<ip>``);
* ``LAB_OVS_PORT_DROP`` - drop everything entering the switch from one lab host's port (``in_port``),
  for spoofed/many-source floods where per-IP rules cannot keep up.

Approval never runs anything on the platform host: it only QUEUES the action. The lab enforcer
(`lab/traffic/enforcer.py`, root inside WSL2) picks queued actions up through the bridge relay,
re-checks the target, installs the rule with ``hard_timeout = TTL`` (OVS removes it on its own) and
reports back. Targets are checked here at proposal, again at approval, and again in the enforcer.
"""
from __future__ import annotations

import ipaddress
from functools import lru_cache
from typing import Optional, Tuple

LAB_TYPES = ("LAB_OVS_DROP", "LAB_OVS_PORT_DROP")
BLOCKABLE_ROLES = ("attacker", "reflector", "client")  # never the victim's port
TTL_DEFAULT_S, TTL_MIN_S, TTL_MAX_S = 300, 30, 3600
COOKIE_PREFIX = 0x5AB0  # top 16 bits of every rule's cookie: the kill switch deletes exactly these
MANAGEMENT_HOSTS = ("10.99.0.254",)  # NAT/uplink address used only by the containment test


@lru_cache(maxsize=1)
def _scope():
    from lab.safety import load_scope

    return load_scope()


def is_lab_type(action_type: Optional[str]) -> bool:
    return action_type in LAB_TYPES


def clamp_ttl(ttl: Optional[int]) -> int:
    try:
        t = int(ttl) if ttl is not None else TTL_DEFAULT_S
    except (TypeError, ValueError):
        t = TTL_DEFAULT_S
    return max(TTL_MIN_S, min(TTL_MAX_S, t))


def validate_target(action_type: str, target: str, scope=None) -> Tuple[bool, str]:
    """(ok, reason). Never the victim, the management path, or anything outside the lab scope."""
    scope = scope or _scope()
    victim = str(scope.hosts.get("victim"))
    if action_type == "LAB_OVS_PORT_DROP":
        if target not in BLOCKABLE_ROLES or target not in scope.hosts:
            return False, f"port target must be one of the lab host roles {BLOCKABLE_ROLES}, got {target!r}"
        return True, f"port of lab host '{target}'"
    if action_type != "LAB_OVS_DROP":
        return False, f"not a lab action type: {action_type!r}"
    try:
        ip = ipaddress.ip_address(str(target).strip())
    except ValueError:
        return False, f"{target!r} is not an IP address"
    if not any(ip in n for n in scope.networks):
        return False, f"{ip} is outside the lab scope {[str(n) for n in scope.networks]}"
    if str(ip) == victim:
        return False, "refusing to block the victim"
    if str(ip) in MANAGEMENT_HOSTS:
        return False, "refusing to block the management/NAT path"
    for n in scope.networks:
        if ip in (n.network_address, n.broadcast_address):
            return False, "refusing the network/broadcast address"
    return True, f"lab source {ip}"


def cookie_for(action_id: str) -> int:
    """64-bit OVS cookie: 0x5AB0 prefix + 48 bits from the action id (hex)."""
    import hashlib

    tail = int(hashlib.sha256(action_id.encode("utf-8")).hexdigest()[:12], 16)  # deterministic everywhere
    return (COOKIE_PREFIX << 48) | tail


def ovs_command(action_type: str, target: str, ttl_s: int, action_id: str, switch: str = "s1") -> str:
    """The exact rule the enforcer installs (shown to the approver before approval)."""
    match = f"in_port=<{target} port>" if action_type == "LAB_OVS_PORT_DROP" else f"ip,nw_src={target}"
    return (f"ovs-ofctl add-flow {switch} \"cookie={hex(cookie_for(action_id))},priority=200,{match},"
            f"hard_timeout={int(ttl_s)},actions=drop\"")
