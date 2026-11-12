# -*- coding: utf-8 -*-
"""Platform side of LAB-ONLY containment (v5.4.0). The rules live in `lab/containment.py` (one definition,
shared with the WSL2 enforcer); see that module for what may be blocked and why."""
from lab.containment import (BLOCKABLE_ROLES, COOKIE_PREFIX, LAB_TYPES, MANAGEMENT_HOSTS, TTL_DEFAULT_S,  # noqa: F401
                             TTL_MAX_S, TTL_MIN_S, clamp_ttl, cookie_for, is_lab_type, ovs_command, validate_target)
