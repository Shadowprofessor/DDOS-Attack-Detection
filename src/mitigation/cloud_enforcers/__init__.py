# -*- coding: utf-8 -*-
"""
Cloud Enforcers — Third-party DDoS mitigation service integrations.

All cloud enforcers follow the same safety contract as local enforcers:
- propose_action() enqueues a PENDING action (auto_execute=False)
- execute() is ONLY called by PendingActionManager.approve() after human approval
"""
from .cloudflare import CloudflareEnforcer

__all__ = ["CloudflareEnforcer"]
