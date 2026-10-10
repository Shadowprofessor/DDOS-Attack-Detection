# -*- coding: utf-8 -*-
"""
Layer 0 — Mitigation Engine package.
Provides centralized rule generation, pending action queue management, and safety gates.
"""
from src.mitigation.manager import PendingActionManager, get_manager

__all__ = ["PendingActionManager", "get_manager"]
