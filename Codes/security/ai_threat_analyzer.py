# -*- coding: utf-8 -*-
"""
Backwards-compatibility facade for OpenRouter Nemotron AI Threat Analyzer.
Canonical implementation now lives in `src/agent/nemotron_agent.py`.
"""
import sys
import os

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from src.agent.nemotron_agent import (
    AIThreatAnalyzer,
    NemotronAgent,
    summarize_ensemble_consensus,
    get_pending_actions,
    get_action,
    get_action_log,
    approve_action,
    reject_action,
    _propose_action,
    _execute_approved_action,
    _pending_actions,
    _pending_actions_lock,
    _action_log,
)

__all__ = [
    "AIThreatAnalyzer",
    "NemotronAgent",
    "summarize_ensemble_consensus",
    "get_pending_actions",
    "get_action",
    "get_action_log",
    "approve_action",
    "reject_action",
    "_propose_action",
    "_execute_approved_action",
    "_pending_actions",
    "_pending_actions_lock",
    "_action_log",
]
