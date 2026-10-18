# -*- coding: utf-8 -*-
"""
DDoS Detection Scoring API Entrypoint.

Re-exports FastAPI application instance and schemas from scoring_service.py
for standard uvicorn entrypoint (uvicorn src.api.app:app).
"""
import sys
from pathlib import Path

# Ensure workspace root is in sys.path
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.api.scoring_service import (
    app,
    lifespan,
    registry,
    rate_limiter,
    FlowFeatures,
    BatchFlowRequest,
    ScoringResult,
    FlowResponse,
    BatchResponse,
    score_flow,
    score_batch,
    health,
    model_info,
    API_KEYS,
    ADMIN_KEYS,
    _generated_dev_key,
    _generated_dev_admin_key,
    config,
    load_config,
)

__all__ = [
    "app",
    "lifespan",
    "registry",
    "rate_limiter",
    "FlowFeatures",
    "BatchFlowRequest",
    "ScoringResult",
    "FlowResponse",
    "BatchResponse",
    "score_flow",
    "score_batch",
    "health",
    "model_info",
    "API_KEYS",
    "ADMIN_KEYS",
    "_generated_dev_key",
    "_generated_dev_admin_key",
    "config",
    "load_config",
]
