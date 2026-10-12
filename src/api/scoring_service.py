# -*- coding: utf-8 -*-
"""
DDoS Detection & Mitigation — FastAPI Real-Time Scoring Service.

Provides:
  POST /score/flow    — score a single flow
  POST /score/batch   — score a batch of flows
  GET  /health        — health check
  GET  /model/info    — model metadata & taxonomy

Security:
  - API key authentication via X-API-Key header (loaded from DDOS_API_KEYS env)
  - Per-key sliding-window rate limiting (configurable via env vars)
  - Request body size cap
"""
import os
import json
import time
import logging
import secrets
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Optional, Any, List, Dict

import joblib
import numpy as np
from fastapi import FastAPI, HTTPException, Request, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("ddos_scoring_api")

# ---------------------------------------------------------------------------
# Configuration from environment
# ---------------------------------------------------------------------------
MODEL_DIR = os.environ.get("DDOS_MODEL_DIR", os.path.join(os.path.dirname(os.path.dirname(__file__)), "models"))

# API keys: comma-separated list in env, or auto-generate one for dev
_raw_keys = os.environ.get("DDOS_API_KEYS", "")
API_KEYS: set[str] = {k.strip() for k in _raw_keys.split(",") if k.strip()}
_generated_dev_key: Optional[str] = None
if not API_KEYS:
    _generated_dev_key = f"dev-{secrets.token_hex(16)}"
    API_KEYS.add(_generated_dev_key)

# Admin API keys: separate, privileged tier for mitigation approval/rejection
_raw_admin_keys = os.environ.get("DDOS_ADMIN_KEYS", "")
ADMIN_KEYS: set[str] = {k.strip() for k in _raw_admin_keys.split(",") if k.strip()}
_generated_dev_admin_key: Optional[str] = None
if not ADMIN_KEYS:
    _generated_dev_admin_key = f"dev-admin-{secrets.token_hex(16)}"
    ADMIN_KEYS.add(_generated_dev_admin_key)

# Rate limiting config
RATE_LIMIT_WINDOW_SECONDS = int(os.environ.get("DDOS_RATE_LIMIT_WINDOW", "60"))
RATE_LIMIT_MAX_REQUESTS = int(os.environ.get("DDOS_RATE_LIMIT_MAX", "120"))
MAX_BATCH_SIZE = int(os.environ.get("DDOS_MAX_BATCH_SIZE", "1000"))

# ---------------------------------------------------------------------------
# Model loading (singleton, loaded once at startup)
# ---------------------------------------------------------------------------
from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES
from src.mitigation.manager import get_manager
from src.models.ensemble import get_default_ensemble

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    registry.load(MODEL_DIR)
    if _generated_dev_key:
        logger.warning(
            "\n"
            "======================================================================\n"
            "  WARNING: NO DDOS_API_KEYS ENVIRONMENT VARIABLE SET!\n"
            "  AUTO-GENERATED DEV API KEY: %s\n"
            "  DO NOT USE IN PRODUCTION — SET DDOS_API_KEYS IN ENVIRONMENT.\n"
            "======================================================================",
            _generated_dev_key,
        )
    if _generated_dev_admin_key:
        logger.warning(
            "\n"
            "======================================================================\n"
            "  WARNING: NO DDOS_ADMIN_KEYS ENVIRONMENT VARIABLE SET!\n"
            "  AUTO-GENERATED DEV ADMIN KEY: %s\n"
            "  DO NOT USE IN PRODUCTION — SET DDOS_ADMIN_KEYS IN ENVIRONMENT.\n"
            "======================================================================",
            _generated_dev_admin_key,
        )
    yield

class ModelRegistry:
    """Holds loaded model artifacts. Instantiated once at app startup."""

    def __init__(self):
        self.stage1 = None
        self.stage2 = None
        self.le1 = None
        self.le2 = None
        self.preprocessor = None
        self.taxonomy = None
        self._loaded = False

    def load(self, model_dir: str = MODEL_DIR):
        if self._loaded:
            return
        logger.info("Loading model artifacts from %s ...", model_dir)
        self.stage1 = joblib.load(os.path.join(model_dir, "stage1_binary_xgb.joblib"))
        self.stage2 = joblib.load(os.path.join(model_dir, "stage2_triage_xgb.joblib"))
        # Force CPU device for API inference thread safety
        try:
            self.stage1.set_params(device="cpu")
            self.stage2.set_params(device="cpu")
        except Exception as e:
            logger.warning("Could not set device='cpu' on XGBoost models: %s", e)

        self.le1 = joblib.load(os.path.join(model_dir, "label_encoder_stage1.joblib"))
        self.le2 = joblib.load(os.path.join(model_dir, "label_encoder_stage2.joblib"))
        self.preprocessor = joblib.load(os.path.join(model_dir, "feature_preprocessor.joblib"))
        with open(os.path.join(model_dir, "taxonomy_config.json"), "r", encoding="utf-8") as f:
            self.taxonomy = json.load(f)

        # Validate feature schema against flow_extractor.py
        loaded_cols = [c.strip() for c in self.preprocessor["feature_cols"]]
        expected_cols = [c.strip() for c in CICFLOWMETER_FEATURE_NAMES]

        if len(loaded_cols) != len(expected_cols):
            raise ValueError(
                f"Feature count mismatch: model preprocessor expects {len(loaded_cols)} features, "
                f"but Layer 1 flow_extractor.py produces {len(expected_cols)} features."
            )

        mismatched = set(loaded_cols) ^ set(expected_cols)
        if mismatched:
            raise ValueError(
                f"Feature schema mismatch between model preprocessor and flow_extractor.py. "
                f"Mismatched columns: {mismatched}"
            )

        self._loaded = True
        logger.info("Models loaded & schema verified (77 features). Stage 2 classes: %s", self.taxonomy["canonical_classes_stage2"])

    def _ensure_loaded(self):
        if not self._loaded:
            self.load()

    @property
    def feature_cols(self) -> list[str]:
        self._ensure_loaded()
        return self.preprocessor["feature_cols"]

    @property
    def medians(self) -> dict:
        self._ensure_loaded()
        return self.preprocessor["medians"]


registry = ModelRegistry()

# ---------------------------------------------------------------------------
# Rate limiter (in-process sliding window, per API key)
# ---------------------------------------------------------------------------
class SlidingWindowRateLimiter:
    """Thread-safe-ish sliding window rate limiter keyed by API key."""

    def __init__(self, window_seconds: int, max_requests: int):
        self.window = window_seconds
        self.max = max_requests
        self._hits: dict[str, list[float]] = defaultdict(list)

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        cutoff = now - self.window
        # Prune old entries
        self._hits[key] = [t for t in self._hits[key] if t > cutoff]
        if len(self._hits[key]) >= self.max:
            return False
        self._hits[key].append(now)
        return True

    def remaining(self, key: str) -> int:
        now = time.monotonic()
        cutoff = now - self.window
        self._hits[key] = [t for t in self._hits[key] if t > cutoff]
        return max(0, self.max - len(self._hits[key]))


rate_limiter = SlidingWindowRateLimiter(RATE_LIMIT_WINDOW_SECONDS, RATE_LIMIT_MAX_REQUESTS)

# ---------------------------------------------------------------------------
# Pydantic request / response models
# ---------------------------------------------------------------------------
class FlowFeatures(BaseModel):
    """A single network flow's CICFlowMeter feature vector."""
    features: dict[str, float] = Field(
        ...,
        description="Mapping of feature name -> numeric value (77 CICFlowMeter features)."
    )
    history_window: Optional[List[Dict[str, float]]] = Field(
        default=None,
        description="Optional list of feature snapshots for temporal sequence models."
    )

class BatchFlowRequest(BaseModel):
    """Batch of flow feature vectors."""
    flows: list[dict[str, float]] = Field(
        ...,
        description="List of feature dictionaries, one per flow.",
        max_length=MAX_BATCH_SIZE,
    )

class ScoringResult(BaseModel):
    is_attack: bool
    confidence: float
    attack_family: Optional[str] = None
    attack_family_confidence: Optional[float] = None
    per_model_breakdown: Optional[Dict[str, Any]] = None

class FlowResponse(BaseModel):
    result: ScoringResult
    model_version: str = "ensemble-rf-xgb-bilstm-v1"

class BatchResponse(BaseModel):
    results: list[ScoringResult]
    count: int
    model_version: str = "hierarchical-xgb-6class-v1"

# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="DDoS Detection Scoring API",
    description="Real-time hierarchical DDoS flow classification (Stage 1: Binary, Stage 2: 6-class triage).",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Auth dependencies
# ---------------------------------------------------------------------------
async def verify_api_key(request: Request) -> str:
    key = request.headers.get("X-API-Key")
    if not key or key not in API_KEYS:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return key


async def verify_admin_key(request: Request) -> str:
    # Accept X-Admin-Key header, or X-API-Key if present in ADMIN_KEYS
    key = request.headers.get("X-Admin-Key") or request.headers.get("X-API-Key")
    if not key:
        raise HTTPException(status_code=401, detail="Missing admin credentials.")
    if key not in ADMIN_KEYS:
        # If the key is a valid scoring API key, reject with 403 Forbidden!
        if key in API_KEYS:
            raise HTTPException(
                status_code=403,
                detail="Insufficient privileges: scoring key cannot execute mitigation actions. Admin key required."
            )
        raise HTTPException(status_code=401, detail="Invalid admin credentials.")
    return key


async def verify_any_key(request: Request) -> str:
    key = request.headers.get("X-Admin-Key") or request.headers.get("X-API-Key")
    if not key:
        raise HTTPException(status_code=401, detail="Missing API credentials.")
    if key in ADMIN_KEYS or key in API_KEYS:
        return key
    raise HTTPException(status_code=401, detail="Invalid API key.")


# ---------------------------------------------------------------------------
# Rate limit dependency
# ---------------------------------------------------------------------------
async def check_rate_limit(key: str = Depends(verify_api_key)) -> str:
    if not rate_limiter.allow(key):
        remaining = rate_limiter.remaining(key)
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Max {RATE_LIMIT_MAX_REQUESTS} requests per {RATE_LIMIT_WINDOW_SECONDS}s window.",
            headers={"Retry-After": str(RATE_LIMIT_WINDOW_SECONDS)},
        )
    return key

# ---------------------------------------------------------------------------
# Inference helpers
# ---------------------------------------------------------------------------
def _preprocess_features(feature_dict: dict[str, float]) -> np.ndarray:
    """Convert a feature dict into a 1×77 numpy array in correct column order."""
    cols = registry.feature_cols
    medians = registry.medians
    row = []
    for c in cols:
        val = feature_dict.get(c, medians.get(c, 0.0))
        if val is None or not np.isfinite(val):
            val = medians.get(c, 0.0)
        row.append(float(val))
    return np.array([row], dtype=np.float32)

def _score_single(X: np.ndarray) -> ScoringResult:
    """Run the two-stage hierarchical pipeline on a single preprocessed row."""
    # Stage 1: binary
    s1_proba = registry.stage1.predict_proba(X)[0]
    s1_pred_idx = int(np.argmax(s1_proba))
    s1_label = registry.le1.inverse_transform([s1_pred_idx])[0]
    s1_conf = float(s1_proba[s1_pred_idx])

    is_attack = s1_label == "Attack"

    if not is_attack:
        return ScoringResult(
            is_attack=False,
            confidence=s1_conf,
            attack_family=None,
            attack_family_confidence=None,
        )

    # Stage 2: 6-class triage
    s2_proba = registry.stage2.predict_proba(X)[0]
    s2_pred_idx = int(np.argmax(s2_proba))
    s2_label = registry.le2.inverse_transform([s2_pred_idx])[0]
    s2_conf = float(s2_proba[s2_pred_idx])

    return ScoringResult(
        is_attack=True,
        confidence=s1_conf,
        attack_family=s2_label,
        attack_family_confidence=s2_conf,
    )

# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    """Health check — no auth required."""
    return {"status": "ok", "models_loaded": registry._loaded}

@app.get("/model/info", dependencies=[Depends(verify_api_key)])
async def model_info():
    """Return model metadata and taxonomy configuration."""
    return {
        "model_version": "hierarchical-xgb-6class-v1",
        "stage1_macro_f1": registry.taxonomy.get("stage1_macro_f1"),
        "stage2_cv_macro_f1_mean": registry.taxonomy.get("stage2_cv_macro_f1_mean"),
        "stage2_cv_macro_f1_std": registry.taxonomy.get("stage2_cv_macro_f1_std"),
        "canonical_classes": registry.taxonomy.get("canonical_classes_stage2"),
        "quarantined_classes": registry.taxonomy.get("quarantined_classes"),
        "feature_count": len(registry.feature_cols),
        "rate_limit": f"{RATE_LIMIT_MAX_REQUESTS} req / {RATE_LIMIT_WINDOW_SECONDS}s",
    }

@app.post("/score/flow", response_model=FlowResponse)
async def score_flow(
    body: FlowFeatures,
    model: str = Query("ensemble", description="Scoring mode: 'ensemble' (default), 'rf_only', 'xgb_only', 'rf_xgb'"),
    key: str = Depends(check_rate_limit),
):
    """Score a single network flow through the calibrated ensemble or fallback mode."""
    hw_matrix = None
    if body.history_window is not None:
        cols = registry.feature_cols
        medians = registry.medians
        hw_rows = []
        for step in body.history_window:
            row = [float(step.get(c, medians.get(c, 0.0))) for c in cols]
            hw_rows.append(row)
        if hw_rows:
            hw_matrix = np.array(hw_rows, dtype=np.float32)

    ensemble = get_default_ensemble()
    label, confidence, breakdown = ensemble.score_flow(
        features=body.features,
        history_window=hw_matrix,
        mode=model,
    )

    is_attack = (label.lower() != "benign")
    attack_family = label if is_attack else None
    attack_family_confidence = confidence if is_attack else None

    result = ScoringResult(
        is_attack=is_attack,
        confidence=confidence,
        attack_family=attack_family,
        attack_family_confidence=attack_family_confidence,
        per_model_breakdown=breakdown,
    )
    logger.info(
        "key=%s score_flow mode=%s attack=%s family=%s conf=%.3f",
        key[:8], model, result.is_attack, result.attack_family, result.confidence,
    )
    return FlowResponse(result=result, model_version="ensemble-rf-xgb-bilstm-v1")

@app.post("/score/batch", response_model=BatchResponse)
async def score_batch(body: BatchFlowRequest, key: str = Depends(check_rate_limit)):
    """Score a batch of network flows."""
    if len(body.flows) > MAX_BATCH_SIZE:
        raise HTTPException(
            status_code=400,
            detail=f"Batch size {len(body.flows)} exceeds maximum {MAX_BATCH_SIZE}.",
        )

    # Vectorized preprocessing
    cols = registry.feature_cols
    medians = registry.medians
    rows = []
    for flow_dict in body.flows:
        row = []
        for c in cols:
            val = flow_dict.get(c, medians.get(c, 0.0))
            if val is None or not np.isfinite(val):
                val = medians.get(c, 0.0)
            row.append(float(val))
        rows.append(row)

    X_batch = np.array(rows, dtype=np.float32)

    # Stage 1: binary on full batch
    s1_proba = registry.stage1.predict_proba(X_batch)
    s1_pred_idx = np.argmax(s1_proba, axis=1)
    s1_labels = registry.le1.inverse_transform(s1_pred_idx)
    s1_confs = np.max(s1_proba, axis=1)

    results = []
    attack_mask = s1_labels == "Attack"

    # Stage 2: only on attack rows
    if attack_mask.any():
        X_attacks = X_batch[attack_mask]
        s2_proba = registry.stage2.predict_proba(X_attacks)
        s2_pred_idx = np.argmax(s2_proba, axis=1)
        s2_labels = registry.le2.inverse_transform(s2_pred_idx)
        s2_confs = np.max(s2_proba, axis=1)
    else:
        s2_labels = np.array([])
        s2_confs = np.array([])

    attack_counter = 0
    for i in range(len(body.flows)):
        if attack_mask[i]:
            results.append(ScoringResult(
                is_attack=True,
                confidence=float(s1_confs[i]),
                attack_family=str(s2_labels[attack_counter]),
                attack_family_confidence=float(s2_confs[attack_counter]),
            ))
            attack_counter += 1
        else:
            results.append(ScoringResult(
                is_attack=False,
                confidence=float(s1_confs[i]),
            ))

    logger.info(
        "key=%s score_batch count=%d attacks=%d",
        key[:8], len(body.flows), int(attack_mask.sum()),
    )
    return BatchResponse(results=results, count=len(results))


# ---------------------------------------------------------------------------
# Mitigation Action Endpoints (Human-in-the-Loop Approval Gate)
# ---------------------------------------------------------------------------
@app.get("/actions/pending")
async def get_pending_actions_endpoint(key: str = Depends(verify_any_key)):
    """Return all pending mitigation actions awaiting human approval."""
    manager = get_manager()
    pending = manager.get_pending()
    return {
        "pending_actions": list(pending.values()),
        "count": len(pending),
    }


@app.post("/actions/approve/{action_id}")
async def approve_action_endpoint(action_id: str, admin_key: str = Depends(verify_admin_key)):
    """
    Approve and execute a pending mitigation action.
    Requires privileged Admin credentials (DDOS_ADMIN_KEYS).
    """
    manager = get_manager()
    action = manager.get_action(action_id)
    if not action:
        raise HTTPException(status_code=404, detail=f"Action '{action_id}' not found.")
    if action.get("status") != "PENDING":
        raise HTTPException(status_code=400, detail=f"Action '{action_id}' is already {action.get('status')}.")

    success, message, updated_action = manager.approve(action_id, approver=f"admin_api:{admin_key[:8]}")
    if not success:
        raise HTTPException(status_code=500, detail=f"Action execution failed: {message}")

    return {
        "status": "executed",
        "action_id": action_id,
        "message": message,
        "action": updated_action,
    }


class RejectRequestBody(BaseModel):
    reason: Optional[str] = Field(default="", description="Reason for rejection")


@app.post("/actions/reject/{action_id}")
async def reject_action_endpoint(
    action_id: str,
    body: Optional[RejectRequestBody] = None,
    admin_key: str = Depends(verify_admin_key),
):
    """
    Reject a pending mitigation action without execution.
    Requires privileged Admin credentials (DDOS_ADMIN_KEYS).
    """
    manager = get_manager()
    action = manager.get_action(action_id)
    if not action:
        raise HTTPException(status_code=404, detail=f"Action '{action_id}' not found.")
    if action.get("status") != "PENDING":
        raise HTTPException(status_code=400, detail=f"Action '{action_id}' is already {action.get('status')}.")

    reason = body.reason if body else ""
    success, message, updated_action = manager.reject(action_id, reason=reason, rejecter=f"admin_api:{admin_key[:8]}")
    return {
        "status": "rejected",
        "action_id": action_id,
        "message": message,
        "action": updated_action,
    }

