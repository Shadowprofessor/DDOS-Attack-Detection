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
from fastapi.responses import JSONResponse, RedirectResponse, PlainTextResponse
from pydantic import BaseModel, Field, field_validator

# ---------------------------------------------------------------------------
# Configuration from centralized environment config loader
# ---------------------------------------------------------------------------
from src.config.loader import load_config, extract_env_flag

# Load unified environment configuration via --env flag, DDOS_ENV, or 'lab' default
config = load_config()

# Configure logging level from config
_log_level_name = config.get("scoring_service", {}).get("log_level", "info").upper()
_log_level = getattr(logging, _log_level_name, logging.INFO)
logging.basicConfig(level=_log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger("ddos_scoring_api")
logger.setLevel(_log_level)

# Observability: Prometheus-compatible metrics + opt-in structured JSON logging.
from src.obs import metrics as obs_metrics
from src.obs import logging as obs_logging
from src.obs.logging import log_safe
obs_logging.configure_from_env()

from src.mitigation.manager import get_manager, PendingActionManager
from src.features.signature_filter import SignatureFilter
from src.features.threshold_detector import ThresholdDetector
from src.features.anomaly_detector import AnomalyDetector, PerDestinationBaseline
from src.agent.campaign_correlator import CampaignCorrelator
from src.agent.blue_team_expert import generate_incident_dossier, generate_campaign_dossier

mgr = get_manager()
_SIG_FILTER = SignatureFilter()
_THRESHOLD_DETECTOR = ThresholdDetector(window_seconds=10.0)
_ANOMALY_DETECTOR = AnomalyDetector()
_H9_BASELINES = PerDestinationBaseline()  # v5.3.0 adaptive per-destination H9
_CAMPAIGN_CORRELATOR = CampaignCorrelator(window_seconds=60.0)

_CAMPAIGN_CORRELATION = defaultdict(lambda: {
    "attacker_ips": set(),
    "first_seen": None,
    "last_seen": None,
    "attack_types": set(),
    "total_packets": 0,
    "total_bytes": 0,
})

MODEL_DIR = config.get("models", {}).get("hierarchical", {}).get(
    "model_dir", os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
)

# Environment name drives fail-closed behavior and whether built-in test keys are honored.
_ENV_NAME = str(config.get("environment") or os.environ.get("DDOS_ENV", "lab")).lower().strip()
_IS_PROD_LIKE = _ENV_NAME in ("production", "staging", "prod")



def _in_lab_scope(ip) -> bool:
    """True if `ip` is inside the lab's allowed networks (lab/lab_scope.yaml)."""
    try:
        import ipaddress

        from lab.containment import _scope

        addr = ipaddress.ip_address(str(ip))
        return any(addr.version == n.version and addr in n for n in _scope().networks)
    except Exception:
        return False

def _env_key_set(var_name: str) -> set[str]:
    return {k.strip() for k in os.environ.get(var_name, "").split(",") if k.strip()}


def _announce_dev_key(label: str, value: str) -> str:
    """Write a generated dev key to a local owner-only file and print only the file path.

    The value never goes to stdout or the logger (stdout is often shipped to log collectors).
    Path: ``DDOS_DEV_KEY_FILE`` or ``./.dev-keys`` (gitignored). Returns the path.
    """
    path = os.environ.get("DDOS_DEV_KEY_FILE") or os.path.join(os.getcwd(), ".dev-keys")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        f.write(f"{_ENV_NAME}\t{label}\t{value}\n")
    print(f"[ddos-scoring] Generated ephemeral {label} for '{_ENV_NAME}' env -> written to {path}", flush=True)
    return path


# API keys: from config/env, or auto-generate one for dev. Fail closed in prod/staging.
_raw_keys = config.get("scoring_service", {}).get("auth", {}).get("api_keys", "") or ""
API_KEYS: set[str] = {k.strip() for k in _raw_keys.split(",") if k.strip()}
_generated_dev_key: Optional[str] = None
if not (API_KEYS | _env_key_set("DDOS_API_KEYS")):
    if _IS_PROD_LIKE:
        raise RuntimeError(
            f"No scoring API keys configured for '{_ENV_NAME}' environment "
            "(set scoring_service.auth.api_keys or DDOS_API_KEYS). Refusing to start."
        )
    _generated_dev_key = f"dev-{secrets.token_hex(16)}"
    API_KEYS.add(_generated_dev_key)
    logger.warning("No API keys configured; generated an ephemeral dev API key (value written to the dev key file).")
    _announce_dev_key("scoring API key", _generated_dev_key)

# Admin API keys: separate, privileged tier for mitigation approval/rejection.
_raw_admin_keys = config.get("scoring_service", {}).get("auth", {}).get("admin_keys", "") or ""
ADMIN_KEYS: set[str] = {k.strip() for k in _raw_admin_keys.split(",") if k.strip()}
_generated_dev_admin_key: Optional[str] = None
if not (ADMIN_KEYS | _env_key_set("DDOS_ADMIN_KEYS")):
    if _IS_PROD_LIKE:
        raise RuntimeError(
            f"No admin keys configured for '{_ENV_NAME}' environment "
            "(set scoring_service.auth.admin_keys or DDOS_ADMIN_KEYS). Refusing to start."
        )
    _generated_dev_admin_key = f"dev-admin-{secrets.token_hex(16)}"
    ADMIN_KEYS.add(_generated_dev_admin_key)
    logger.warning("No admin keys configured; generated an ephemeral dev admin key (value written to the dev key file).")
    _announce_dev_key("admin key", _generated_dev_admin_key)

# Rate limiting config
_rate_cfg = config.get("scoring_service", {}).get("rate_limit", {})
RATE_LIMIT_WINDOW_SECONDS = int(_rate_cfg.get("window_seconds", 60))
RATE_LIMIT_MAX_REQUESTS = int(_rate_cfg.get("max_requests", 120))
MAX_BATCH_SIZE = int(_rate_cfg.get("max_batch_size", 1000))

# ---------------------------------------------------------------------------
# Model loading (singleton, loaded once at startup)
# ---------------------------------------------------------------------------
from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES
from src.mitigation.manager import get_manager
from src.models.ensemble import get_default_ensemble
from src.web.realtime_dashboard.broadcaster import get_broadcaster
from src.web.realtime_dashboard.router import router as dashboard_router
from src.agent.blue_team_expert import generate_incident_dossier

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    registry.load(MODEL_DIR)
    await get_broadcaster().start()
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
    ir_rt = None
    if os.environ.get("DDOS_IR_SCHEDULER", "on").strip().lower() not in ("0", "off", "false", "no"):
        try:
            from src.ir.runtime import get_ir_runtime
            ir_rt = get_ir_runtime()
            ir_rt.start()  # auto-rollback + CERT-In timers
        except Exception as e:  # IR must never take the scoring path down
            logger.error("Incident-response scheduler failed to start: %s", log_safe(type(e).__name__))
            ir_rt = None
    try:
        yield
    finally:
        if ir_rt is not None:
            ir_rt.stop()
        await get_broadcaster().stop()

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
        stage1_path = os.path.join(model_dir, "stage1_binary_xgb.joblib")
        if not os.path.isfile(stage1_path):
            is_test_env = bool(
                os.environ.get("CI") or os.environ.get("GITHUB_ACTIONS")
                or os.environ.get("PYTEST_CURRENT_TEST") or os.environ.get("DDOS_ALLOW_TEST_DUMMY")
            )
            if is_test_env:
                self._load_dummy()
                return
            raise FileNotFoundError(
                f"Model artifacts not found in '{model_dir}'. Regenerate them (see README "
                "'Model artifacts'), or set CI=1 for a DummyClassifier test fallback."
            )
        self.stage1 = joblib.load(stage1_path)
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

    def _load_dummy(self):
        """DummyClassifier fallback so the app loads without real artifacts (CI/test only).
        Mirrors the ensemble's fallback; produces structurally valid but meaningless predictions."""
        logger.warning("Model artifacts missing; using DummyClassifier fallback (testing/CI only).")
        from sklearn.dummy import DummyClassifier
        from sklearn.preprocessing import LabelEncoder
        cols = list(CICFLOWMETER_FEATURE_NAMES)
        # Stage-2 is attack-family triage (6 classes; Benign is decided at Stage 1).
        classes2 = ["MSSQL", "NTP", "Reflection-Amplification", "Syn", "TFTP", "UDP-Based"]
        self.stage1 = DummyClassifier(strategy="constant", constant=0).fit(
            np.zeros((2, len(cols))), [0, 1])
        self.stage2 = DummyClassifier(strategy="constant", constant=0).fit(
            np.zeros((len(classes2), len(cols))), list(range(len(classes2))))
        self.le1 = LabelEncoder().fit(["Benign", "Attack"])
        self.le2 = LabelEncoder().fit(classes2)
        self.preprocessor = {"feature_cols": cols, "medians": {c: 0.0 for c in cols}}
        self.taxonomy = {
            "canonical_classes_stage2": classes2,
            "stage1_macro_f1": None, "stage2_cv_macro_f1_mean": None,
            "stage2_cv_macro_f1_std": None, "quarantined_classes": ["WebDDoS"],
        }
        self._loaded = True

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
# Layer-2 zero-day signal.
#   Primary: supervised OOD = 1 - max class confidence >= tau  (see docs/EVAL_NOTES.md).
#   Secondary (OFF by default): IsolationForest "benign anomaly" monitor — it does NOT
#   separate CICDDoS2019 attacks, so it never drives the zero-day flag; enable with
#   DDOS_ENABLE_ANOMALY=1 to surface its score as an advisory 'anomaly' field.
# ---------------------------------------------------------------------------
from src.models.ood_detector import OODDetector

_OOD_TAU = float(config.get("scoring_service", {}).get("ood_tau", 0.5))
# Prefer the deployed model-backed detector (isotonic-calibrated XGBoost — the SAME
# methodology the LOCO eval scores); fall back to a confidence-tau JSON, then default.
_OOD_CANDIDATES = [
    config.get("scoring_service", {}).get("ood_model_path"),
    os.environ.get("DDOS_OOD_MODEL"),
    "models/ood_model.joblib",
    config.get("scoring_service", {}).get("ood_detector_path"),
    os.environ.get("DDOS_OOD_DETECTOR"),
    "models/ood_detector.json",
]
_OOD = OODDetector(tau=_OOD_TAU)
for _cand in _OOD_CANDIDATES:
    if _cand and os.path.exists(_cand):
        try:
            _OOD = OODDetector.load(_cand)
            logger.info("Loaded OOD detector (model_backed=%s, tau=%.4f) from %s",
                        _OOD.is_model_backed, _OOD.tau, _cand)
            break
        except Exception as _ood_load_err:  # pragma: no cover
            logger.warning("Could not load OOD detector (%s): %s", _cand, _ood_load_err)

_ANOMALY_ENABLED = os.environ.get("DDOS_ENABLE_ANOMALY", "").strip().lower() in ("1", "true", "yes", "on")
_ANOMALY_DETECTOR_IF = None
if _ANOMALY_ENABLED:
    _anom_path = (
        config.get("scoring_service", {}).get("novelty_model_path")
        or os.environ.get("DDOS_NOVELTY_MODEL", "models/novelty_detector.joblib")
    )
    if _anom_path and os.path.exists(_anom_path):
        try:
            from src.models.anomaly_novelty import NoveltyDetector
            _ANOMALY_DETECTOR_IF = NoveltyDetector.load(_anom_path)
            logger.info("Loaded secondary benign-anomaly monitor from %s", _anom_path)
        except Exception as _anom_err:  # pragma: no cover - load failure path
            logger.warning("Could not load benign-anomaly monitor (%s): %s", _anom_path, _anom_err)


def _ood_assessment(confidence: float, features: dict, label: str) -> Optional[dict]:
    """Supervised OOD / zero-day assessment from model confidence; optional IF anomaly advisory."""
    try:
        if _OOD.is_model_backed:
            result = _OOD.assess_features(features, getattr(registry, "medians", None))
        else:
            result = _OOD.assess(confidence)
        if result.get("ood_suspected"):
            try:
                obs_metrics.ALERTS.inc(severity="ood")
            except Exception:
                pass
        if _ANOMALY_DETECTOR_IF is not None:
            try:
                cols = registry.feature_cols
                medians = registry.medians
                vec = [float(features.get(c, medians.get(c, 0.0))) for c in cols]
                anom = float(_ANOMALY_DETECTOR_IF.anomaly_score([vec])[0])
                # Advisory only — labelled 'anomaly', never 'zero_day'; does not drive the flag.
                result["anomaly"] = {"score": round(anom, 4), "note": "benign-drift monitor; not attack detection"}
            except Exception:
                pass
        return result
    except Exception as _ood_err:  # pragma: no cover - defensive
        logger.debug("OOD assessment failed: %s", _ood_err)
        return None


# ---------------------------------------------------------------------------
# Layer-7 low-and-slow (Slowloris / R.U.D.Y.) detector — stateful across flows.
# ---------------------------------------------------------------------------
from src.features.l7_lowslow import LowSlowDetector, LowSlowConfig

_lowslow_threshold = int(
    config.get("scoring_service", {}).get("lowslow_concurrent_threshold")
    or os.environ.get("DDOS_LOWSLOW_THRESHOLD", 20)
)
_LOWSLOW = LowSlowDetector(LowSlowConfig(concurrent_threshold=_lowslow_threshold))


def _lowslow_observe(feat: dict, src_ip: str, dst_ip: str) -> Optional[dict]:
    """Feed a flow summary to the low-and-slow detector; returns an alert dict or None."""
    try:
        summary = {
            "src_ip": src_ip,
            "src_port": feat.get("Source Port") or feat.get("src_port"),
            "dst_ip": dst_ip,
            "dst_port": feat.get("Destination Port") or feat.get("dst_port") or 80,
            "duration_sec": float(feat.get("Flow Duration", 0.0)) / 1e6,  # CICFlowMeter µs -> s
            "fwd_bytes": float(
                feat.get("Fwd Packets Length Total", feat.get("Total Length of Fwd Packets", 0.0)) or 0.0
            ),
            "header_complete": feat.get("header_complete", True),
            "bwd_packets": feat.get("Total Backward Packets"),
        }
        alert = _LOWSLOW.observe(summary)
        if alert:
            try:
                obs_metrics.ALERTS.inc(severity="low_slow")
            except Exception:
                pass
        return alert
    except Exception:  # pragma: no cover - defensive
        return None


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
    features: dict[str, Any] = Field(
        ...,
        description="Mapping of feature name -> numeric value or string metadata."
    )
    history_window: Optional[List[Dict[str, float]]] = Field(
        default=None,
        description="Optional list of feature snapshots for temporal sequence models."
    )
    feature_completeness: Optional[float] = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Proportion of features populated by capture backend in [0.0, 1.0]."
    )
    source_mode: Optional[str] = Field(
        default=None,
        description="Capture provenance mode (e.g. 'host_ingress', 'cloud_flow_log', 'tap', 'libpcap')."
    )

    @classmethod
    def from_flow(cls, flow: Any, backend: Optional[Any] = None) -> "FlowFeatures":
        """Construct FlowFeatures directly from a Flow dataclass instance, extracting backend telemetry."""
        payload = flow.to_flow_features(backend=backend)
        return cls(**payload)

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
    feature_completeness: float = 1.0
    degraded_confidence: bool = False
    degradation_reason: Optional[str] = None
    proposed_action_id: Optional[str] = None
    meets_threshold: bool = True
    calibrated_threshold: Optional[float] = None

class FlowResponse(BaseModel):
    result: ScoringResult
    model_version: str = "ensemble-rf-xgb-bilstm-v1"
    # Layer-2 supervised OOD / zero-day signal (ood_score, tau, ood_suspected; optional anomaly advisory).
    ood: Optional[dict] = None
    # Layer-7 low-and-slow (Slowloris/RUDY) alert for the target, when concurrency crosses threshold.
    low_slow: Optional[dict] = None
    # v5.3.0: detected_by / attack_type / confidence / MITRE / reason for an attack verdict (None if benign)
    explanation: Optional[dict] = None

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

# CORS: same-origin by default (the SOC app is served from this server). Cross-origin API
# clients must be listed explicitly in DDOS_CORS_ORIGINS (comma-separated).
_cors_origins = [o.strip() for o in os.environ.get("DDOS_CORS_ORIGINS", "").split(",") if o.strip()]
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_methods=["POST", "GET"],
        allow_headers=["X-API-Key", "X-Admin-Key", "Content-Type"],
    )

app.include_router(dashboard_router)

from src.api.analyst_router import router as analyst_router  # noqa: E402  Layer-3 analyst API

app.include_router(analyst_router)

from src.api.ir_router import router as ir_router  # noqa: E402  M3 incident-response API

app.include_router(ir_router)

from src.api.live_router import router as live_router  # noqa: E402  v5.2.0 live attack view

app.include_router(live_router)

from src.api.lab_router import router as lab_router  # noqa: E402  v5.4.0 lab enforcer hand-off

app.include_router(lab_router)

from src.api.agent_router import router as agent_router  # noqa: E402  v5.4.0 agentic analyst

app.include_router(agent_router)

from src.api.session_router import router as session_router  # noqa: E402  v4.3.0 SOC web app
from src.web import app_server as _soc_app  # noqa: E402

app.include_router(session_router)
_soc_app.install(app)


@app.middleware("http")
async def _metrics_middleware(request: Request, call_next):
    """Count every HTTP request and record its latency for Prometheus."""
    start = time.perf_counter()
    response = await call_next(request)
    try:
        # Label by the MATCHED route template (e.g. /actions/approve/{action_id}), not the raw
        # URL, so unbounded path params / random probes cannot explode metric cardinality.
        route = request.scope.get("route")
        endpoint_label = getattr(route, "path", None) or "unmatched"
        obs_metrics.HTTP_REQUESTS.inc(endpoint=endpoint_label, status=str(response.status_code))
        obs_metrics.SCORE_LATENCY.set(time.perf_counter() - start)
    except Exception:
        pass
    return response


@app.get("/metrics", include_in_schema=False)
async def metrics_endpoint():
    """Prometheus scrape endpoint (text exposition format; unauthenticated by convention)."""
    try:
        obs_metrics.PENDING_ACTIONS.set(float(len(get_manager().get_pending())))
    except Exception:
        pass
    return PlainTextResponse(
        obs_metrics.render_latest(),
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Auth dependencies
# ---------------------------------------------------------------------------
def _get_valid_api_keys() -> set[str]:
    keys = set(API_KEYS)
    env_keys = os.environ.get("DDOS_API_KEYS", "")
    if env_keys:
        keys.update(k.strip() for k in env_keys.split(",") if k.strip())
    # Built-in convenience key is honored ONLY in an explicit test environment.
    if _ENV_NAME == "test":
        keys.add("scoring-key-test")
    return keys


def _get_valid_admin_keys() -> set[str]:
    keys = set(ADMIN_KEYS)
    env_keys = os.environ.get("DDOS_ADMIN_KEYS", "")
    if env_keys:
        keys.update(k.strip() for k in env_keys.split(",") if k.strip())
    # Built-in convenience key is honored ONLY in an explicit test environment.
    if _ENV_NAME == "test":
        keys.add("admin-key-test")
    return keys


async def verify_api_key(request: Request) -> str:
    key = request.headers.get("X-API-Key")
    valid_keys = _get_valid_api_keys()
    if not key or key not in valid_keys:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return key


async def verify_admin_key(request: Request) -> str:
    # Accept X-Admin-Key header, or X-API-Key if present in ADMIN_KEYS, or (SOC web app) an
    # admin session cookie + CSRF token. An analyst session gets 403 like an analyst key.
    key = request.headers.get("X-Admin-Key") or request.headers.get("X-API-Key")
    if not key:
        from src.api.rbac import session_key
        key = session_key(request)
    valid_admin_keys = _get_valid_admin_keys()
    valid_api_keys = _get_valid_api_keys()
    if not key:
        raise HTTPException(status_code=401, detail="Missing admin credentials.")
    if key not in valid_admin_keys:
        # If the key is a valid scoring API key, reject with 403 Forbidden!
        if key in valid_api_keys:
            raise HTTPException(
                status_code=403,
                detail="Insufficient privileges: scoring key cannot execute mitigation actions. Admin key required."
            )
        raise HTTPException(status_code=401, detail="Invalid admin credentials.")
    return key


async def verify_any_key(request: Request) -> str:
    key = request.headers.get("X-Admin-Key") or request.headers.get("X-API-Key")
    if not key:
        from src.api.rbac import session_key
        key = session_key(request)
    if not key:
        raise HTTPException(status_code=401, detail="Missing API credentials.")
    valid_admin_keys = _get_valid_admin_keys()
    valid_api_keys = _get_valid_api_keys()
    if key in valid_admin_keys or key in valid_api_keys:
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
@app.get("/", include_in_schema=False)
async def root_redirect():
    """Redirect root path to the SOC web app."""
    return RedirectResponse(url="/app/")

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
    model: str = Query(
        "xgb_only",
        description="Scoring mode for real-time automated scoring: 'xgb_only' (default, <1ms latency), 'ensemble' (calibrated stacking), 'rf_xgb' (tabular blend), or 'rf_only'",
    ),
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

    effective_mode = model
    if body.history_window is not None and model == "xgb_only":
        effective_mode = "ensemble"

    ensemble = get_default_ensemble()
    label, confidence, breakdown = ensemble.score_flow(
        features=body.features,
        history_window=hw_matrix,
        mode=effective_mode,
        feature_completeness=body.feature_completeness,
        source_mode=body.source_mode,
    )

    is_attack = (label.lower() != "benign")
    attack_family = label if is_attack else None
    attack_family_confidence = confidence if is_attack else None

    # Extract degraded confidence telemetry populated by score_flow
    degraded_conf = bool((breakdown or {}).get("degraded_confidence", False))
    comp_val = float((breakdown or {}).get("feature_completeness", body.feature_completeness if body.feature_completeness is not None else 1.0))
    deg_reason = (breakdown or {}).get("degradation_reason", None)

    # Extract IP endpoints from flow features (needed for both blocklist check and proposal)
    feat = body.features
    attacker_ip = str(feat.get("src_ip") or feat.get("Source IP") or "192.168.1.100")
    victim_ip = str(feat.get("dst_ip") or feat.get("Destination IP") or "10.0.0.1")
    mgr = get_manager()

    # === Ingress Fast-Path Interception: Layer 0 ➔ Layer 1 ===
    # When traffic arrives from an IP with an EXECUTED (human-approved) mitigation
    # action, intercept immediately at Ingress before model inference. This prevents
    # re-scoring and duplicate proposals for already-blocked IPs (Issue #2 root cause).
    if mgr.is_ip_blocked(attacker_ip):
        logger.info(
            "🛡️ Ingress blocklist: IP %s already has EXECUTED mitigation action — DROPPING before scoring",
            log_safe(attacker_ip),
        )
        # Broadcast dropped event to SOC dashboard
        get_broadcaster().broadcast_dropped({
            "attacker_ip": attacker_ip,
            "victim_ip": victim_ip,
            "reason": f"Traffic dropped by active Layer 0 firewall containment rule (Action before scoring)",
            "status": "DROPPED",
        })
        # Return a dropped result — no proposal generated, no duplicate queue entry
        result = ScoringResult(
            is_attack=False,
            confidence=0.0,
            attack_family=None,
            attack_family_confidence=None,
            feature_completeness=comp_val,
            degraded_confidence=False,
            degradation_reason="Traffic dropped by active Layer 0 firewall containment rule",
            proposed_action_id=None,
            meets_threshold=True,
            calibrated_threshold=None,
        )
        # Skip the rest of the scoring pipeline and return immediately
        return FlowResponse(result=result)
    else:
        # === Multi-Layer Arbitration Engine (Layers 0, 1, 2, 3) ===
        # 1. Layer 1 Ingress Rate Threshold Detector (H6)
        h6_result = _THRESHOLD_DETECTOR.record_flow(feat, src_ip=attacker_ip, dst_ip=victim_ip)

        # 2. Layer 1/2 Statistical Anomaly Detector (H9)
        # v5.3.0: the victim's own rate from H6 (never one flow's 'Flow Packets/s', ~10^5 for a µs flow), judged
        # against that destination's adaptive EWMA baseline instead of one fixed global baseline.
        agg_pps = h6_result.current_pps
        agg_bps = h6_result.current_bps
        h9_result = _H9_BASELINES.evaluate(victim_ip, agg_pps, agg_bps)

        # 3. Layer 3 Multi-Flow Botnet / Campaign Correlator (H8)
        flow_tot_pkts = int(feat.get("Total Fwd Packets", 0) + feat.get("Total Backward Packets", 0)) or 1
        flow_tot_bytes = int(feat.get("Fwd Packets Length Total", 0) + feat.get("Bwd Packets Length Total", 0)) or int(comp_val * 1500)
        campaign = _CAMPAIGN_CORRELATOR.ingest_flow_alert(
            src_ip=attacker_ip,
            victim_ip=victim_ip,
            attack_label=label,
            pps=agg_pps,
            bps=agg_bps,
            packet_count=flow_tot_pkts,
            byte_count=flow_tot_bytes,
            generate_ai_notes=False,
        )

        # 4. Multi-Layer Arbitration: Overriding stateless single-flow limits
        is_h6_critical = (h6_result.status == "CRITICAL")
        is_h9_critical = (h9_result.get("severity") in ("CRITICAL", "HIGH") and h9_result.get("is_anomaly", False))
        # v5.3.0: "≥3 sources" alone is not a campaign (a web server's normal clients are ≥3 sources), and
        # campaign.aggregate_pps sums per-flow 'Flow Packets/s' (~10^5 for a µs-long flow). Corroboration now
        # needs real rate evidence from H6 (victim packet rate over its window) or H9 (baseline anomaly).
        # DEV (run2): before, it flagged 88/90 benign and 90/90 flash-crowd sampled flows.
        rate_evidence = is_h6_critical or is_h9_critical
        is_campaign_active = (campaign.flow_count >= 3 and campaign.bot_count >= 3 and rate_evidence)
        is_aggregate_flood = (campaign.flow_count >= 3 and rate_evidence)

        consensus_mode = (breakdown or {}).get("mode", model)
        if not is_attack and is_aggregate_flood:
            # A 1-2 packet SYN handshake retry is indistinguishable from normal retries
            # in isolation, but H6/H9/H8 aggregate reasoning flags the coordinated surge.
            is_attack = True
            consensus_mode = "MULTI_LAYER_CAMPAIGN_CORROBORATION"

            # Grounded multi-layer corroboration heuristic certainty:
            # Base certainty: 0.90 for multi-layer confirmation
            # +0.03 for Critical rate surge (H6 >= 200 SYN/s)
            # +0.03 for Critical statistical baseline anomaly (H9 Z_pps >= 10σ)
            # +0.02 for verified botnet scale (H8 >= 10 distinct endpoints)
            comp_conf = 0.90
            if is_h6_critical:
                comp_conf += 0.03
            elif h6_result.status == "WARNING":
                comp_conf += 0.01
            if is_h9_critical:
                comp_conf += 0.03
            elif h9_result.get("is_anomaly"):
                comp_conf += 0.01
            if campaign.bot_count >= 10:
                comp_conf += 0.02
            confidence = min(0.98, comp_conf)

            if h6_result.current_syn_rate >= 50.0 or any("syn" in r.lower() for r in h6_result.triggered_rules):
                attack_family = "Distributed-SYN-Flood"
            elif h9_result.get("is_anomaly"):
                attack_family = "Unsupervised-Volumetric-Anomaly"
            else:
                attack_family = "Distributed-Coordinated-Campaign"
            label = attack_family
            attack_family_confidence = confidence

            # Explicitly annotate breakdown so operator knows confidence is a joint heuristic, not ML output
            breakdown = dict(breakdown or {})
            for m in ("random_forest", "xgboost"):  # v5.3.0: no placeholder verdicts for models that did not run
                if m not in breakdown:
                    breakdown[m] = {"status": "not scored", "label": None, "confidence": None}
            breakdown.update({
                "consensus_tier": "MULTI_LAYER_CAMPAIGN_CORROBORATION",
                "confidence_type": "MULTI_LAYER_CORROBORATION_HEURISTIC",
                "confidence_origin": "Multi-Layer Joint Corroboration (H6 Rate + H8 Campaign + H9 Baseline Anomaly)",
                "corroborating_layers": {
                    "H6_Rate_Detector": h6_result.status,
                    "H9_Anomaly_Detector": h9_result.get("severity"),
                    "H8_Campaign_Correlator": f"{campaign.bot_count:,} nodes across {campaign.flow_count:,} flows",
                }
            })

        proposed_aid = None
        try:  # v5.4.0 (live4): a destination that is under a live attack is the victim: never propose blocking it
            from src.api.live_router import get_live_state
            attacker_is_victim = attacker_ip in get_live_state().open
        except Exception:
            attacker_is_victim = False
        if attacker_is_victim:
            logger.info("Not proposing a block for %s: it is a victim under a live alert", log_safe(attacker_ip))
        # v6.0.0 (live7): lab hosts are contained on the lab switch (the agent's LAB_OVS_* plan). A host-level
        # iptables proposal for a lab address does nothing on this machine and crowded the Approvals page, so
        # the admin approved it instead of the lab step. Detection and the incident are unchanged.
        lab_source = _in_lab_scope(attacker_ip)
        if lab_source:
            logger.info("Not proposing a host block for lab address %s: lab containment goes via the agent plan",
                        log_safe(attacker_ip))
        if is_attack and not attacker_is_victim and not lab_source:
            try:
                is_campaign_scope = (is_aggregate_flood or (attack_family and "distributed" in attack_family.lower()) or campaign.flow_count >= 3)

                # Check if there is already an active pending campaign action for this victim
                existing_pending = mgr.get_pending()
                pending_campaign_aid = None
                for aid, a in existing_pending.items():
                    if a.get("victim_ip") == victim_ip and (
                        a.get("dossier", {}).get("is_campaign") or 
                        "Distributed" in a.get("action_type", "") or
                        "MULTI_LAYER" in (a.get("consensus_tier") or "")
                    ):
                        pending_campaign_aid = aid
                        break

                if is_campaign_scope:
                    if not pending_campaign_aid:
                        dossier = generate_campaign_dossier(
                            campaign_id=campaign.campaign_id,
                            victim_ip=victim_ip,
                            attack_family=attack_family or "Distributed-SYN-Flood",
                            bot_count=campaign.bot_count,
                            flow_count=campaign.flow_count,
                            aggregate_pps=campaign.aggregate_pps if campaign.aggregate_pps > 0 else agg_pps,
                            aggregate_mbps=campaign.aggregate_mbps,
                            participating_ips=sorted(list(campaign.participating_ips)),
                            h6_result=h6_result.to_dict(),
                            h9_result=h9_result,
                            analyst_notes=campaign.analyst_notes,
                            confidence=confidence,
                        )
                        containment_cmds = [
                            dossier["containment"]["firewall_rule"],
                            f"docker exec <web_container> sysctl -w net.ipv4.tcp_syncookies=1",
                        ]
                        proposed_aid = mgr.propose(
                            action_type=attack_family or "Distributed-SYN-Flood",
                            attacker_ip=f"Distributed Pool ({campaign.bot_count} endpoints)",
                            victim_ip=victim_ip,
                            reason=dossier["incident_summary"],
                            confidence=confidence,
                            commands=containment_cmds,
                            source="multi_layer_blue_team_engine",
                            dossier=dossier,
                            per_model_breakdown=breakdown,
                            consensus_tier=consensus_mode,
                        )
                        pending = mgr.get_pending()
                        get_broadcaster().broadcast_pending_update(list(pending.values()), len(pending))
                    else:
                        proposed_aid = pending_campaign_aid
                        # Periodically refresh the single pending campaign action with growing scale
                        if campaign.flow_count % 25 == 0 or campaign.flow_count in (3, 5, 10, 50, 100, 250, 500, 1000, 2500):
                            dossier = generate_campaign_dossier(
                                campaign_id=campaign.campaign_id,
                                victim_ip=victim_ip,
                                attack_family=attack_family or "Distributed-SYN-Flood",
                                bot_count=campaign.bot_count,
                                flow_count=campaign.flow_count,
                                aggregate_pps=campaign.aggregate_pps if campaign.aggregate_pps > 0 else agg_pps,
                                aggregate_mbps=campaign.aggregate_mbps,
                                participating_ips=sorted(list(campaign.participating_ips)),
                                h6_result=h6_result.to_dict(),
                                h9_result=h9_result,
                                analyst_notes=campaign.analyst_notes,
                                confidence=confidence,
                            )
                            mgr.update_campaign_telemetry(
                                action_id=pending_campaign_aid,
                                attacker_ip=f"Distributed Pool ({campaign.bot_count:,} endpoints)",
                                reason=dossier["incident_summary"],
                                confidence=confidence,
                                dossier=dossier,
                                per_model_breakdown=breakdown,
                                save=True,
                            )
                else:
                    dossier = generate_incident_dossier(
                        features=feat,
                        label=label,
                        confidence=confidence,
                        breakdown=breakdown,
                        attacker_ip=attacker_ip,
                        victim_ip=victim_ip,
                    )
                    containment_cmds = [
                        dossier["containment"]["firewall_rule"],
                        f"docker exec <container_id> iptables -A OUTPUT -d {victim_ip} -j DROP",
                    ]
                    proposed_aid = mgr.propose(
                        action_type=label,
                        attacker_ip=attacker_ip,
                        victim_ip=victim_ip,
                        reason=dossier["incident_summary"],
                        confidence=confidence,
                        commands=containment_cmds,
                        source="blue_team_detection_engine",
                        dossier=dossier,
                        per_model_breakdown=breakdown,
                        consensus_tier=consensus_mode,
                    )
                    pending = mgr.get_pending()
                    get_broadcaster().broadcast_pending_update(list(pending.values()), len(pending))
            except Exception as e:
                logger.warning("Failed to record proposed mitigation action: %s", e)

        # 5. Broadcast campaign updates to dashboard if active
        if is_campaign_active or is_h6_critical:
            camp_payload = {
                "is_ddos_campaign": True,
                "active_bot_count": campaign.bot_count,
                "distributed_ip_traceback": {ip: {"country": "Unknown", "country_code": "UN"} for ip in campaign.participating_ips},
                "aggregate_attack_volume": {
                    "total_packets": campaign.total_packets,
                    "aggregate_pps": round(campaign.aggregate_pps, 2),
                    "aggregate_bandwidth_bps": campaign.aggregate_bps,
                    "attack_types": {attack_family or label: campaign.flow_count},
                },
                "campaign_correlation_window_sec": 60,
                "first_seen_utc": None,
                "containment_plan": {
                    "action": "Distributed Botnet Containment",
                    "batch_ipset_block": list(campaign.participating_ips)[:20],
                    "subnet_null_route": True,
                },
            }
            get_broadcaster().broadcast_campaign_update(camp_payload)

        cal_thresh = None
        meets_thresh = True
        thresh_file = os.path.join(MODEL_DIR, "class_thresholds.json")
        if not os.path.isfile(thresh_file):
            root_thresh = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "models", "class_thresholds.json")
            if os.path.isfile(root_thresh):
                thresh_file = root_thresh
        if os.path.isfile(thresh_file):
            try:
                with open(thresh_file, "r", encoding="utf-8") as tf:
                    tdata = json.load(tf)
                    if label in tdata:
                        cal_thresh = float(tdata[label].get("threshold", 0.50))
                        meets_thresh = bool(confidence >= cal_thresh)
            except Exception as e:
                logger.warning("Could not load class thresholds: %s", e)

        result = ScoringResult(
            is_attack=is_attack,
            confidence=confidence,
            attack_family=attack_family,
            attack_family_confidence=attack_family_confidence,
            per_model_breakdown=breakdown,
            feature_completeness=comp_val,
            degraded_confidence=degraded_conf,
            degradation_reason=deg_reason,
            proposed_action_id=proposed_aid,
            meets_threshold=meets_thresh,
            calibrated_threshold=cal_thresh,
        )

        logger.info(
            "key=%s score_flow mode=%s attack=%s family=%s conf=%.3f degraded=%s",
            log_safe(key[:8]), log_safe(model), result.is_attack, log_safe(result.attack_family), result.confidence,
            degraded_conf,
        )

        # Decoupled fire-and-forget enqueue to dashboard broadcaster
        seq_info = (breakdown or {}).get("sequence_classifier") or {}
        caveat_text = seq_info.get("caveat") if seq_info.get("active") else None
        get_broadcaster().enqueue_flow({
            "src_ip": attacker_ip,
            "dst_ip": victim_ip,
            "label": label,
            "confidence": confidence,
            "is_attack": is_attack,
            "consensus_tier": consensus_mode,
            "per_model_breakdown": breakdown,
            "caveat": caveat_text,
            "feature_completeness": comp_val,
            "degraded_confidence": degraded_conf,
            "degradation_reason": deg_reason,
        })

        from src.agent.explain import explain_score

        basis = "multi_layer" if "MULTI_LAYER" in str((breakdown or {}).get("consensus_tier") or "") else "ml"
        expl = explain_score(result.is_attack, str(result.attack_family or label), result.confidence, basis,
                             h6=h6_result.to_dict(), h9=h9_result, dst=victim_ip)
        return FlowResponse(
            result=result,
            model_version="ensemble-rf-xgb-bilstm-v1",
            ood=_ood_assessment(confidence, body.features, label),
            low_slow=_lowslow_observe(feat, attacker_ip, victim_ip),
            explanation=expl.model_dump() if expl else None,
        )

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
        log_safe(key[:8]), len(body.flows), int(attack_mask.sum()),
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
        logger.error("Action %s execution failed: %s", log_safe(action_id), log_safe(message))
        raise HTTPException(status_code=500, detail="Action execution failed; see server logs.")

    pending = manager.get_pending()
    get_broadcaster().broadcast_pending_update(list(pending.values()), len(pending))

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
    pending = manager.get_pending()
    get_broadcaster().broadcast_pending_update(list(pending.values()), len(pending))
    return {
        "status": "rejected",
        "action_id": action_id,
        "message": message,
        "action": updated_action,
    }

