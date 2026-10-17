# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v2.0] - 2026-10-18 - Intelligent Operations

### Added
- **BiLSTM Sequence Classifier** (`src/models/sequence_classifier.py`):
  - Bidirectional LSTM with temporal attention for multi-step packet sequence classification.
  - Harmonized to the canonical 13-class DDoS taxonomy (e.g. Syn, UDP, MSSQL, SSDP, NetBIOS, WebDDoS, PortScan, etc.).
  - Supports variable temporal windows (1 to 20 flows, padded with masking) and preserves explicit caveat tracking regarding synthetic pseudo-temporal windowing.
- **Calibrated Ensemble Scorer** (`src/models/ensemble.py`, `src/api/scoring_service.py`):
  - Blended scoring integrating Random Forest, XGBoost, and BiLSTM sequence models.
  - Multi-tier dynamic mode selection: `xgb_only` (production live default), `rf_xgb` (fast tabular pair), and full ensemble.
  - Strict weight capping for unverified temporal inputs (`rf: 0.425`, `xgb: 0.425`, `sequence_classifier: 0.15`) preventing circular synthetic validation bias.
  - **Latency Performance**: Single-flow scoring latency measured at **0.4ms – 0.8ms**, comfortably outperforming the sub-5ms operational SLA.
- **Nemotron LLM Agent Context Enrichment** (`src/agent/nemotron_agent.py`):
  - Real-time ensemble consensus reasoning (`FULL_UNANIMOUS`, `TABULAR_UNANIMOUS_SEQUENCE_DISSENT`, `TABULAR_SPLIT`, `SINGLE_MODEL`).
  - Ingestion of per-model breakdown (RF/XGBoost/LSTM confidence, predictions, and caveats) directly into LLM prompts for blast-radius analysis.
  - Hardened degraded-mode fallbacks when API keys or network routes are unavailable.
- **Real-Time WebSocket Dashboard** (`src/web/realtime_dashboard/`):
  - High-performance live telemetry streaming via FastAPI WebSocket (`/ws/dashboard`).
  - Secure first-message authentication handshake (`{"type": "auth", "key": "..."}`) with automatic 1008 disconnection on invalid/missing keys.
  - Decoupled scoring path via bounded async queues (`drop_oldest` backpressure, 10 Hz sampled telemetry) preserving sub-1ms `/score/flow` latency.
  - Gated operator dashboard with one-click Approve/Reject actions strictly routed through authenticated `/actions/approve` and `/actions/reject` REST endpoints.
- **Cloudflare Magic Transit Connector** (`src/mitigation/cloud_enforcers/cloudflare.py`):
  - Enterprise cloud scrubbing integration following the strict "propose, don't execute" invariant.
  - `propose_action()` writes `cloudflare_scrub` to `PendingActionManager` without calling external APIs.
  - Discrete `execute()` method strictly gated behind operator approval (`status: EXECUTED`).
  - Credential-shaped regex sanitization preventing API tokens and authorization headers from leaking into telemetry or logs.

### Verified & Audited
- **HITL Mitigation Gate Invariants**:
  - `tests/test_mitigation_approval_gate.py`: **14/14 passing** (100%).
  - `tests/test_mitigation_bypass.py`: **5/5 passing** (100%).
  - `tests/test_cloud_enforcers.py`: **17/17 passing** (100%).
  - Zero regression across all expanded surface areas (LLM reasoning, WebSocket dashboard, cloud enforcers).
- **Test Suite Pass Count**:
  - Full automated suite: **196/196 tests passing**.

## [v1.0] - 2026-10-11 - Verified Detection Core

### Added
- **Generalized Multi-Source Detection Pipeline**:
  - Standardized on a canonical 77-feature flow extraction schema (`CICFLOWMETER_FEATURE_NAMES`) matching CICFlowMeter conventions.
  - Added multi-dataset support in `src/features/dataset_registry.py` incorporating:
    - **CICDDoS2019**: Multi-class reflection and exploitation DDoS attack flows.
    - **InSDN**: Software-defined networking traffic with 77/77 features verified side-by-side between raw columns and standardized schema.
    - **CICIoT2023 (Partial Mirror)**: Rigorously verified train/test split disjointness (zero overlapping hashes across 14,000 train and 6,000 test flows) for Benign, SYN Flood, and UDP Flood classes.
    - **Synthetic SDN Isolation**: Held out from training split as eval-only sanity check to prevent 71 zero-filled features from introducing shortcut learning.
- **Pluggable Capture Backends** (`src/features/capture_backends/`):
  - `LibpcapBackend`: Live interface packet capture and offline PCAP ingestion with packet timestamp preservation.
  - `CloudFlowLogBackend`: Ingestion of VPC flow logs (AWS, Azure, GCP) with bidirectional 5-tuple conversation pairing within a 300-second window. Correctly pairs forward and reverse flows, populating backward packet and byte counts and achieving 24.68% (`19/77`) feature completeness with explicit completeness metadata.
  - `EBPFBackend`: Stub for Linux kernel XDP/eBPF ring-buffer flow collection with graceful non-Linux fallback.
  - Verified bitwise equivalence between direct-injection flows and backend-parsed network flows.
- **Security & Safety Guardrails**:
  - Implemented human-approval gate preventing automated firewall changes, docker network drops, or rule enforcement (`auto_execute=False` default).
  - Added dedicated mitigation bypass tests (`tests/test_mitigation_bypass.py` and `tests/test_mitigation_approval_gate.py`).
  - Added GitHub Actions CI workflow (`.github/workflows/tests.yml`) running Python 3.11 with an isolated mitigation safety gate check.

### Verified
- **Model Performance Gate**:
  - Evaluated candidate multi-dataset model achieving a weighted F1 of **0.983** against production baseline of **0.998**.
  - Production model artifacts (`src/models/*.joblib`) were **correctly NOT overwritten**, strictly enforcing the regression prevention gate.
  - Verified gate behavior empirically through OS file timestamp inspection.
- **Test Suite**:
  - Full suite: **142/142 tests passing** locally and configured in CI.
