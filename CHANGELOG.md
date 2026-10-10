# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
