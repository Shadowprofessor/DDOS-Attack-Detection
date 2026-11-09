# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.0.0] — 2026-11-09

First release of the single-author, clean-history detection core. Numbered v4.0.0 to
supersede the prior public tags (which reached v3.1).

### Added
- **Supervised OOD / zero-day signal** — isotonic-calibrated XGBoost (`1 − max calibrated
  confidence ≥ tau`), tau calibrated to a 2% false-OOD rate; same model backs `/score/flow`
  and the leave-one-class-out evaluation.
- **Layer-7 low-and-slow detector** (Slowloris / R.U.D.Y.) wired into `/score/flow`.
- **Leakage-safe evaluation** — by-capture / chronological splits, binary + per-class metrics,
  and a **shortcut-feature audit** confirming the score is real signal, not an artefact.
- **Observability** — Prometheus-compatible `/metrics` endpoint and opt-in structured JSON logs.
- **One-command demo** (`python -m src.demo`) and dataset citations (`docs/DATASETS.md`).
- Authentication on the dashboard JSON/LLM endpoints (`/api/chat`, `/api/campaigns`,
  `/api/session-detection-summary`).

### Changed
- **Fail-closed authentication (F-1 fix)** — built-in test keys are honoured only under
  `DDOS_ENV=test`; the service refuses to start in production/staging without a configured key.
- Low-and-slow concurrency threshold is configurable via `DDOS_LOWSLOW_THRESHOLD`.
- Fresh-clone CI: `DummyClassifier` fallback when model artefacts are absent, and
  artefact-dependent tests skip with a clear reason (see README "Model artifacts").

### Security
- Removed the always-valid hardcoded admin/scoring credentials from the auth path.

### Notes
- Reported detection numbers are **CIC-DDoS2019 same-dataset** (separate extraction);
  cross-dataset generalization (CIC-IDS2017 / UNSW-NB15) is planned for v5.0.0 (M6).

[4.0.0]: https://github.com/Shadowprofessor/DDOS-Attack-Detection/releases/tag/v4.0.0
