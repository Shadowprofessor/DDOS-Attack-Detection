# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.1.1] — 2026-11-10

### Security — fixes for all open CodeQL high/medium alerts (19, pre-existing from v4.0.x)
- **DOM XSS (4 high)** in the legacy dashboard `static/app.js`: every server-derived string
  (IPs, action IDs, labels, caveats, dossier text, commands) is now passed through `escapeHtml`
  before `innerHTML`. `escapeHtml` no longer drops `0` values.
- **Remote property injection (1 high)**: taxonomy counts use a `Map`, so a flow label such as
  `__proto__` cannot pollute the object prototype.
- **Path injection (1 high)** in legacy `Codes/dashboard/app.py`: incident IDs used in file names
  must match `[A-Za-z0-9_-]{1,64}`.
- **Clear-text secret (1 high)**: generated dev keys are written to an owner-only `.dev-keys`
  file (gitignored, override with `DDOS_DEV_KEY_FILE`); only the path is printed. Prod/staging
  still refuse to start without configured keys.
- **Log injection (8 medium)**: new `src.obs.logging.log_safe()` escapes CR/LF and truncates
  untrusted values in the scoring service, mitigation manager and WS broadcaster.
- **Stack-trace / error exposure (1 medium)**: a failed approval returns a generic 500; the
  detail goes to the server log only.
- **Incomplete URL check (3 high, tests only)**: tests compare `urlparse(...).hostname`.

### Tests
- `tests/test_codeql_hardening.py` (log injection, path allowlist, no error leak, JS escaping).
- Dev-key test now checks the key is in the file and NOT in stdout or logs.

## [4.1.0] — 2026-11-10

### Added — M2: Nemotron AI threat analyst (Layer 3)
- `POST /api/analyst/analyze`: analyses ONE aggregated incident (`IncidentAggregate`) and
  returns a strict, validated `AnalysisResult` (attack type, MITRE IDs, severity 1-5,
  confidence, evidence, false-positive assessment, ranked recommended actions, next queries,
  report summary). Recommendations only - no path to any enforcer. API key + per-key rate limit.
- `GET /api/analyst/config`: non-secret analyst configuration.
- Versioned system prompt `prompts/threat_analyser.md`; strict JSON via forced tool-calling;
  pydantic validation -> retry once -> deterministic rule-based fallback.
- Config-driven model chain (`analyst:` YAML section / `DDOS_LLM_MODELS`), IDs verified against
  the live NIM model list: `nemotron-3-ultra-550b-a55b` -> `nemotron-3-super-120b-a12b` -> rules.
- One cached analysis per incident window; 90 s timeout; optional HMAC IP pseudonymisation.
- LLM latency / token / estimated-cost / cache / fallback / policy metrics on `/metrics`.
- Prompt-injection evaluation: 32 payloads x 3 conditions on live Nemotron, plus a held-out
  detector set and benign false-positive set (`src/agent/injection_eval.py`, EVAL_NOTES §6).

### Security
- Layered prompt-injection defence: sanitiser (invisible chars stripped, tags escaped, bounded
  strings, `<telemetry>` wrapping) + untrusted-data system prompt + **code-enforced output
  policy** (pinned incident ID, human approval forced on every action, foreign-IP actions
  dropped, injected downgrades overridden or flagged `llm_ml_disagreement`, canary redaction).
- `/api/chat` now routes through the hardened client and sanitises its live context.

### Known limitations
- `nemotron-3-super-120b-a12b` is in the NIM catalog but returns 404 for this account, so the
  effective chain is Ultra -> rules.
- The regex instruction detector does not generalise (0/12 on held-out phrasings); safety does
  not depend on it - see EVAL_NOTES §6.

## [4.0.2] — 2026-11-09

### Added
- Supply-chain & CI security: `security.yml` (gitleaks secret scan, Bandit static analysis,
  pip-audit dependency audit [advisory], CycloneDX SBOM artifact) and `codeql.yml`
  (CodeQL for Python + JavaScript, weekly + on PR).
- Dependabot for pip and GitHub Actions.
- `SECURITY.md` disclosure policy and `.well-known/security.txt` (RFC 9116).
- CycloneDX SBOM attached to each GitHub release.
- README status badges (Tests, Security Scans, CodeQL, Release).

### Security
- **CWE-502:** `SequenceClassifier.load()` now uses `torch.load(weights_only=True)` with an
  explicit allowlist (sklearn scaler/imputer + numpy array/dtype reconstructors only), so a
  tampered checkpoint cannot execute code. Regression test added.
- MD5 used for leakage-eval row de-duplication is now marked `usedforsecurity=False` (B324);
  hashes are unchanged.
- Bandit `B104` (`"0.0.0.0"` placeholder IPs, not socket binds) annotated with justified
  `# nosec` comments.

## [4.0.1] — 2026-11-09

### Fixed
- CI: the live NVIDIA NIM test (`tests/test_nvidia_nim_live.py`) now **skips** when
  `NVIDIA_API_KEY` is unset (instead of `sys.exit(1)`), so the suite passes on fresh
  clones / CI without a key.

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

[4.1.0]: https://github.com/Shadowprofessor/DDOS-Attack-Detection/releases/tag/v4.1.0
[4.0.2]: https://github.com/Shadowprofessor/DDOS-Attack-Detection/releases/tag/v4.0.2
[4.0.1]: https://github.com/Shadowprofessor/DDOS-Attack-Detection/releases/tag/v4.0.1
[4.0.0]: https://github.com/Shadowprofessor/DDOS-Attack-Detection/releases/tag/v4.0.0
