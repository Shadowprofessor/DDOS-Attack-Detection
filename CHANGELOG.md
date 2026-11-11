# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [4.7.0] — 2026-11-11

### Added — threat hunting + security self-assessment
- **Two hypothesis-driven hunts** (`docs/hunts/README.md`, rules in `src/hunt/rules.py`):
  H1 low-rate distributed reflection (≥50 reflectors, each ≤20 pps, together ≥200 pps from
  amplification source ports) and H2 distributed slow-read L7 abuse (long HTTP flows with tiny
  client windows and starved downloads across ≥10 sources). Both were executed over the v4.6.1
  lab flows (~221k): **no findings**, which is expected for that data. Inputs were verified as
  populated, and neither rule fires on the flash crowd. Not yet validated on positive traffic.
- **STRIDE threat model** (`docs/security/STRIDE.md`): 18 threats, each with its in-code
  mitigation, the test/CI evidence, and residual risk.
- **Bug-hunt report** (`docs/security/bug_hunt.md`): 12 items covering authz/IDOR, CSRF, SSRF,
  injection, deserialisation, rate limits and more.

### Fixed (bug hunt)
- IR write endpoints had no rate limit. Now limited per actor (`DDOS_IR_WRITE_RATE_PER_MIN`, 120).
- `/api/chat` (each message may be an LLM call) had no rate limit. Now limited per key
  (`DDOS_CHAT_RATE_PER_MIN`, 20).
- `/api/chat` no longer returns 500 on a non-object JSON body; messages are capped at 2,000 chars.

### Tests
- `tests/test_hunt_rules.py` (11, positive + negative per rule), `tests/test_bug_hunt_fixes.py` (7).
- Gated like CI (no `NVIDIA_API_KEY`). The opt-in live NIM test failed locally on two runs because
  of the NVIDIA endpoint (60 s read timeout, then HTTP 503), not because of a code change. It is
  re-checked before v5.0.0.

## [4.6.1] — 2026-11-11

### Added — purple-team lab runs (owner-approved traffic generation; docs: `docs/purple_team/README.md`)
- `lab/traffic/generator.py`: LAB-ONLY gated generator. It runs only after `lab.safety` planning
  passes: WSL2 + a Mininet host network namespace, allowlisted lab scope, caps, kill switch.
  Every packet's source and destination are re-checked, total packets are capped, and the kill
  switch is checked every tick. Sending lives in `_emit_*` functions reachable only through
  `GatedTrafficRunner` (AST-tested). It reports `achieved_pps`.
- `lab/traffic/orchestrate.py`: isolated Mininet LAN (OVS, no NAT/route out), per-scenario victim
  pcaps. The manifest is saved after every scenario.
- `--containment`: a separate net with a deliberately opened NAT path. nftables
  (`lab/traffic/containment.nft`) must drop lab egress. Verdict is contained / NOT contained /
  inconclusive, with diagnostics.
- `src/eval/lab_analysis.py`: pcaps → real L1 (threshold + signature + low-and-slow) / L2 ensemble
  / OOD / rule L3 → coverage matrix, MTTD, false positives, ATT&CK Navigator layer
  (`docs/purple_team/{results.json,coverage.md,navigator_layer.json}`).

### Results (first measured run, reported as measured)
- **Containment proven.** 3/3 probes to TEST-NET-1 reached the boundary and were dropped; 0 on
  the uplink.
- **Detected:** UDP flood, NTP reflection, HTTP low-and-slow. **Partial:** SYN flood (L3 called it
  low-and-slow), DNS reflection (generic UDP family), novel/OOD mix (OOD 48%).
  **False positives:** flash crowd (L1 on 41% of flows), benign baseline (3%).
- **L2 ensemble flagged 0 of 1,452 sampled lab SYN-flood flows** and 1–16% for the other floods.
  Consistent with v4.4.0: the classifier does not transfer beyond CIC-DDoS2019.
- MTTD ≈ 1 s after flow export (≈ 61 s including a 60 s idle-timeout export); low-and-slow 117 s.

### Fixed
- `family_from_text()` matched "ood" inside "fl**ood**", so "UDP flood" analyses were routed to
  the zero-day playbook. Now whole-word matching, with a regression test.

## [4.6.0] — 2026-11-11

### Added — purple-team lab safety layer (docs: `docs/purple_team/README.md`). No traffic generation.
- `lab/lab_scope.yaml` + `lab/safety.py`: code-enforced scope. Allowed networks must be private,
  at most /16, and not loopback/link-local/multicast/reserved. Every host role must be inside
  them. Public IPv4/IPv6 and non-allowlisted private targets are refused. Rate, duration and
  concurrency are capped. Kill switch: file, env var or `trip()`. The runner refuses to start
  unless WSL2 **and** Mininet are detected.
- `lab/scenarios/*.yaml` + `lab/library.py`: 8 scenarios (benign baseline, flash crowd, SYN flood,
  UDP flood, simulated NTP and DNS reflection, HTTP low-and-slow, novel/OOD mix), each mapped to
  ATT&CK with expected family, layers and MTTD budget. The schema forbids extra fields (no
  commands, no raw addresses).
- `lab/runner.py`: mock runner. Every safety check, then per-tick *descriptions* only (no
  packets). The kill switch is re-checked before every tick. `to_aggregate()` builds a synthetic
  aggregate for a replay-based pipeline check (documented as *not* detection evidence).

### Tests
- `tests/test_lab_safety.py` (37):
  - public and non-allowlisted targets refused, bad scope networks rejected;
  - caps enforced; refuses to start outside the lab;
  - kill switch stops a running scenario within one tick and blocks start (file + env);
  - scenario validation, mock pipeline wiring;
  - **AST scan: `lab/` contains no networking/process code**.

## [4.5.0] — 2026-11-11

### Added — SOC web app, part 3 (docs: `docs/SOC_APP.md`)
- **Live feed** page: `/ws/dashboard` stream over the session cookie (same-origin), with
  filters, pause/resume and a windowed list (2,000 events kept).
- **Replay** page (scenario + speed → replay incident, stages shown, dry-run proposals only).
- **AI analyst** chat page (read-only `/api/chat`, optional incident scope, provenance shown).
- **Settings & health** page + `GET /api/system` (versions, model artifacts, analyst config with
  key presence only, IR settings).
- Legacy dashboard served at `/legacy` too. Both URLs send `Deprecation` / `Link` /
  `Warning` headers. Removal is in v5.0.0.
- README screenshots in `docs/img/`, captured by an opt-in Playwright spec.

### Changed
- `/api/chat`, the legacy dashboard JSON endpoints and `/api/analyst/config` accept the web-app
  session (CSRF on POST). `/ws/dashboard` accepts a same-origin session cookie. The cookie check
  is shared with `/ws/incidents` via `rbac.ws_session_key`.
- Scored-flow broadcasts now include `src_ip` / `dst_ip`. Without them the feed could not show
  who was talking to whom.

### Fixed
- Long incident titles in a dropdown widened the AI analyst page past a 375 px screen. Stat
  cards on the overview were vertically misaligned.

### Tests
- pytest `tests/test_soc_pages.py` (7): session chat + CSRF, analyst config via session,
  `/api/system` has no secrets, legacy deprecation headers, `/ws/dashboard` cookie auth +
  cross-origin rejection.
- Vitest 23 (+3). Playwright 21 (+8): **axe-core 0 serious/critical on every page**, no CSP
  violations, 375 px on every page, reduced motion, live feed receives a scored flow, replay,
  chat refuses to act, settings shows no secrets, legacy deprecation.

## [4.4.0] — 2026-11-11

### Added — cross-dataset evaluation (docs: `docs/eval/cross_dataset.md`)
- `src/eval/cross_dataset.py`: CIC-DDoS2019-trained ensemble tested on a CICIoT2023 CSV sample
  (Benign / DDoS-SYN_Flood / DDoS-UDP_Flood, 2,000 rows each, fixed seed, SHA-256 manifest).
  Option B mapping: 20 of 77 CICFlowMeter features have a CICIoT2023 counterpart. The other 57
  are filled three ways (zero / CIC-DDoS2019 Benign median / production heuristic), plus a non-ML
  protocol/flag baseline. Results in `docs/eval/cross_dataset/results.json`; the doc table is
  generated from it.

### Results (reported honestly: inconclusive)
- Attack F1: **1.000** (zero fill), **0.050** (benign-median fill), **0.966** (production path;
  benign FPR **14.2%**). The protocol rule alone: F1 0.916, benign FPR **36.9%**.
- These numbers depend on how the unmapped features are filled, and the three classes are easy
  to separate by protocol and flags. This measures sensitivity to a feature-schema mismatch,
  **not** generalisation. The OOD detector flagged ~0% of these shifted inputs.
- **The same-dataset caveat stays.** No same-extractor test (pcaps through our CICFlowMeter
  extractor) has been run.

### Tests
- `tests/test_cross_dataset.py` (9 + 1 slow opt-in): mapping coverage, deterministic seeded
  sampling + manifest, imputation strategies, metrics on a known scorer, family rules, baseline
  reproduction against the committed results, doc table == results.json. `DDOS_RUN_SLOW=1`
  re-runs the ensemble and compares exactly.

## [4.3.1] — 2026-11-11

### Added — SOC web app, part 2 (docs: `docs/SOC_APP.md`)
- **Incident detail** page: lifecycle actions by role (containment dialog with justification),
  AI analyst panel labelled as a recommendation with provenance, aggregated telemetry, playbook
  runner ("Request action" only proposes), linked actions with rollback state, notes,
  hash-chained timeline with verification status, MD/PDF export, CERT-In draft + "mark reported"
  (admin).
- **Approvals** page (admin): pending actions with estimated blast radius, reversibility,
  rollback TTL and incident link; approve or reject (with reason) through a confirmation dialog;
  active blocks with a live rollback countdown, extend or make permanent (with reason).
- **Live updates** over `/ws/incidents` with session-cookie auth (same-origin handshakes
  only), reconnect with backoff, polling fallback, status chip.
- API: `GET /api/approvals` (read-only feed) and `POST /api/incidents/{id}/analyze` (stores the
  analyst result on the incident; never proposes or executes). `/actions/approve|reject|pending`
  accept the web-app session + CSRF.

### Fixed
- `requirements.txt` now pins `websockets==16.0`. Plain `uvicorn` has no WebSocket library, so
  a fresh install rejected every `/ws/*` upgrade (dashboard and incidents). Local runs passed
  only because the package happened to be installed. Caught by the Playwright live-update test
  in CI.

### Tests
- pytest `tests/test_soc_detail.py` (12): session approve/reject + CSRF, analyst 403, approvals
  feed + countdown, analysis stored without new proposals, WS cookie auth + cross-origin reject.
- Vitest 20 (+5). Playwright 13 (+5): analyst workflow (triage, note, playbook steps, AI panel,
  MD/PDF download), analyst approve via API → 403, admin approve → countdown, keyboard-only
  extend, contain with justification + CERT-In draft, live WS update without reload.

## [4.3.0] — 2026-11-10

### Added — SOC web app, part 1 (`dashboard/`, docs: `docs/SOC_APP.md`)
- React 19 + Vite 8 + strict TypeScript app served by FastAPI at `/app`, with a
  traversal-safe page fallback that never shadows `/api`. Pinned `package-lock.json`.
- **Login** exchanges an API key for a server-side session (`ddos_session`: HttpOnly, Secure,
  SameSite=Strict). New id on every login, idle + absolute expiry, role re-checked every request,
  login rate limit. `GET /api/session`, `POST /api/session/logout`.
- **CSRF**: synchroniser token required on cookie-authenticated mutations (403 otherwise);
  header-key API clients unchanged.
- **Strict CSP** (no `unsafe-inline`/`unsafe-eval`) + nosniff, no-referrer, Permissions-Policy,
  frame denial on `/app*` and `/api/*`; HSTS in production/staging.
- **Overview** page + `GET /api/overview`: open incidents, pending approvals, MTTC,
  false-positive rate, open-by-severity chart, CERT-In countdowns, recent incidents, health.
- **Incidents** page: filter, sort, paginate. `GET /api/incidents` gains `sort` and `min_severity`.
- Dark theme (cyan / violet / amber; red only for severity 5), skip link, visible focus,
  reduced-motion, no horizontal scroll at 375 px.
- CI workflow `webapp.yml`: lint, typecheck, Vitest, build, `npm audit --audit-level=high`,
  Playwright against the real API. Dependabot for npm.

### Changed
- CORS is same-origin by default (was `*`); set `DDOS_CORS_ORIGINS` to allow listed origins.

### Tests
- pytest `tests/test_soc_session.py` (20): cookie flags, rotation, expiry, revocation, CSRF,
  CSP/headers, SPA fallback + traversal, overview. `test_ir_api.py` +1 (sort/filter).
- Vitest (15): API client (CSRF only on mutations, same-origin only, error mapping), auth store
  (memory-only), severity colours. Playwright (8): login, bad key, list filter/sort/paginate,
  XSS renders as text, logout, cookie flags + no key in storage, CSRF-less POST → 403, 375 px.

## [4.2.0] — 2026-11-10

### Added — M3: incident-response backend (`src/ir/`, docs: `docs/IR.md`)
- **Persistence**: SQLite via SQLAlchemy 2.x (`ir.database_url`, default `data/ir.db`);
  tables `incidents`, `incident_events`, `actions`, `playbook_runs`, `schema_version`.
- **NIST SP 800-61r3 lifecycle** `new → triage → investigating → contained → eradicated →
  recovered → closed` (+ `false_positive`), explicit transition table, CSF 2.0 mapping.
  `contained` requires a human-approved action or a written justification.
- **Tamper-evident timeline**: every event is SHA-256 hash-chained; `verify_chain()` is shown on
  every incident and export.
- **YAML playbooks** (`playbooks/`: SYN flood, UDP reflection/amplification, DNS amplification,
  L7 low-and-slow, zero-day/OOD) with strict schema validation. `propose_action` steps only call
  `PendingActionManager.propose()`.
- **CERT-In 6-hour timer** (Directions No. 20(3)/2022-CERT-In, 28.04.2022): deadline for
  severity ≥ threshold, `ddos_cert_in_seconds_remaining`, warnings at 1 h / 15 min / breach,
  report **draft** (never auto-submitted), "reported" acknowledgement.
- **Export**: Markdown and PDF (reportlab) incident reports with escaped untrusted text and
  AI output labelled as a recommendation.
- **Auto-rollback**: incident-linked approved blocks revert after a TTL (default 600 s) via the
  new `PendingActionManager.revert()`. Retry with backoff, restart-safe, admin extend/permanent
  with reason.
- **Replay engine**: stored incident aggregates go through L1 → L2 → rule-based L3 into
  `is_replay` incidents, with a dry-run action manager (no real proposals).
  Scenarios in `replay/scenarios/`.
- **API** (`src/api/ir_router.py`): incidents CRUD/transition/notes/actions/playbook steps,
  export, CERT-In draft/reported, replay, rollback status/extend; `WS /ws/incidents`
  (auth on connect, server→client only).
- **RBAC** (`src/api/rbac.py`): `analyst` (`DDOS_API_KEYS`) vs `admin` (`DDOS_ADMIN_KEYS`), deny by
  default, correct 401 vs 403. Actors are recorded as key fingerprints, never key material.
- **Metrics**: `ddos_incidents{state}`, MTTD/MTTC histograms, `ddos_rollbacks_total{result}`,
  CERT-In remaining. A dependency-free `Histogram` was added to `src/obs/metrics.py`.
- `ir:` config block in all six environment YAMLs.

### Changed
- `requirements.txt` pinned to exact, tested versions; added `sqlalchemy`, `reportlab`;
  bumped `requests` 2.34.2, `scapy` 2.8.0, `pyyaml` 6.0.3 (pip-audit: 0 known vulnerabilities).
- CI runs on Python 3.14 (numpy 2.5 / xgboost 3.4 have no 3.11 wheels).

### Tests
- `tests/test_ir.py` (54) and `tests/test_ir_api.py` (15): lifecycle legal/illegal matrix,
  hash-chain tamper cases, playbook validation, PENDING-only proposals, AST guard that `src/ir/`
  never approves or executes, CERT-In timing with an injected clock, export escaping and PDF
  round-trip, rollback TTL/extend/restart/retry, replay isolation, RBAC endpoint × role matrix,
  422 without traces, WS auth.

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
