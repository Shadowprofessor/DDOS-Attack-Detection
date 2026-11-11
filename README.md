# Advanced Multi-Layer DDoS Detection & Mitigation Platform

[![Tests](https://github.com/Shadowprofessor/DDOS-Attack-Detection/actions/workflows/tests.yml/badge.svg)](https://github.com/Shadowprofessor/DDOS-Attack-Detection/actions/workflows/tests.yml)
[![Security Scans](https://github.com/Shadowprofessor/DDOS-Attack-Detection/actions/workflows/security.yml/badge.svg)](https://github.com/Shadowprofessor/DDOS-Attack-Detection/actions/workflows/security.yml)
[![CodeQL](https://github.com/Shadowprofessor/DDOS-Attack-Detection/actions/workflows/codeql.yml/badge.svg)](https://github.com/Shadowprofessor/DDOS-Attack-Detection/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/Shadowprofessor/DDOS-Attack-Detection)](https://github.com/Shadowprofessor/DDOS-Attack-Detection/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Python 3.14](https://img.shields.io/badge/Python-3.14-blue.svg)](https://www.python.org/)
[![SOC Web App](https://github.com/Shadowprofessor/DDOS-Attack-Detection/actions/workflows/webapp.yml/badge.svg)](https://github.com/Shadowprofessor/DDOS-Attack-Detection/actions/workflows/webapp.yml)
[![Security: Gated Mitigation](https://img.shields.io/badge/Security-Approval%20Gated-orange.svg)](src/mitigation/)

An advanced, defense-in-depth Distributed Denial of Service (DDoS) detection, attacker forensics, and intelligent mitigation platform designed for Software-Defined Networks (SDN) and modern cloud edge infrastructures. All detection code is strictly defensive; attack-traffic generation is restricted to isolated local test harnesses targeting owned containers only. Mitigation actions require explicit human approval — no automatic execution.

> ✅ **~590 pytest + 24 Vitest + 21 Playwright tests** in CI (fresh clone uses a DummyClassifier
> fallback). Read the **[technical report](REPORT.md)** for the honest evaluation: strong
> same-dataset numbers, inconclusive cross-dataset, and a real lab run where the ML missed a SYN
> flood but the rules caught most attacks. **[60-second demo](docs/DEMO.md)**.
> **[Runbook](docs/RUNBOOK.md)**: copy-paste commands for every way to run it (app, scoring, replay, Mininet lab, analysis, tests).
> **Live demo (v5.2.0)**: a Mininet attack shows up on the SOC website **3.8–5.8 s** after it starts (runbook block H, `docs/DETECTION_LATENCY.md`).
>
> **[Detection time](docs/DETECTION_LATENCY.md)**: measured ~81 ms per flow end-to-end, and lab attacks flagged by L1 within ~1–2 s of starting (window-bound).

```mermaid
flowchart LR
  T[Traffic] --> L1[L1 rules] --> L2[L2 ML + OOD] --> AGG[Incident aggregate] --> L3[L3 analyst<br/>recommends only]
  L3 --> IR[Incident response<br/>lifecycle, playbooks, CERT-In]
  IR -- propose --> GATE[Human approval gate] -- admin approves --> ENF[Enforcers]
  IR --> UI[SOC web app /app]
```

---

## 🚀 Quick demo (M1 detection core)

One command drives the real scoring app in-process and replays benign + attack +
low-and-slow + OOD flows:

```bash
python -m src.demo
```

It shows: benign correctly cleared, known attacks classified by the supervised ensemble,
a **Slowloris/R.U.D.Y. low-and-slow alert**, and a **zero-day-suspected (OOD) flag** at a
threshold calibrated to a 2% false-OOD rate.

### Headline results — CIC-DDoS2019 (same-dataset, separate extraction); cross-dataset: see below

> **Scope:** these are **CIC-DDoS2019 only**, train vs. a *separate extraction* (`test_real_v2`)
> with exact-duplicate rows removed. `test_real_v2` shares ~13k identical rows with the training
> set, so it is the **same CIC-DDoS2019 recordings re-split, not an independent capture**.
> Generalisation beyond it is **not established**: the CICIoT2023 check was inconclusive
> (v4.4.0) and the ML missed the lab SYN flood (v4.6.1). See [REPORT.md](REPORT.md) §5.

**Attack vs. benign (binary):**

| Metric | All 77 features | Artefacts removed¹ |
|---|---|---|
| Detection rate | **100%** | 99.9% |
| Benign false-positive rate | 0.05% | 0.74% |
| Binary F1 | **1.000** | 0.999 |

¹ A shortcut-feature audit (`src/models/eval_shortcut.py`) removed the CICFlowMeter artefact
candidates (Flow Duration, Fwd/Bwd Header Length, Init Fwd/Bwd Win Bytes); performance barely
moves, so the binary score is **not** an artefact shortcut — top features are real attack signal
(packet-length stats, SYN/ACK/URG flag counts, Bwd Packets/s).

The attack/benign decision is robust; the leakage *damage* is confined to fine-grained
**family attribution** — per-class macro-F1 is **0.52** leakage-safe vs **0.85** under a leaky
random split (−0.33). See [`docs/EVAL_NOTES.md`](docs/EVAL_NOTES.md) for the full tables,
the shortcut audit, and the leave-one-class-out OOD study.

**M1 detection components** (additive to the existing pipeline):
- `src/models/ood_detector.py` + `src/models/train_ood_model.py` — supervised OOD / zero-day
  signal from an **isotonic-calibrated XGBoost** (`1 − max calibrated P(class) ≥ tau`), the
  **same model and tau** that back `/score/flow` and the LOCO evaluation
  (`models/ood_model.joblib`, tau at 2% false-OOD).
- `src/features/l7_lowslow.py` — Layer-7 low-and-slow (Slowloris/RUDY) detector.
- `src/models/eval_split.py` — leakage-safe (by-capture / chronological) splits.
- `src/models/anomaly_novelty.py` — IsolationForest benign-anomaly monitor (secondary,
  **OFF by default**; it does **not** detect CICDDoS2019 attacks — see below).

**Regenerate artifacts** (needs the parquet data under `data/`):
```bash
python -m src.models.train_ood_model --target-false-ood 0.02   # deployed OOD model -> models/ood_model.joblib
python -m src.models.eval_ood        --target-false-ood 0.02   # leave-one-class-out OOD table
python -m src.models.eval_leakage    --cap 12000               # leakage before/after (binary + per-class)
python -m src.models.eval_shortcut   --cap 10000               # shortcut-feature audit
python -m src.models.train_novelty   --data data/combined_training_set.parquet --val data/test_real_v2.parquet
```

**Datasets & required citations:** see [`docs/DATASETS.md`](docs/DATASETS.md) (CIC-DDoS2019,
CIC-IDS2017, CICIoT2023, UNSW-NB15).

### Getting the data (for a fresh clone)

Datasets and trained model artefacts are **gitignored** (large). To run the demo end-to-end:

1. **Download CIC-DDoS2019** from the Canadian Institute for Cybersecurity:
   <https://www.unb.ca/cic/datasets/ddos-2019.html> (CIC-IDS2017 and UNSW-NB15 for the M6
   cross-dataset eval; CICIoT2023: <https://www.unb.ca/cic/datasets/iotdataset-2023.html>).
2. **Produce the 77-feature parquets** the pipeline expects at
   `data/combined_training_set.parquet` and `data/test_real_v2.parquet` (CICFlowMeter features +
   a `Label` column); place any `data/ciciot2023/*.csv` similarly.
3. **Install + regenerate + run:**
   ```bash
   pip install -r requirements.txt
   python -m src.models.train_ood_model --target-false-ood 0.02   # -> models/ood_model.joblib
   python -m src.demo                                             # low-and-slow + zero-day flag
   pytest tests/ -q
   ```

Reported numbers are **CIC-DDoS2019 same-dataset** (see the headline above and
`docs/EVAL_NOTES.md`).

**Cross-dataset check (v4.4.0): inconclusive, reported as such.** The CIC-DDoS2019 models were
tested on a CICIoT2023 CSV sample (Benign / SYN flood / UDP flood, 6,000 rows) by mapping the 20
CICIoT2023 columns that have a CICFlowMeter counterpart. Depending only on how the other 57
features are filled, attack F1 ranges from 1.00 to 0.05, and a two-line protocol rule also catches
every attack. This shows sensitivity to a feature-schema mismatch, **not** generalisation. A
same-extractor test (pcaps through our CICFlowMeter extractor) has not been done. Details and
caveats: [`docs/eval/cross_dataset.md`](docs/eval/cross_dataset.md).

### Model artifacts

Trained models (`src/models/*.joblib`, `models/*.joblib`) are **gitignored** and not in the
repo or release assets. Regenerate them from the data above:

```bash
python -m src.models.train_cicddos2019     # stage1/stage2 + encoders + preprocessor
python -m src.models.train_ood_model --target-false-ood 0.02   # models/ood_model.joblib
```

**Fresh clone / CI:** the test suite runs **without** artifacts — the scoring service falls
back to a `DummyClassifier` (enabled when `CI`, `GITHUB_ACTIONS`, `PYTEST_CURRENT_TEST`, or
`DDOS_ALLOW_TEST_DUMMY` is set), and artifact-dependent tests (e.g. `test_model_artifacts.py`)
**skip with a clear reason**. The dummy fallback is for testing only and is refused in
production/staging.

> ⚠️ **Honest caveats** (see [`docs/EVAL_NOTES.md`](docs/EVAL_NOTES.md)): the unsupervised
> IsolationForest does **not** detect CICDDoS2019 attacks (0% at 1% FPR) — kept only as a
> benign-anomaly monitor. Supervised OOD is a weak signal for *family novelty* (LOCO mean
> AUROC ≈ 0.61) but rarely misses an unseen attack as *Benign* (≈6.6%).

---

## 🧠 AI Threat Analyst (Layer 3 — NVIDIA Nemotron 3.5 Lightning; Ultra optional)

The analyst triages **one aggregated incident at a time** (never packets) and returns a strict,
validated analysis: attack type, MITRE ATT&CK IDs, severity 1-5, confidence, evidence,
false-positive assessment, ranked recommended actions, next queries and a report summary.
**It recommends; it never executes** — there is no code path from the analyst to any enforcer.

```bash
curl -s -X POST localhost:8000/api/analyst/analyze -H "X-API-Key: $KEY" \
     -H "Content-Type: application/json" -d @incident.json      # IncidentAggregate JSON
```

| Piece | Where |
|---|---|
| Versioned system prompt | `prompts/threat_analyser.md` |
| Input / output contracts (pydantic) | `src/agent/schemas.py` |
| Sanitiser + `<telemetry>` wrapping + IP pseudonymisation | `src/agent/sanitize.py` |
| Model chain, tool-calling, cost/latency metrics | `src/agent/llm_client.py` |
| Validate → retry once → fallback, cache, **output policy** | `src/agent/threat_analyst.py` |
| API (`/api/analyst/analyze`, `/api/analyst/config`) | `src/api/analyst_router.py` |

- **Models** (v5.1.0; ids verified against the live NIM model list):
  - Default: `nvidia/nemotron-3.5-lightning-30b-a3b`, with tool calling confirmed live. Override it
    with `NEMOTRON_MODEL` (one model) or `DDOS_LLM_MODELS` (a comma-separated chain).
  - Optional escalation: with `DDOS_LLM_ESCALATE_ULTRA=true` (default **off**), incidents the rules
    rate severity 5 try `nvidia/nemotron-3-ultra-550b-a55b` first (`DDOS_LLM_ESCALATION_MODEL`).
  - Last step is always the deterministic rule-based analysis, which is also what tests and CI use.
- **Latency:**
  - Lightning: 7.9 s for the live structured analysis, with reasoning disabled. With reasoning on,
    the first attempt ran out of tokens and returned nothing.
  - Ultra: ~30–45 s (timeout 90 s).
  - Either way it runs once per incident window (cached), off the fast path; the rule-based
    result is instant.
- **Prompt-injection defence (layered):** (1) sanitise attacker strings, escape tags, wrap in
  `<telemetry>`; (2) system prompt declares telemetry untrusted; (3) **code-enforced output policy** —
  `incident_id` is pinned, every action requires human approval, actions targeting IPs not in the
  incident are dropped, injected downgrades are overridden or flagged for review, prompt canaries are
  redacted. **Live result (32 payloads, Nemotron Ultra):** 34% injection success with no defences
  → **0/31** with prompt defences (95% upper bound ≈10%; static payloads, not adaptive attacks).
  The code-layer guarantees hold even for a fully compromised model (tested). The regex
  instruction detector does **not** generalise (0/12 held-out) and no safety property depends on
  it. Details: [`docs/EVAL_NOTES.md` §6](docs/EVAL_NOTES.md).
- **Observability:** `ddos_llm_requests_total`, `ddos_llm_latency_seconds_{sum,count}`,
  `ddos_llm_tokens_total`, `ddos_llm_cost_usd_total`, `ddos_analyst_cache_total`,
  `ddos_analyst_fallback_total`, `ddos_analyst_policy_violations_total` on `/metrics`.
- The operator chat (`/api/chat`) is read-only, requires a key, and uses the same sanitiser.

---

## 🟣 Purple-Team Lab (v4.6.0 safety layer · v4.6.1 + v5.1.0 measured runs)

Attack simulation is **lab-only** and the safety rules are enforced in code (`lab/safety.py`). Only
private, allowlisted lab addresses can be targets; public IPs are refused. Rate, duration and
concurrency are capped. A kill switch is checked every tick. The runner refuses to start unless it
detects WSL2 + Mininet. The safety layer, 12 ATT&CK-mapped scenarios (8 in v4.6.0, 4 in v5.1.0) and a mock runner are
all tested in CI.

**What's measured (Mininet on WSL2; `run2` v4.6.1 + `run3` v5.1.0, 12 scenarios):**
- **Containment proven in both runs.** Lab egress was dropped by nftables, with nothing on the uplink.
- **Measured attack types (10):** SYN, UDP, ICMP, TCP ACK and TCP RST floods; NTP and DNS
  reflection (simulated reflector); HTTP low-and-slow; LAND; a novel/OOD mix.
  - **Fully detected (4):** UDP flood, NTP reflection, HTTP low-and-slow, ICMP flood.
  - **Partial (6):** SYN, ACK and RST floods; DNS reflection; LAND; novel mix.
  - L1 fired on all 10. The rule-based L3 did **not detect** the SYN, ACK and RST floods or the
    novel mix.
- **2 false positives** (a flash crowd tripped the L1 rate thresholds).
- **The ML ensemble missed the lab SYN flood entirely** (0/1,452; also 0/20 ICMP flows). v5.1.0
  traced this to the training data: lab-shaped flows are 46:1 `Benign` in CIC-DDoS2019. It is a
  documented limitation, not retrained.
- Not measured: multi-Gbps floods, real reflectors, slow-read, carpet-bombing.

Coverage matrix, MTTD and findings: [`docs/purple_team/README.md`](docs/purple_team/README.md).

---

## 🔎 Threat Hunting & Security Review (v4.7.0)

- **Hunts:** two documented hypotheses with rules and tests, run over the lab data:
  low-rate distributed reflection, and distributed slow-read
  ([`docs/hunts/README.md`](docs/hunts/README.md)).
- **STRIDE threat model:** [`docs/security/STRIDE.md`](docs/security/STRIDE.md).
- **Bug hunt:** [`docs/security/bug_hunt.md`](docs/security/bug_hunt.md). 12 items; the fixed ones
  (rate limits on IR writes and LLM chat, chat input handling) have regression tests.

---

## 🖥️ SOC Web App (v4.3 – v5.0)

A React SOC console served at **`/app`**: login, an overview with KPIs and CERT-In countdowns,
and a filterable incident list. It uses an HttpOnly session cookie, CSRF tokens and a strict CSP
with no inline script or style. Server text always renders as text.

```bash
cd dashboard && npm ci && npm run build   # then open http://localhost:8000/app
```

Pages: overview, incidents, incident detail (AI recommendation panel, playbooks, timeline,
MD/PDF export), approvals (admin), live feed, replay, AI analyst chat (read-only), and
settings/health. Every page passes axe-core with 0 serious/critical issues and fits a 375 px screen.

Governance & assurance: [control mapping](docs/grc/control_mapping.md) (NIST CSF 2.0, ISO 27001:2022, CIS v8, CERT-In, D3FEND) · [risk register](docs/grc/risk_register.md) · [STRIDE](docs/security/STRIDE.md).

| Overview | Incident detail |
|---|---|
| ![Overview](docs/img/overview.png) | ![Incident detail](docs/img/incident-detail.png) |
| **Approvals (admin)** | **Live feed** |
| ![Approvals](docs/img/approvals.png) | ![Live feed](docs/img/live-feed.png) |

Details and the security model: [`docs/SOC_APP.md`](docs/SOC_APP.md).

---

## 🚨 Incident Response (M3, v4.2.0)

Detections become tracked incidents with a **NIST SP 800-61r3 lifecycle**, a **hash-chained
timeline**, YAML **playbooks**, a **CERT-In 6-hour reporting timer** with a report draft,
**Markdown/PDF export**, **auto-rollback** of approved blocks (default 10 min, admin can extend),
and a **replay engine** for demos and regression tests. Analysts can triage, investigate, take
notes and request actions. Only admins can contain, close, extend rollbacks or pull the
CERT-In draft. Approval of any block is still `POST /actions/approve/{id}` with an admin key.

```bash
curl -s -X POST localhost:8000/api/replay -H "X-API-Key: $KEY" \
     -H "Content-Type: application/json" -d '{"scenario": "syn_flood"}'   # replay incident
curl -s localhost:8000/api/incidents -H "X-API-Key: $KEY"                 # list
```

Full reference (lifecycle diagram, RBAC matrix, CERT-In flow, rollback semantics):
[`docs/IR.md`](docs/IR.md).

---

## 📋 Version History

| Version | What | Status |
|---|---|---|
| v4.0.x | Clean history; detection core; CI + supply-chain security | Released |
| v4.1.x | Nemotron AI analyst (recommend-only); CodeQL fixes | Released |
| v4.2.0 | Incident-response backend (NIST 800-61r3, playbooks, CERT-In, rollback, replay) | Released |
| v4.3.x | SOC web app: sessions/CSRF/CSP, incidents, approvals, live updates | Released |
| v4.4.0 | Cross-dataset evaluation (CICIoT2023): inconclusive, reported honestly | Released |
| v4.5.0 | Remaining SOC pages, axe-clean, screenshots | Released |
| v4.6.x | Purple-team lab: safety layer, then measured Mininet runs + containment | Released |
| v4.7.0 | Threat hunts, STRIDE, bug hunt | Released |
| **v5.0.0** | GRC control map + risk register, technical report, citation check, legacy dashboard removed | Released |

Per-release details: [CHANGELOG.md](CHANGELOG.md) · [GitHub releases](https://github.com/Shadowprofessor/DDOS-Attack-Detection/releases).

**Roadmap (next):** retrain/adapt ML on lab + CICIoT2023 pcaps through our own extractor ·
adaptive L1 baselines (fix flash-crowd false positives) · handshake-aware low-and-slow and
source-port reflection rules · artifact hash pinning · per-user OIDC sign-in.

---

## ⚡ 2-Minute Quickstart (Docker Compose)

### Prerequisites
- Docker 24+
- Docker Compose v2+
- 4 GB RAM

### Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/Shadowprofessor/DDOS-Attack-Detection.git
   cd DDOS-Attack-Detection
   ```

2. **Copy environment configuration**:
   ```bash
   cp config/environments/development.yaml .env.yaml   # edit API keys if needed
   ```

3. **Build and start all services**:
   ```bash
   docker-compose -f deploy/docker-compose.yml up --build
   ```

4. **Access the platform**:
   - Open **http://localhost:8000** — SOC dashboard
   - Open **http://localhost:8000/docs** — FastAPI OpenAPI spec

### Health Check
```bash
docker-compose -f deploy/docker-compose.yml ps
```
All services should show "healthy".

### Stopping
```bash
docker-compose -f deploy/docker-compose.yml down
```

---

## ⚙️ Configuration Reference

Per-environment configuration files live in [`config/environments/`](config/environments/):

| File | Use Case |
|------|----------|
| `development.yaml` | Local Mininet/Docker sandbox (no live cloud credentials needed) |
| `staging.yaml` | Pre-production / integration testing |
| `production.yaml` | Bare-metal or cloud VPC production deployment |

### Key Variable Groups

| Group | Variables | Description |
|-------|-----------|-------------|
| **Scoring Service** | `scoring_service.host`, `scoring_service.port`, `scoring_service.model_dir` | FastAPI server binding and model artifact paths |
| **API Credentials** | `llm.openrouter_api_key`, `llm.nvidia_api_key`, `cloud_providers.cloudflare.api_token` | LLM and cloud provider authentication (loaded from `${ENV_VAR}` references) |
| **Controller** | `controller.host`, `controller.openflow_port`, `controller.poll_interval` | SDN controller binding and flow polling settings |
| **Rate Limiting** | `scoring_service.rate_limit.window_seconds`, `max_requests`, `max_batch_size` | API rate limiting thresholds |
| **Dashboard** | `scoring_service.host`, `scoring_service.port` | Dashboard host and port binding |
| **Cloud Providers** | `cloud_providers.cloudflare.api_token`, `cloud_providers.cloudflare.account_id` | Cloud scrubbing service configuration |

> ⚠️ **Never commit literal API keys.** All secrets must be references to environment variables (e.g., `${OPENROUTER_API_KEY:-}`) or loaded from a local `.env` file excluded from version control.

---

## 📖 Operator Guide

### 6a. SOC web app

Open `http://localhost:8000/` (redirects to `/app/`) and sign in with an analyst or admin key.
The old `/dashboard` page was removed in v5.0.0 and redirects to `/app/`. Pages and the security
model: [`docs/SOC_APP.md`](docs/SOC_APP.md). Guided tour: [`docs/DEMO.md`](docs/DEMO.md).

- **Approve / reject** pending mitigations on **Approvals** (admin). Every approval goes through a
  confirmation dialog and `PendingActionManager.approve()`. Incident-linked blocks auto-revert
  after 10 minutes unless extended with a reason.
- **`DEGRADED`** on a live-feed row means the flow was scored with incomplete telemetry (for
  example, a single-direction ingress tap leaves 23 of 77 CICFlowMeter features unobserved).
  Hover to see the reason. Confidence is dampened accordingly.

### 6b. CLI Approval Workflow

```bash
# List all pending mitigation actions
python -m src.mitigation.cli list-pending

# Approve a specific action by ID
python -m src.mitigation.cli approve <action_id>

# Reject a specific action by ID
python -m src.mitigation.cli reject <action_id>

# Bulk-approve all pending (use with caution)
python -m src.mitigation.cli approve-all
```

---

## 🛡️ Security Model

This section explains the platform's security guarantees in plain language — written for security managers and auditors, not just developers.

### 7a. Human-in-the-Loop Guarantee

No IP is blocked, no firewall rule is installed, and no container is isolated without a human operator explicitly approving the action. The AI detects and recommends — it never acts autonomously.

- **PendingActionManager**: Every proposed mitigation action (block an IP, install a firewall rule, isolate a container) is first written to a pending action queue. Nothing executes until a human reviews and approves it.
- **`auto_execute=False`**: Every mitigation action is created with automatic execution disabled by default. There is no code path that sets this to `True` without a human operator explicitly changing it.

### 7b. What the AI Does vs. What Humans Decide

**The AI does:**
- Traffic analysis and flow feature extraction
- Attack classification (13-class taxonomy)
- Threat scoring (0–100 severity scale)
- LLM-based reasoning and incident correlation (Nemotron 3.5 Lightning; Ultra optional)
- Mitigation recommendation (what action to take and why)

**Humans decide:**
- Whether to execute any blocking, rate-limiting, or isolation action
- Whether to approve, reject, or defer each proposed mitigation
- When to escalate to cloud scrubbing services (Cloudflare, AWS Shield)

### 7c. AST-Verified No-Bypass Guarantee

The codebase includes a static code audit (`tests/test_mitigation_bypass.py`) that automatically fails if any code path is found that calls `_execute_action` outside of the human approval gate. This test runs on every commit. It uses Python's Abstract Syntax Tree (AST) parser to scan all source files — meaning it catches bypass attempts at the code structure level, not just through runtime testing.

### 7d. Defense-Only Policy

Attack traffic generation is restricted to isolated local Mininet/Docker sandboxes targeting sandbox-internal IPs only. No code in this repository can send attack traffic to public internet hosts. All traffic generation scripts in the test harness are pointed exclusively at container-internal addresses (e.g., `10.0.0.x` inside Mininet).

### 7e. Secret Handling

All API tokens (OpenRouter, NVIDIA NIM, Cloudflare) are loaded from environment variables only. No secrets appear in source code or committed configuration files. The `config/environments/*.yaml` files use `${ENV_VAR:-}` syntax to reference secrets without embedding them.

---

## ☁️ Cloudflare Connector: Mocked-Only in This Build

The Cloudflare enforcer (`src/mitigation/cloud_enforcers/cloudflare.py`) is **MOCKED in this build**. It logs proposed IP block rules to the incident log and `pending_actions.json` but does **NOT** make live API calls to Cloudflare.

### What Would Be Required to Go Live

1. An active Cloudflare account with **Magic Transit** or **Spectrum** enabled (Magic Transit requires a minimum /24 prefix and enterprise contract)
2. A valid `CLOUDFLARE_API_TOKEN` with **Zone:Edit** and **Firewall:Edit** permissions set in your `.env` file
3. Your protected IP prefix registered in Cloudflare's Magic Transit dashboard
4. Change `CLOUDFLARE_MOCK_MODE=false` in your `production.yaml` configuration
5. Run the integration test:
   ```bash
   python -m pytest tests/test_cloudflare_enforcer.py -k live --cf-token $CLOUDFLARE_API_TOKEN
   ```
   to verify connectivity

> ⚠️ **Do not enable live mode** without first verifying with your Cloudflare account representative that Magic Transit is provisioned for your prefix.

---

## 🏛️ System Architecture (4-Layer Defense)

The platform operates across four coordinated layers, forming a defense-in-depth pipeline:

```text
       Incoming Raw Traffic / PCAP / Network Stream
                           │
                           ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Layer 1: Telemetry & Ingress Packet Sanity Filter            │
 │ • RFC-compliant TCP flag validation (SYN+FIN, NULL, XMAS, PSH/URG without ACK)    │
 │ • Packet boundary checks and size anomaly guards             │
 │ • IP fragmentation evasion detection (TINY_MF, FRAGMENT_FLOOD, IP_FRAGMENT) │
 │ • 77-feature CICFlowMeter flow representation                │
 └─────────────────────────────────────────────────────────────┘
                           │ Validated Flow Features
                           ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Layer 2: Fast Machine Learning Classifiers                  │
 │ • XGBoost & Random Forest / ExtraTrees multi-class attack classifiers │
 │ • Asymmetric host-ingress telemetry adaptation (feature completeness calibration) │
 │ • Confidence scoring with degraded-input handling           │
 │ • BiLSTM SequenceClassifier with pseudo-temporal windows (optional) │
 └─────────────────────────────────────────────────────────────┘
                           │ High-Confidence Alerts & Anomalies
                           ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Layer 3: Generative LLM Reasoning Agent (Nemotron Lightning) │
 │ • Multi-flow alert correlation & attacker attribution       │
 │ • False-positive suppression & threat intelligence lookup   │
 │ • Contextual mitigation strategy recommendation             │
 │ • Structured JSON output: explanation, severity, proposed_action, requires_human_approval │
 └─────────────────────────────────────────────────────────────┘
                           │ Proposed Mitigation Actions
                           ▼
 ┌─────────────────────────────────────────────────────────────┐
 │ Layer 0: Mitigation Engine & Operator Approval Gate         │
 │ • PendingActionManager: Strict Human-in-the-Loop review     │
 │ • All actions auto_execute=False; persisted to pending_actions.json │
 │ • Multi-target enforcers: OpenFlow, IPSet, iptables, Docker container isolator, Cloudflare, AWS Shield │
 │ • Zero unapproved automated execution (AST enforced — code audit verified) │
 │ • Approval gate: CLI command, dashboard button, or admin API triggers human approval │
 └─────────────────────────────────────────────────────────────┘
```

---

## 🌟 Key Capabilities

### 1. Layer 1 Ingress Sanity Filtering (`src/features/packet_sanity_filter.py`)
- **RFC Protocol Conformance**: Intercepts contradictory TCP flags (SYN+FIN, SYN+RST, NULL scans, XMAS, PSH/URG without ACK).
- **Packet Boundary Checks**: Verifies header lengths against total payload sizes and enforces sub-minimum payload thresholds.
- **Fragmentation Evasion Interception**:
  - `IP_FRAGMENT`: Detects non-first IP fragments.
  - `TINY_MF_FRAGMENT`: Catches More-Fragments (`MF=1`) datagrams smaller than 576 bytes (RFC 791 minimum reassembly buffer limit) used in evasion attacks.
  - `FRAGMENT_FLOOD`: Stateful sliding-window tracker identifying fragment surges exceeding 50 fragments/sec per flow key.

### 2. Layer 2 Machine Learning Ensemble (`src/models/ensemble.py`)
- **Dual-Model Decision Tree Ensemble**: Combines tuned XGBoost and Random Forest classifiers trained on bidirectional PCAP and benchmark flow datasets.
- **Degraded Input Calibration**: Accommodates asymmetric single-interface telemetry (e.g., eBPF ingress taps where 23 backward-looking features are unobserved) by dampening confidence scores and tagging alerts with `feature_completeness`.
- **SequenceClassifier (BiLSTM)**: Optional secondary model for temporal flow analysis, with documented synthetic-windowing caveat.

### 3. Layer 3 AI Security Analyst (`src/agent/nemotron_agent.py`)
- Powered by **NVIDIA Nemotron 3.5 Lightning** (default since v5.1.0; `NEMOTRON_MODEL` overrides) via NVIDIA NIM / OpenRouter APIs.
- Triages security alerts, correlates distributed spoofed sources, cross-references threat scores, and generates human-readable incident summaries with actionable mitigation recommendations.
- Implements strict fallback heuristics when API quotas or offline constraints apply.

### 4. Non-Bypassable Layer 0 Mitigation Engine (`src/mitigation/`)
- **Absolute Approval Gate**: No model prediction or LLM response can directly modify firewall tables or drop packets. All actions must be queued in `PendingActionManager` for explicit operator approval.
- **Pluggable Enforcers**:
  - **SDN Controller**: Injects OpenFlow 1.3 `OFPFC_ADD` drop flow-mods to edge switches.
  - **Linux IPSet & iptables**: Generates atomic kernel drop rules for volumetric floods.
  - **Docker Sandbox Enforcer**: Disconnects or rate-limits compromised containers in test topologies.
  - **Cloud Scrubbing Adapters**: Proposes IP access rules for Cloudflare and AWS Shield APIs.

### 5. Attacker Forensics Utilities (`Codes/security/`)
- **Attacker Profiling (`attacker_profiler.py`)**: Scores attacker IPs (0–100) based on packet rate, target spread, and payload ratio.
- **GeoIP Traceback (`geo_locator.py`)**: Resolves attacker IPs to country, city, ISP, and ASN metadata for both public IPs and Mininet local subnets.
- **Attack Vector Classification (`attack_type_classifier.py`)**: Classifies detected attacks into SYN Flood, ICMP Echo Flood, UDP Amplification, LAND Attack, or Volumetric DDoS categories.
- **Forensic Incident Logger (`forensics_logger.py`)**: Writes structured JSON incident reports per attack event for security audits and post-mortem analysis.
- **Dynamic Threat Intelligence (`threat_intelligence.py`)**: Maintains a live IP blacklist/whitelist with automatic block expiration for adaptive response.
- **AI Threat Analyzer (`ai_threat_analyzer.py`)**: Lightweight local threat scoring module used as offline fallback when the Nemotron LLM agent is unavailable.
- **Docker Sandbox Enforcer (`docker_enforcer.py`)**: Disconnects or rate-limits compromised containers within local test harnesses; queued through the Layer 0 approval gate.

### 6. Real-Time SOC Command Dashboard (`src/web/realtime_dashboard/`)
- Fast, asynchronous web UI backed by FastAPI and WebSockets.
- Live attack telemetry feed with `[DEGRADED INPUT]` flags, dynamic threat score metrics (0–100), attacker geo-traceback, and one-click operator mitigation authorization.

---

## 🧪 Testing & Validation

The codebase includes an extensive automated test suite covering unit tests, integration paths, adversarial robustness checks, and AST security audits:

```bash
# Run the complete test suite (250+ tests)
python -m pytest tests/ -q

# Run structural packet sanity filter tests
python -m pytest tests/test_packet_sanity_filter.py -v

# Run IP fragmentation evasion tests
python -m pytest tests/test_packet_sanity_filter.py -k fragmentation_evasion -v

# Run the strict AST mitigation approval gate safety audit
python -m pytest tests/test_mitigation_bypass.py -v
```

---

## 🔒 Security & Safety Mandate

1. **Defense-Only Policy**: This repository contains strictly defensive detection, feature extraction, and mitigation code. Attack traffic generation scripts are restricted to synthetic, isolated local test harnesses targeting local containers only.
2. **Mandatory Approval Gate**: All destructive actions (IP blocking, rule injection, container termination) require human confirmation via CLI or the SOC dashboard.
3. **No Hardcoded Secrets**: All API tokens (OpenRouter, NVIDIA NIM, Cloudflare) are loaded strictly from environment variables or local `.env` configurations.
4. **AST Safety Audit**: Static code audit (`tests/test_mitigation_bypass.py`) confirms `_execute_action` is ONLY called inside `PendingActionManager.approve()` — no hidden call sites exist in `src/api` or `src/mitigation`.

---

## 📁 Repository Structure

```text
DDOS-Attack-Detection/
├── src/
│   ├── features/           # Layer 1 packet sanity filter & flow extractor
│   ├── models/             # Layer 2 ML ensemble (XGBoost, Random Forest, BiLSTM)
│   ├── agent/              # Layer 3 Nemotron 3 Ultra LLM reasoning agent
│   ├── mitigation/         # Layer 0 approval gate & pluggable enforcers
│   ├── api/                # FastAPI scoring service & WebSocket feeds
│   └── web/                # Real-time SOC dashboard interface
├── tests/                  # Pytest automated test suite (250+ tests)
├── models/                 # Model artifacts & adversarial evaluation reports
├── Codes/                  # SDN Controller & Mininet emulation scripts
├── config/                 # Per-environment configuration (development, staging, production)
├── deploy/                 # Docker Compose, Helm chart, systemd service files
├── docs/                   # System architecture, datasets, and runbooks
├── requirements.txt        # Python dependencies
├── README.md               # Main project documentation
└── LICENSE                 # MIT License — see LICENSE file for details
```

---

## 👤 Author & Maintainer

- **Sachit Sharma** ([@Shadowprofessor](https://github.com/Shadowprofessor))

---

## 🙏 Authorship

This platform is an original implementation by **Sachit Sharma**, featuring:
- A non-bypassable, approval-gated mitigation engine (Layer 0)
- Adversarially-hardened packet sanity filtering with fragmentation evasion detection (Layer 1)
- An LLM-based threat triage agent using NVIDIA Nemotron (Layer 3)
- A real-time FastAPI/WebSocket SOC dashboard
- A 250-test automated verification suite with AST-based security auditing

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
