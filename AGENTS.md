# AGENTS.md — DDoS Detection & Mitigation System

## What this project is
A layered DDoS/DoS detection and mitigation system with four coordinated layers:

### Four-Layer Architecture
- **Layer 0 — Mitigation Engine & Operator Approval Gate**: PendingActionManager
  with `auto_execute=False`. Pluggable enforcers: OpenFlow, IPSet/iptables,
  Docker container isolator, Cloudflare [mocked in this build], AWS Shield.
  All actions require explicit human approval before execution.
- **Layer 1 — Telemetry & Ingress Packet Sanity Filter**: RFC-compliant TCP
  flag validation (SYN+FIN, NULL, XMAS, PSH/URG without ACK), packet boundary
  checks, IP fragmentation evasion detection (TINY_MF, FRAGMENT_FLOOD,
  IP_FRAGMENT), 77-feature CICFlowMeter flow representation.
- **Layer 2 — ML Ensemble**: XGBoost + Random Forest/ExtraTrees multi-class
  attack classifiers with degraded-input calibration for asymmetric telemetry.
  BiLSTM SequenceClassifier is CAPPED — secondary/optional only, with
  documented synthetic-windowing caveat. Not primary.
- **Layer 3 — LLM Reasoning Agent**: NVIDIA Nemotron 3 Ultra via NIM/OpenRouter
  API. Multi-flow alert correlation, false-positive suppression, structured
  JSON output (explanation, severity, proposed_action, requires_human_approval),
  offline fallback heuristics when API is unavailable.

### Capture Backends
Three supported capture backends, configured via `CAPTURE_BACKEND` env var:
- **eBPF/XDP** (primary): Line-rate packet capture, Linux only
- **libpcap** (fallback): Cross-platform, lower throughput
- **Cloud flow log ingest**: AWS VPC Flow Logs, GCP Flow Logs for cloud
  deployments without direct packet access

### Dashboard
FastAPI + WebSockets real-time SOC dashboard at `localhost:8000`. Features:
- One-click operator approval gate for pending mitigation actions
- `[DEGRADED INPUT]` flags when telemetry is asymmetric/incomplete
- Threat score display (0–100), attack class, GeoIP traceback
- LLM reasoning summaries from Nemotron agent

### Cloudflare Connector
The Cloudflare enforcer (`src/mitigation/cloud_enforcers/cloudflare.py`) is
**MOCKED ONLY** in this build. It logs proposed IP block rules but does NOT
make live API calls. See README.md Section 8 for activation requirements.

### 13-Class Canonical Attack Taxonomy (locked in Prompt 4b)
```
BENIGN, SYN_FLOOD, UDP_FLOOD, ICMP_FLOOD, HTTP_FLOOD, SLOWLORIS,
DNS_AMPLIFICATION, NTP_AMPLIFICATION, SSDP_AMPLIFICATION, LAND_ATTACK,
XMAS_SCAN, NULL_SCAN, FRAGMENT_FLOOD
```
All models, evaluation metrics, and confusion matrices use this taxonomy.
Do not add, remove, or rename classes without explicit sign-off.

---

## Hard rules — do not violate these
1. NEVER write or suggest code whose purpose is to GENERATE or LAUNCH a DDoS/DoS
   attack against any real target. Attack-traffic generation is only allowed
   inside an isolated local test harness (e.g. a Docker-networked sandbox with
   synthetic traffic generators like `hping3` or `scapy` pointed at a
   container we own, never at a real IP). Always ask me before adding any
   traffic-generation code, even for testing.
2. Any mitigation action that blocks/null-routes a real IP, modifies live
   firewall rules, or calls a third-party scrubbing API (Cloudflare/AWS Shield)
   must default to "propose, don't execute" — log the recommended action and
   require my explicit approval before it runs for real.
3. Models and datasets must come only from what's listed in DATASETS.md —
   do not download or train on scraped/unknown traffic captures.
4. Every new feature must come with a test (pytest) and must not be marked
   done until `pytest` passes and I've reviewed the diff.
5. Before implementing anything non-trivial: STOP, explore the relevant code
   first, write an implementation plan, and wait for my explicit approval
   before writing code.

## Human-in-the-Loop Mandate
No function may call iptables, docker exec/stop/disconnect, nftables, tc,
or any OpenFlow DROP/mitigation rule as a DIRECT result of a model
prediction or an LLM response. Every such action must:
  (a) be written to a pending-actions store with full context and a reason,
  (b) require a separate, explicitly-invoked "approve" step (CLI command,
      dashboard button, or similar) triggered by a human,
  (c) default `auto_execute=False` wherever this flag exists, with no code
      path that flips it to True without me changing it myself.

**AST enforcement**: `tests/test_mitigation_bypass.py` scans all source files
using Python's AST parser to verify `_execute_action` is ONLY called inside
`PendingActionManager.approve()`. This test must be re-run after every new
enforcer is added. No automated execution, all actions through
PendingActionManager — no exceptions.

This applies to the EXISTING auto-mitigation in docker_enforcer.py and
ai_threat_analyzer.py just as much as to any new code.

## Tech stack
- Python 3.11, scikit-learn, xgboost, pandas, numpy
- PyTorch (for the BiLSTM SequenceClassifier secondary model)
- FastAPI for the real-time scoring service + WebSocket SOC dashboard
- NVIDIA NIM API or OpenRouter API for Nemotron 3 Ultra calls (Layer 3)
- Docker Compose for local sandbox + services (`deploy/docker-compose.yml`)
- Helm chart for Kubernetes deployment (`deploy/helm/`)
- systemd service file for bare-metal deployment (`deploy/systemd/`)
- pytest for all tests

## Directory layout (target)
data/            # raw + processed datasets (gitignored, large files)
notebooks/       # exploration only, not production code
src/
  features/      # Layer 1 packet sanity filter & flow feature extraction
  models/        # Layer 2 ML ensemble (RF/XGBoost/BiLSTM)
  agent/         # Layer 3 Nemotron orchestration layer (prompts, tool calls)
  mitigation/    # Layer 0 approval gate, PendingActionManager, pluggable enforcers
  api/           # FastAPI real-time scoring + dashboard endpoints
  web/           # Real-time SOC dashboard (FastAPI + WebSockets)
Codes/
  controller/    # Ryu SDN controller
  mininet/       # Mininet topology scripts
  security/      # Attacker forensics utilities (7 modules)
  ml/            # Legacy ML training scripts
config/
  environments/  # Per-environment YAML configs (development, staging, production)
deploy/          # Docker Compose, Helm chart, systemd service files
tests/           # Pytest automated test suite
docs/
  DATASETS.md
  ARCHITECTURE.md
  RUNBOOK.md
  eval/          # Confusion matrices, precision/recall/F1 per class

## Testing mandate
- Full suite: currently 219 tests (on main), all passing
- `test_mitigation_bypass.py` must be re-run after every new enforcer module
- Per-dataset precision/recall must be reported separately for each dataset
  (CICDDoS2019, CICIoT2023, CAIDA) — not averaged together
- Model changes include a confusion matrix + precision/recall/F1 per class
  logged to `docs/eval/`
- No TODOs left unexplained
- README/RUNBOOK updated if behavior changed

## Definition of done for any task
- Code has tests, tests pass locally
- No TODOs left unexplained
- README/RUNBOOK updated if behavior changed
- Model changes include a confusion matrix + precision/recall/F1 per class
  logged to `docs/eval/`

---

## Current repository state (as of Prompt 15)
This is an EXISTING working prototype with substantial extensions:
- A Ryu/Mininet SDN controller doing live detection
- Random Forest / ExtraTrees + XGBoost models
- A Nemotron 3 Ultra integration via OpenRouter (ai_threat_analyzer.py)
- A FastAPI + WebSocket real-time SOC dashboard
- A non-bypassable approval-gated mitigation engine (Layer 0)
- Layer 1 packet sanity filter with fragmentation evasion detection
- Docker Compose, Helm, and systemd deployment packaging
- Per-environment config templates (development, staging, production)
Known bugs and safety gaps are tracked in docs/KNOWN_ISSUES.md — fix those
before or alongside any new feature, never after.

## Priority order for all work in this project
1. P0 — safety/security bugs (unapproved auto-mitigation, hardcoded secrets,
   crash bugs) — always fix these first, in their own commits, with tests.
2. P1 — the new CICFlowMeter + CICDDoS2019 + XGBoost/LSTM pipeline, built as
   an ADDITIVE parallel path. Do not delete, replace, or restructure the
   existing Mininet/Ryu/RF code without my explicit sign-off first.
3. P2 — new features, dashboard polish, extra datasets.

## Secrets
No API keys, tokens, or credentials in source files, ever. Load from
environment variables or a gitignored .env file only. If you find a hardcoded
secret anywhere in this repo while working, stop and flag it to me before
continuing, even if it's not the file you were asked to touch.
