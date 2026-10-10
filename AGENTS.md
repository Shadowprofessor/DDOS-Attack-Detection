# AGENTS.md — DDoS Detection & Mitigation System

## What this project is
A layered DDoS/DoS detection and mitigation system:
- Layer 1: flow feature extraction from pcap/live traffic (CICFlowMeter-style)
- Layer 2: fast ML classifiers (Random Forest / XGBoost baseline, optional LSTM)
- Layer 3: an LLM reasoning agent (Nemotron 3 Ultra via NVIDIA NIM / OpenRouter
  API) that triages alerts, correlates them, and proposes mitigation actions
- Layer 0: a mitigation engine that enforces actions (rate limit, block, alert)

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

## Tech stack
- Python 3.11, scikit-learn, xgboost, pandas, numpy
- PyTorch (for the LSTM/CNN-LSTM secondary model)
- FastAPI for the real-time scoring service
- NVIDIA NIM API or OpenRouter API for Nemotron 3 Ultra calls (Layer 3)
- Docker Compose for local sandbox + services
- pytest for all tests

## Directory layout (target)
data/            # raw + processed datasets (gitignored, large files)
notebooks/       # exploration only, not production code
src/
  features/      # flow feature extraction
  models/        # training + inference code for RF/XGBoost/LSTM
  agent/         # Nemotron orchestration layer (prompts, tool calls)
  mitigation/    # rule generation + enforcement (sandboxed by default)
  api/           # FastAPI real-time scoring + dashboard endpoints
tests/
docs/
  DATASETS.md
  ARCHITECTURE.md
  RUNBOOK.md

## Definition of done for any task
- Code has tests, tests pass locally
- No TODOs left unexplained
- README/RUNBOOK updated if behavior changed
- Model changes include a confusion matrix + precision/recall/F1 per class
  logged to `docs/eval/`

---

## Current repository state (as of exploration report)
This is an EXISTING working prototype, not a greenfield build. It has:
- A Ryu/Mininet SDN controller doing live detection + auto-mitigation
- Random Forest / ExtraTrees models trained on synthetic FlowStatsfile.csv
- A Nemotron 3 Ultra integration via OpenRouter (ai_threat_analyzer.py)
- A Flask dashboard
Known bugs and safety gaps are tracked in docs/KNOWN_ISSUES.md — fix those
before or alongside any new feature, never after.

## Priority order for all work in this project
1. P0 — safety/security bugs (unapproved auto-mitigation, hardcoded secrets,
   crash bugs) — always fix these first, in their own commits, with tests.
2. P1 — the new CICFlowMeter + CICDDoS2019 + XGBoost/LSTM pipeline, built as
   an ADDITIVE parallel path. Do not delete, replace, or restructure the
   existing Mininet/Ryu/RF code without my explicit sign-off first.
3. P2 — new features, dashboard polish, extra datasets.

## Mitigation approval gate — hard rule, no exceptions
No function may call iptables, docker exec/stop/disconnect, nftables, tc,
or any OpenFlow DROP/mitigation rule as a DIRECT result of a model
prediction or an LLM response. Every such action must:
  (a) be written to a pending-actions store with full context and a reason,
  (b) require a separate, explicitly-invoked "approve" step (CLI command,
      dashboard button, or similar) triggered by a human,
  (c) default `auto_execute=False` wherever this flag exists, with no code
      path that flips it to True without me changing it myself.
This applies to the EXISTING auto-mitigation in docker_enforcer.py and
ai_threat_analyzer.py just as much as to any new code.

## Secrets
No API keys, tokens, or credentials in source files, ever. Load from
environment variables or a gitignored .env file only. If you find a hardcoded
secret anywhere in this repo while working, stop and flag it to me before
continuing, even if it's not the file you were asked to touch.
