# CLAUDE.md — DDoS Detection & Mitigation Platform

Guidance for Claude Code working in this repository. Author: Sachit Sharma.

## What this is
A layered, defense-in-depth DDoS/DoS **detection + response** platform for SDN and cloud-edge
networks. All detection code is strictly defensive. The system is organized in four layers plus
two AI agents.

## Architecture (layers)
- **L0 — Mitigation engine & approval gate.** `PendingActionManager` (`src/mitigation/manager.py`),
  `auto_execute=False`. Pluggable enforcers (OpenFlow, iptables/ipset, Docker, Cloudflare [mocked]).
  **Every** blocking action is *proposed*, never auto-executed.
- **L1 — Telemetry & sanity filter.** Packet sanity + signature + threshold + entropy/EWMA anomaly
  detectors, plus the L7 low-and-slow detector (`src/features/`). 77-feature CICFlowMeter flows.
- **L2 — ML ensemble.** XGBoost + RandomForest multi-class (`src/models/`), plus a supervised
  **OOD / zero-day** signal (`ood_detector.py`, isotonic-calibrated, tau at 2% false-OOD). BiLSTM is
  secondary/capped.
- **L3 — LLM reasoning agent.** NVIDIA Nemotron 3 Ultra (`nvidia/nemotron-3-ultra-550b-a55b`, base
  `https://integrate.api.nvidia.com/v1`, key `NVIDIA_API_KEY`) via `src/agent/`. Aggregated-alert
  triage only. Offline rule fallback when no key.
- **Dashboard/obs.** FastAPI + WebSocket SOC dashboard (`src/web/`), Prometheus `/metrics`, JSON logs
  (`src/obs/`). React rebuild planned (M5).

## Non-negotiable rules
- **LLM is NEVER in the packet fast-path.** It only sees aggregated alerts (1 call/incident, cached,
  timeout → rule fallback) and **recommends — never executes**. Treat all telemetry as untrusted
  (sanitize before any prompt).
- **Human-in-the-loop mitigation.** No `iptables`/`docker`/`nftables`/`tc`/OpenFlow-DROP as a direct
  result of a model/LLM decision. Everything goes through `PendingActionManager.approve()`.
  `tests/test_mitigation_bypass.py` (AST scan) must stay green.
- **Purple-team / attack traffic is LAB-ONLY** — isolated Mininet/netns/containers you own, never a
  real target. Ask before adding any traffic-generation code.
- **No secrets in source.** Keys from env / gitignored `.env` only. Fail-closed auth in prod/staging.
- **Datasets** only from `docs/DATASETS.md`; cite them.
- **Honesty:** report real numbers even when poor. Current detection numbers are **CIC-DDoS2019
  same-dataset**; cross-dataset generalization is M6. Never present inflated/leaky metrics without context.

## Workflow & versioning
- **Stop after each milestone** with a summary + test results + diff; wait for approval before the next.
- **Feature branches** (`feat/m2-nemotron`, …). Merge to `main` only after tests pass and approval.
- **Semantic versioning per milestone** (clean history starts at **v4.0.0**): M2 = v4.1.0,
  M3 = v4.2.0, M4 = v4.3.0, M5 = v4.4.0, M6 = v5.0.0. Each: update `CHANGELOG.md`, tag, GitHub release.
- **Never force-push `main` after v4.0.0.**
- Every feature ships with a pytest; run the full suite before committing.

## Run it
```bash
pip install -r requirements.txt
python -m src.demo        # benign/attacks + low-and-slow + zero-day flag
pytest tests/ -q          # full suite (318 passing)
```
See `README.md` → "Getting the data" for datasets/artifacts (gitignored).
