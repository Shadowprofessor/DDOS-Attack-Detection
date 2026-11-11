# Runbook: every way to run the platform

Copy-paste blocks, each labelled with what it does, the expected output, how to stop it, and what
it needs. The commands were run on 2026-11-11 (Windows 11 + WSL2 Ubuntu 26.04, Python 3.14,
Node 24). Outputs below are from those runs.

| Block | Needs WSL2 | Needs sudo | Needs model files¹ | Typical time |
|---|:-:|:-:|:-:|---|
| A. One-time setup | WSL part only | WSL part only | — | 5–15 min |
| B. Run the SOC app | — | — | optional | ~30 s to start |
| C. Score one attack flow | — | — | optional | < 1 s |
| D. Replay a scenario | — | — | — | < 1 s |
| E. Mininet purple-team lab | **yes** | **yes** | — | ~11 min |
| F. Analyse lab pcaps | — | — | **yes** | ~25 min first time, ~7 min after |
| G. Full test suite | — | — | optional | ~3–5 min |

¹ `models/*.pkl|.joblib` are gitignored (see README → "Getting the data"). Without them the API
falls back to a DummyClassifier: everything runs, but L2 verdicts are not meaningful.

Commands assume the repo root as the working directory:
`C:\Users\Sachit Sharma\Documents\Sachit Main\DDoS-Detection-clean` (Windows) or
`/mnt/c/Users/Sachit Sharma/Documents/Sachit Main/DDoS-Detection-clean` (WSL). Quote the path:
it contains spaces.

---

## A. One-time setup

**Windows (PowerShell or Git Bash):** Python deps and the web-app build.
```bash
pip install -r requirements.txt
cd dashboard && npm ci && npm run build && cd ..
```
Expected: pip ends with `Successfully installed …` (or "Requirement already satisfied"), and the
build ends with `✓ built in …ms` and writes `dashboard/dist/`. No stop needed.

**WSL2 lab dependencies (Ubuntu, needs sudo):** only for blocks E–F traffic generation.
```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch python3-scapy python3-pydantic python3-yaml tcpdump nftables iputils-ping
sudo service openvswitch-switch start      # if `systemctl is-active openvswitch-switch` is not "active"
```
Verified versions: mininet 2.3.0, openvswitch-switch 3.7.1, python3-scapy 2.7.0,
python3-pydantic 2.12.5, python3-yaml 6.0.3, tcpdump 4.99.6, nftables 1.1.6.

---

## B. Run the SOC app locally (no LLM key, no traffic)

Starts the FastAPI service with throwaway **demo keys** and serves the React SOC app.

PowerShell:
```powershell
$env:DDOS_API_KEYS  = "demo-analyst-key-01"     # analyst role
$env:DDOS_ADMIN_KEYS = "demo-admin-key-0001"    # admin role (approve / reject / extend)
python -m uvicorn src.api.app:app --host 127.0.0.1 --port 8000
```
Git Bash / WSL:
```bash
export DDOS_API_KEYS=demo-analyst-key-01 DDOS_ADMIN_KEYS=demo-admin-key-0001
python -m uvicorn src.api.app:app --host 127.0.0.1 --port 8000
```
Open **http://localhost:8000/app** (http://localhost:8000/ redirects there). Sign in with
`demo-analyst-key-01` or `demo-admin-key-0001`.

Expected: after ~30 s (model loading) uvicorn prints `Uvicorn running on http://127.0.0.1:8000`.
`curl -s localhost:8000/health` returns `{"status":"ok","models_loaded":true}` (or `false` without
model files).

Optional:
- `NVIDIA_API_KEY` enables the live LLM analyst; without it the rule-based analyst is used.
- `DDOS_IR_DATABASE_URL` / `DDOS_PENDING_ACTIONS_PATH` move the incident DB and action queue
  (defaults: `data/ir.db`, `data/pending_actions.json`).

**Stop:** `Ctrl+C` in that terminal. If it was started in the background:
```powershell
Stop-Process -Id (Get-NetTCPConnection -LocalPort 8000 -State Listen).OwningProcess -Force
```
Never use the demo keys outside your machine. Production/staging refuse to start without
configured keys.

---

## C. Score one attack flow → a PENDING mitigation (nothing is executed)

Needs B running. Sends one SYN-flood-shaped flow to `/score/flow`. The platform classifies it and
**proposes** a block, which waits for a human admin.

PowerShell:
```powershell
$env:DDOS_API_KEYS = "demo-analyst-key-01"
$body = '{"features":{"src_ip":"10.0.0.9","dst_ip":"10.0.0.4","Protocol":6,"SYN Flag Count":100}}'
(Invoke-RestMethod -Method Post -Uri http://localhost:8000/score/flow -Headers @{ "X-API-Key" = $env:DDOS_API_KEYS } -ContentType "application/json" -Body $body).result
```
Git Bash / WSL:
```bash
curl -s -X POST localhost:8000/score/flow -H "X-API-Key: $DDOS_API_KEYS" -H "Content-Type: application/json" \
     -d '{"features":{"src_ip":"10.0.0.9","dst_ip":"10.0.0.4","Protocol":6,"SYN Flag Count":100}}'
```
Expected (with model files): `is_attack: True`, `attack_family: Syn`, `confidence ≈ 0.9998`, and a
`proposed_action_id` such as `7a990815`. `GET /actions/pending` then shows it with status
`PENDING`, and it appears on **Approvals** in the app. One request, nothing to stop.

---

## D. Replay a stored scenario → an incident in the UI

Needs B running. Replays `replay/scenarios/syn_flood.json` through L1 → L2 → rule-based L3. No
traffic, no LLM. Any action a playbook proposes for a replay goes to an isolated dry-run queue.

PowerShell:
```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8000/api/replay -Headers @{ "X-API-Key" = $env:DDOS_API_KEYS } -ContentType "application/json" -Body '{"scenario":"syn_flood","speed":600}'
```
Git Bash / WSL:
```bash
curl -s -X POST localhost:8000/api/replay -H "X-API-Key: $DDOS_API_KEYS" -H "Content-Type: application/json" \
     -d '{"scenario":"syn_flood","speed":600}'
```
Expected: an incident such as `INC-20261111-2696` titled `[REPLAY] TCP SYN flood (syn_flood)`,
with stages `L1, L1, L1, L2, L3`. It appears live on **Incidents** (WebSocket push). Also available
from the UI: **Replay** → pick a scenario → *Run replay*. Other scenario: `udp_reflection_ntp`.
One request, nothing to stop.

---

## E. Purple-team lab in Mininet (WSL2 + sudo; lab-only traffic)

Builds an isolated Mininet LAN (`10.99.0.0/24`, no NAT, no route out) and runs all 8 scenarios
through the gated generator. It records the victim's traffic to pcaps. `--containment` first
proves (in a separate throwaway network) that lab traffic cannot leave. Every packet is checked
against `lab/lab_scope.yaml` (private lab IPs only, ≤ 2,000 pkt/s, ≤ 120 s, kill switch).

In a **WSL Ubuntu** terminal:
```bash
cd "/mnt/c/Users/Sachit Sharma/Documents/Sachit Main/DDoS-Detection-clean"
sudo mn -c                                    # clean up any earlier Mininet state
sudo python3 -m lab.traffic.orchestrate --out data/lab_runs/run3 --containment
```
**Takes ~11 minutes** (measured 10.6 min for `run2`). Each scenario sends real-time traffic for
60 s (low-and-slow: 120 s + ~30 s connection teardown), with short gaps between scenarios.

Expected output:
- `containment: {… 'verdict': 'contained' …}` within ~30 s. 3 probes are dropped at the lab
  boundary and 0 appear on `eth0`. Anything else (`NOT contained` or `inconclusive …`) prints its
  diagnostics. Do not trust a run that isn't `contained`.
- One line per scenario, e.g.
  `syn_flood -> {… 'packets': 89286, 'stopped_by': 'completed', 'achieved_pps': 1483.0}`.
- Finally `wrote data/lab_runs/run3/manifest.json`.

Where results land: `data/lab_runs/<run>/` holds `manifest.json` and `<scenario>.pcap` per scenario
(gitignored). The manifest is saved after every scenario, so an interrupted run keeps finished
scenarios.

**Stop (kill switch):** from a **second** WSL terminal, in the repo:
```bash
touch lab/KILL          # the generator stops within one 1-second tick; no new scenario starts
```
Afterwards `rm lab/KILL` (otherwise the next run refuses to start) and `sudo mn -c`. `Ctrl+C` on
the orchestrator also tears the network down. Do **not** run `sudo mn -c` while a run is still
going: it kills the lab mid-scenario.

---

## F. Analyse lab pcaps → coverage matrix (Windows side)

Runs every captured flow through the real stack (L1 rules, L2 ensemble, OOD, rule-based L3).
It reports per-scenario outcome, MTTD, false positives, an ATT&CK Navigator layer, and per-stage
detection latency.
```bash
python -m src.eval.lab_analysis data/lab_runs/run2          # coverage matrix
python scripts/detection_latency.py data/lab_runs/run2      # processing latency + per-layer MTTD
```
Time: first analysis ~25 min (the 183 MB Random Forest is ~10 ms/flow; ML is scored on ≤ 1,500
flows per scenario). Re-runs reuse `data/lab_runs/<run>/scores/` and take ~7 min.
`detection_latency.py` takes ~10 min.

Expected: one line per scenario (e.g. `syn_flood partial ['L1', 'OOD', 'L3'] 0.98 flows=34843 …`),
then `wrote …\docs\purple_team`. Outputs:
- `docs/purple_team/coverage.md`: the coverage matrix;
- `docs/purple_team/results.json`: raw per-scenario numbers;
- `docs/purple_team/navigator_layer.json`: ATT&CK Navigator layer;
- `docs/eval/latency/results.json` and `docs/DETECTION_LATENCY.md`: latency tables.

**Stop:** `Ctrl+C`. Scores already cached are kept.

---

## G. Full test suite (CI parity)

CI has no `NVIDIA_API_KEY`, so the opt-in live-LLM tests skip. Run with the key unset to match:

PowerShell:
```powershell
Remove-Item Env:NVIDIA_API_KEY -ErrorAction SilentlyContinue
python -m pytest tests/ -q
```
Git Bash / WSL:
```bash
env -u NVIDIA_API_KEY python -m pytest tests/ -q
```
Expected: `590 passed, 5 skipped` at v5.0.0, or more as tests are added (~3–5 min). Web-app tests:
```bash
cd dashboard && npm run lint && npm run typecheck && npm test && npm run build && npx playwright test
```
Expected: lint/typecheck clean, `Tests 24 passed`, then Playwright `21 passed, 1 skipped`. The
skipped one is the opt-in screenshot capture. Playwright starts its own server on port 8765 with
a temporary DB.

**Stop:** `Ctrl+C`.
