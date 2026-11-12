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
| H. Live demo (Mininet → SOC in real time) | **yes** | **yes** | **yes** | ~7 min |

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

Builds an isolated Mininet LAN (`10.99.0.0/24`, no NAT, no route out) and runs all 12 scenarios
through the gated generator. It records the victim's traffic to pcaps. `--containment` first
proves (in a separate throwaway network) that lab traffic cannot leave. Every packet is checked
against `lab/lab_scope.yaml` (private lab IPs only, ≤ 2,000 pkt/s, ≤ 120 s, kill switch).

In a **WSL Ubuntu** terminal:
```bash
cd "/mnt/c/Users/Sachit Sharma/Documents/Sachit Main/DDoS-Detection-clean"
sudo mn -c                                    # clean up any earlier Mininet state
sudo python3 -m lab.traffic.orchestrate --out data/lab_runs/run3 --containment
```
**Takes ~11 minutes** for the original 8 (measured 10.6 min for `run2`); add ~5 min for the 4
v5.1.0 scenarios. To run only some, pass `--scenarios icmp_flood,tcp_ack_flood,tcp_rst_flood,land_attack`. Each scenario sends real-time traffic for
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
python -m src.eval.lab_analysis data/lab_runs/run2 data/lab_runs/run3       # coverage matrix (later run wins per scenario)
python scripts/detection_latency.py data/lab_runs/run2 data/lab_runs/run3   # processing latency + per-layer MTTD
```
Time: first analysis ~25 min (the 183 MB Random Forest is ~10 ms/flow; ML is scored on ≤ 1,500
flows per scenario). Re-runs reuse `data/lab_runs/<run>/scores/<model-fingerprint>/` and take ~10 min for both runs.
Changing a model file changes the fingerprint, so stale scores are never reused.
`detection_latency.py` takes ~14 min for both runs.

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
Expected: `607 passed, 5 skipped` at v5.1.0, or more as tests are added (~3–5 min). Web-app tests:
```bash
cd dashboard && npm run lint && npm run typecheck && npm test && npm run build && npx playwright test
```
Expected: lint/typecheck clean, `Tests 24 passed`, then Playwright `21 passed, 1 skipped`. The
skipped one is the opt-in screenshot capture. Playwright starts its own server on port 8765 with
a temporary DB.

**Stop:** `Ctrl+C`.

---

## H. Live demo: Mininet attack → SOC website in real time (v5.2.0)

Three terminals. The WSL side writes each scenario's pcap packet by packet (`tcpdump -U`) and the
switch's port counters (`ovs-ofctl dump-ports`, read-only) into `data/lab_runs/<run>/` on the
Windows disk. The Windows bridge tails those files and feeds the running platform through its API.
**No WSL2 ↔ Windows network path is used**, so nothing in `.wslconfig` or the firewall has to
change, and uvicorn stays bound to `127.0.0.1`.

**1. Platform (Windows PowerShell).** Stop any older server on port 8000 first (it would not have the
live API):
```powershell
$env:DDOS_API_KEYS  = "demo-analyst-key-01"
$env:DDOS_ADMIN_KEYS = "demo-admin-key-0001"
python -m uvicorn src.api.app:app --host 127.0.0.1 --port 8000
```
Open **http://localhost:8000/app/live-attack** and sign in with `demo-analyst-key-01`.

**Port:** the live demo always uses **8000**. The bridge reads the platform URL from `DDOS_API_URL`
(default `http://127.0.0.1:8000`) and its key from `DDOS_LIVE_KEY` (else the first `DDOS_API_KEYS` entry).
Sign in on the website with the **admin** key (`demo-admin-key-0001`) to approve or reject. Use the
analyst key to only view.

**2. Bridge (second Windows terminal).** Start it *before* the lab run; it ignores pcaps that already exist:
```powershell
$env:DDOS_LIVE_KEY = "demo-analyst-key-01"
python scripts/live_bridge.py data/lab_runs/live1 --reset
```
Expected: `platform http://127.0.0.1:8000: {'status': 'ok', ...}` then `watching data\lab_runs\live1 ...`.

**3. Lab (WSL Ubuntu terminal, sudo).**
```bash
cd "/mnt/c/Users/Sachit Sharma/Documents/Sachit Main/DDoS-Detection-clean"
sudo bash lab/live_demo.sh live1
```
The sequence is benign → SYN flood → ICMP flood → flash crowd → UDP flood, with 15 s gaps
(`DEMO_SCENARIOS` / `DEMO_GAP` override it). It takes about 7 minutes: containment proof ~30 s,
then 60 s per scenario.

What appears, and when:
- **Within ~1–4 s of each flood starting:** the red "Attack in progress" banner, with the L1 rule
  and its numbers, the pps/bps spike, top attackers, and the protocol/flag mix.
- **Within ~1 s more:** a `[LIVE]` incident in the Incidents list. The rule analyst's (or Nemotron's)
  verdict is on the incident page.
- **About every 2 s:** OVS port counters per switch port, with the lab host on it.
- **5 quiet seconds after a flood ends:** the banner clears and the alert history shows how long it
  lasted.
- **Benign and flash-crowd phases:** no banner is expected. Any banner there is a false positive and
  is reported as one.

**Afterwards:** `python scripts/live_mttd.py data/lab_runs/live1` writes the real-time MTTD table
into `docs/DETECTION_LATENCY.md` and `docs/eval/live/results.json`.

**Stop:**
- `touch lab/KILL` in a second WSL terminal stops the generator within one tick; then `rm lab/KILL`.
- `Ctrl+C` in the bridge and server terminals.
- Nothing is ever blocked automatically. Any mitigation the platform proposes stays **PENDING**
  on Approvals until an admin approves it.

**Without WSL** (pipeline check only, recorded traffic): `python scripts/pcap_replay_live.py
data/lab_runs/run2/syn_flood.pcap --out data/lab_runs/replay1` re-writes a recorded pcap into a
growing file at real-time pace for the bridge. It sends no packets. Label any numbers from it as
*replay*, not live.
