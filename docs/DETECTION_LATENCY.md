# Detection time: processing latency and MTTD (v5.0.1, updated v5.1.0, live v5.2.0)

Two different questions, measured separately and **from real data**: no estimates.

1. **Processing latency:** how long the code takes to judge one flow, per stage. That is algorithm
   plus Python cost on this machine.
2. **MTTD (mean time to detect):** in the Mininet lab runs (`run2` v4.6.1, `run3` v5.1.0), how long after each attack
   *started* did each layer first raise an alert.

They are not the same. MTTD **includes** the scenario's ramp-up (the first packets of an attack
are not yet a flood), each detector's aggregation window (the L1 rate rules look at a 10 s
window; the low-and-slow rule only counts a connection after it has been open ≥ 10 s), and when
a flow's last packet is seen. So MTTD is an **upper bound** on detection speed, not pure algorithm
speed. A deployed CICFlowMeter-style exporter would add its own idle/active timeout on top (60 s /
120 s by default). That latency is *not* included here.

Reproduce: `python scripts/detection_latency.py data/lab_runs/run2 data/lab_runs/run3` (needs the
lab pcaps and the per-flow score cache from `python -m src.eval.lab_analysis data/lab_runs/run2 data/lab_runs/run3`). Raw numbers:
[`docs/eval/latency/results.json`](eval/latency/results.json).

## Results (generated from `results.json`)

<!-- LATENCY:START -->
Measured on **Intel64 Family 6 Model 183 Stepping 1, GenuineIntel** (28 logical CPUs, 15.7 GB RAM, GPU NVIDIA GeForce RTX 5060 Laptop GPU), Windows 11, Python 3.14.6. 2021 real flows from lab run `run2,run3` (deterministic sample across all scenarios), 50 warm-up flows excluded.

| Stage | Unit | n | p50 (ms) | p95 (ms) | p99 (ms) | mean (ms) |
|---|---|---:|---:|---:|---:|---:|
| L1 rules (threshold + signature + low-and-slow) | per flow | 2021 | 0.2563 | 6.0535 | 12.0451 | 1.0172 |
| L2 ML ensemble (RF + XGBoost) | per flow | 2021 | 68.1837 | 72.0209 | 77.0019 | 68.493 |
| OOD detector | per flow | 2021 | 13.6007 | 15.0047 | 16.2102 | 13.6881 |
| **End-to-end per flow (L1+L2+OOD)** | per flow | 2021 | 82.4564 | 90.4929 | 96.8713 | 83.1984 |
| L3 rule analyst | per incident | 1800 | 0.1148 | 0.1701 | 0.2587 | 0.1196 |

**MTTD per scenario** (seconds from scenario start to the first alert at that layer; "not detected" = that layer never fired during the run):

| Scenario | L1 | L2 (ML)* | OOD* | L3 (rules) | L3 verdict | Duration (s) |
|---|---:|---:|---:|---:|---|---:|
| `benign_baseline` | 0.6 | not detected | not detected | not detected | — | 64.9 |
| `dns_reflection_sim` | 2.2 | 2.2 | 0.9 | 1.0 | UDP flood | 60.8 |
| `flash_crowd` | 0.5 | not detected | not detected | not detected | — | 64.2 |
| `http_low_and_slow` | 117.3 | not detected | not detected | 118.0 | Slowloris / low-and-slow HTTP (L7) | 153.8 |
| `novel_ood_mix` | 1.4 | 1.4 | 1.5 | not detected | — | 61.0 |
| `ntp_reflection_sim` | 1.2 | 2.5 | 1.2 | 2.0 | UDP flood | 61.0 |
| `syn_flood` | 1.0 | not detected | 12.3 | not detected | — | 60.8 |
| `udp_flood` | 1.3 | 11.8 | 0.9 | 1.0 | UDP flood | 60.7 |
| `icmp_flood` | 55.8 | not detected | not detected | 56.0 | ICMP flood | 61.0 |
| `tcp_ack_flood` | 1.2 | 1.2 | 1.2 | not detected | — | 61.0 |
| `tcp_rst_flood` | 1.5 | 12.4 | 53.5 | not detected | — | 61.3 |
| `land_attack` | 60.8 | 60.8 | 60.8 | 61.0 | TCP SYN flood | 61.0 |

\* L2/OOD were scored on every k-th flow in the lab analysis (k shown in `results.json`), so their first-alert times are upper bounds.
<!-- LATENCY:END -->

## Real-time MTTD: live demo (v5.2.0)

Attack start → first alert **on the website**, measured from a live Mininet run while the attack
was running. Pcaps were tailed as tcpdump wrote them, L1 was evaluated on 1 s windows by the
platform, and alerts were pushed over `/ws/live`. Reproduce with block H of `docs/RUNBOOK.md`, then
`python scripts/live_mttd.py data/lab_runs/<run>`.

<!-- LIVE:START -->
Two live Mininet runs (2026-11-12), victim `10.99.0.10`, same sequence, containment `contained` in
both. Seconds from scenario start (WSL2 clock). Raw numbers: [`docs/eval/live/results.json`](eval/live/results.json).

| Scenario | Attack? | First alerting 1 s window | **Alert on website** | Incident opened | Alert stayed on | L3 verdict | L2 (ML) attack verdict* | Offline L1 MTTD |
|---|---|---:|---:|---:|---|---|---:|---:|
| **live2 (after the timing fix)** | | | | | | | | |
| `benign_baseline` | no | — | no alert (correct) | — | — | — | none (correct) | 0.6 (false positive offline) |
| `syn_flood` | yes | 1.74 | **5.83** | 5.86 | 58.8 s of 60.6 s, 1 alert | SYN flood (Nemotron Lightning) | not detected | 1.0 |
| `icmp_flood` | yes | 2.02 | **3.89** | 3.93 | 60.7 s of 60.7 s, 1 alert | ICMP flood (Nemotron Lightning) | not detected | 55.8 |
| `flash_crowd` | no | — | no alert (correct) | — | — | — | none (correct) | 0.5 (false positive offline) |
| `udp_flood` | yes | 1.92 | **3.77** | 3.82 | 61.0 s of 60.8 s, 1 alert | **Benign / flash crowd** (Nemotron Lightning, wrong) | 10.27 | 1.3 |
| **live1 (before the fix)** | | | | | | | | |
| `syn_flood` | yes | 2.09 | 4.69 | 4.72 | **4.9 s** of 60.6 s, then cleared | Benign / insufficient evidence (rules) | not detected | 1.0 |
| `icmp_flood` | yes | 1.37 | 2.95 | 2.98 | 14.0 s in 2 alerts | ICMP flood (rules) | not detected | 55.8 |
| `udp_flood` | yes | 1.65 | 3.39 | 3.43 | 17.9 s in 2 alerts | UDP flood (rules) | 11.41 | 1.3 |

live1's benign and flash-crowd rows were the same as live2's (no alert). \* L2 = an "attack" verdict from the
ML ensemble on a sampled flow to the victim (`/score/flow`, 1.5 flows/s), so an upper bound.

**What this shows:**
- **Alert on the website 3.8–5.8 s after an attack starts.** About 2 s of that is the detector
  (the first 1 s window over the threshold, plus ramp-up). The other ~2 s is getting the packets
  from WSL2 to Windows: tcpdump's writes become visible on the shared disk in bursts (window post
  lag p50 2.3 s). Incidents open ~0.05 s after the alert.
- **ICMP: 3.9 s live vs 55.8 s offline.** Offline, a flow is only judged when it ends, and an ICMP
  flood is 20 flows lasting the whole attack. Live windows don't wait for flows.
- **No live alert on benign or flash crowd** in either run. The offline flow-based L1 fired on
  both (0.6 s / 0.5 s).
- **The fix:** in live1 the alert cleared after 5–18 s of a 60 s flood. Late-arriving packets were
  closed as empty windows. In live2 each flood is one alert for its whole duration, with 0 late
  packets.
- **L3:** in live2 the server had `NVIDIA_API_KEY`, so Nemotron 3.5 Lightning analysed each
  incident. It named the SYN and ICMP floods but called the **UDP flood "Benign / flash crowd"**.
  The rule analyst (live1) named UDP and ICMP but not SYN. Neither is reliable on its own.
- **Rate corroboration in `/score/flow` is a false-positive source:** it called sampled benign and
  flash-crowd flows "attack" 16–20 s into those phases, in both runs, while the ML said Benign. The
  Live Attack view labels these "rate corroboration", never ML. To be fixed in v5.3.0.
- **live2 window post lag max 12.9 s:** the bridge waited on the LLM analysis (5 s timeout) inside
  its loop. The analysis now runs in a background thread with a 120 s timeout. That change is
  tested but not yet re-measured in a lab run.

**Clocks:** the alert time is on the Windows clock, the scenario start on the WSL2 clock. The
smallest observed (Windows − WSL2 packet) gap was 0.05 s (live2) / 0.15 s (live1), an upper bound
on the skew.
<!-- LIVE:END -->

## Summary

**The pipeline processes one flow in ~82 ms (p50; p99 ~97 ms) on this laptop.** Almost all of that
is the ML ensemble: L2 RF + XGBoost ~68 ms, OOD ~14 ms, while the L1 rules take ~0.26 ms p50.
These are single-flow, unbatched calls through `score_flow`, one model call per flow. That is how
`/score/flow` works today. That's ~12 flows/s per worker for the ML path; batching was **not**
measured here, so no batched figure is claimed. The rule-based L3 analyst adds ~0.12 ms per
*incident*. (v5.0.1 measured 81 ms on 1,600 `run2` flows; this sample of 2,021 adds `run3`.)

**In the lab, most floods were flagged within ~1–2.5 s of starting** by L1 (window-bound), and the
slow attack after ~117 s. Per layer, as measured:

- **L1 rules** fired on every attack:
  - 0.98–2.2 s for the SYN, UDP, reflection, ACK and RST floods and the novel mix;
  - 117.3 s for low-and-slow. A connection only counts as "slow" after ≥ 10 s, and the alert
    needs ≥ 20 such connections.
  - **ICMP 55.8 s and LAND 60.8 s.** These are bound by flow completion, not detector speed: the
    ICMP flood is 20 long flows (one per source) and LAND is a single flow. Both end only when the
    scenario ends.
- **L2 ML:**
  - 1.2–12.4 s on the UDP-family floods, the novel mix, ACK and RST (ACK labelled as UDP
    reflection).
  - **Not detected** on the SYN flood, ICMP and low-and-slow. LAND at 60.8 s, from its single flow.
- **OOD:** 0.9–12.3 s on most floods; 53.5 s on RST; **not detected** on ICMP and low-and-slow.
- **L3 rule analyst:**
  - 1–2 s on the UDP floods, 56 s on ICMP, 118 s on low-and-slow.
  - On LAND (61 s) it named a **TCP SYN flood**, the wrong family for that scenario.
  - **Not detected** on the SYN, ACK and RST floods and the novel mix. For SYN this replaces
    v5.0.1's "2.0 s, HTTP flood": that alert came from a harness bug that counted zero-payload
    handshakes as HTTP requests (fixed in v5.1.0; see `docs/purple_team/README.md` finding 3).
- **False alarms:** L1 also fired on the **benign baseline (0.6 s) and the flash crowd (0.5 s)**.
  Those times are false positives, not detections, and match the v4.6.1 finding.

**Why MTTD is an upper bound, not algorithm speed:** it starts at the scenario start. So it
includes the generator ramp-up, the L1 10 s rate window, the low-and-slow 10 s connection-age
rule, and the time until a flow's last packet is seen. L2/OOD figures are upper bounds too,
because the lab analysis scored every k-th flow (k = 21–58 for the floods). A CICFlowMeter-style
exporter in production would add its idle/active timeout (default 60 s / 120 s) before any of this
runs.

**Hardware notes:** the CPU string is as reported by the OS (`platform.processor()`). An RTX 5060
GPU is present. Earlier runs logged XGBoost warning that the model is configured for `cuda:0`
while input data is on the CPU, so prediction falls back to DMatrix. No warnings were captured
during this benchmark, and whether XGBoost used the GPU here was not established. Numbers are
from one run on one machine.
