# Detection time: processing latency and MTTD (v5.0.1)

Two different questions, measured separately and **from real data**: no estimates.

1. **Processing latency:** how long the code takes to judge one flow, per stage. That is algorithm
   plus Python cost on this machine.
2. **MTTD (mean time to detect):** in the v4.6.1 Mininet lab run, how long after each attack
   *started* did each layer first raise an alert.

They are not the same. MTTD **includes** the scenario's ramp-up (the first packets of an attack
are not yet a flood), each detector's aggregation window (the L1 rate rules look at a 10 s
window; the low-and-slow rule only counts a connection after it has been open ≥ 10 s), and when
a flow's last packet is seen. So MTTD is an **upper bound** on detection speed, not pure algorithm
speed. A deployed CICFlowMeter-style exporter would add its own idle/active timeout on top (60 s /
120 s by default). That latency is *not* included here.

Reproduce: `python scripts/detection_latency.py data/lab_runs/run2` (needs the lab pcaps and the
per-flow score cache from `python -m src.eval.lab_analysis data/lab_runs/run2`). Raw numbers:
[`docs/eval/latency/results.json`](eval/latency/results.json).

## Results (generated from `results.json`)

<!-- LATENCY:START -->
Measured on **Intel64 Family 6 Model 183 Stepping 1, GenuineIntel** (28 logical CPUs, 15.7 GB RAM, GPU NVIDIA GeForce RTX 5060 Laptop GPU), Windows 11, Python 3.14.6. 1600 real flows from lab run `run2` (deterministic sample across all scenarios), 50 warm-up flows excluded.

| Stage | Unit | n | p50 (ms) | p95 (ms) | p99 (ms) | mean (ms) |
|---|---|---:|---:|---:|---:|---:|
| L1 rules (threshold + signature + low-and-slow) | per flow | 1600 | 0.2752 | 6.5098 | 12.8069 | 1.0092 |
| L2 ML ensemble (RF + XGBoost) | per flow | 1600 | 67.0104 | 69.995 | 71.1209 | 67.1637 |
| OOD detector | per flow | 1600 | 13.0926 | 14.2195 | 15.1507 | 13.1525 |
| **End-to-end per flow (L1+L2+OOD)** | per flow | 1600 | 80.683 | 87.0241 | 94.5829 | 81.3254 |
| L3 rule analyst | per incident | 1200 | 0.1258 | 0.1915 | 0.2662 | 0.1291 |

**MTTD per scenario** (seconds from scenario start to the first alert at that layer; "not detected" = that layer never fired during the run):

| Scenario | L1 | L2 (ML)* | OOD* | L3 (rules) | L3 verdict | Duration (s) |
|---|---:|---:|---:|---:|---|---:|
| `benign_baseline` | 0.6 | not detected | not detected | not detected | — | 64.9 |
| `dns_reflection_sim` | 2.2 | 2.2 | 0.9 | 1.0 | UDP flood | 60.8 |
| `flash_crowd` | 0.5 | not detected | not detected | not detected | — | 64.2 |
| `http_low_and_slow` | 117.3 | not detected | not detected | 118.0 | Slowloris / low-and-slow HTTP (L7) | 153.8 |
| `novel_ood_mix` | 1.4 | 1.4 | 1.5 | not detected | — | 61.0 |
| `ntp_reflection_sim` | 1.2 | 2.5 | 1.2 | 2.0 | UDP flood | 61.0 |
| `syn_flood` | 1.0 | not detected | 12.3 | 2.0 | HTTP flood (L7) | 60.8 |
| `udp_flood` | 1.3 | 11.8 | 0.9 | 1.0 | UDP flood | 60.7 |

\* L2/OOD were scored on every k-th flow in the lab analysis (k shown in `results.json`), so their first-alert times are upper bounds.
<!-- LATENCY:END -->

## Summary

**The pipeline processes one flow in ~81 ms (p50; p99 ~95 ms) on this laptop.** Almost all of that
is the ML ensemble: L2 RF + XGBoost ~67 ms, OOD ~13 ms, while the L1 rules take ~0.3 ms p50.
These are single-flow, unbatched calls through `score_flow`, one model call per flow. That is how
`/score/flow` works today. That's ~12 flows/s per worker for the ML path; batching was **not**
measured here, so no batched figure is claimed. The rule-based L3 analyst adds ~0.13 ms per
*incident*.

**In the lab, the floods were flagged within ~1–2 s of starting** by L1 (0.9–2.2 s; window-bound),
and the slow attack after ~117 s. Per layer, as measured:

- **L1 rules** fired first on every attack: 0.9–2.2 s for the floods, 117.3 s for low-and-slow.
  That last one is by design: a connection only counts as "slow" after ≥ 10 s, and the alert needs
  ≥ 20 such connections.
- **L2 ML:** 1.4–11.8 s on the UDP-family floods and the novel mix, but **not detected** on the SYN
  flood and the low-and-slow attack.
- **OOD:** 0.9–12.3 s on most attacks; **not detected** on low-and-slow.
- **L3 rule analyst:** 1–2 s on the floods and 118 s on low-and-slow; **not detected** on the novel
  mix. On the SYN flood it alerted at 2.0 s but **named the wrong attack** (early windows read as
  "HTTP flood", the full run as low-and-slow; see `docs/purple_team/README.md` finding 3).
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
