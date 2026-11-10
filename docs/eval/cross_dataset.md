# Cross-dataset evaluation: CIC-DDoS2019 → CICIoT2023 (v4.4.0)

**Bottom line:** this does **not** show that the models generalise to a new network.

On a small, easy three-class CICIoT2023 sample the scores swing from perfect to near-useless
depending only on how we fill the 57 features CICIoT2023 does not provide. The test is mostly a
measure of sensitivity to a feature-schema mismatch. A real cross-dataset test needs CICIoT2023
(or CIC-IDS2017) pcaps run through **our own** CICFlowMeter extractor. That is listed below as
not done. The headline detection numbers in the README remain **CIC-DDoS2019 same-dataset**.

## Setup

| Item | Value |
|---|---|
| Trained on | CIC-DDoS2019 (models in `models/`, unchanged; no retraining) |
| Tested on | CICIoT2023 CSV sample (Neto et al., *Sensors* 2023, see `docs/DATASETS.md`): `BenignTraffic`, `DDoS-SYN_Flood`, `DDoS-UDP_Flood` |
| Sample | 2,000 rows per class, fixed seed `20231101` → 6,000 rows. File SHA-256 + row counts in `results.json` → `manifest` |
| Models | Calibrated RF + XGBoost ensemble (`score_flow`, as `/score/flow` uses; sequence model off), supervised OOD detector (`models/ood_model.joblib`, τ calibrated on CIC-DDoS2019 to 2% false-OOD) |
| Harness | `src/eval/cross_dataset.py` (`python -m src.eval.cross_dataset --per-class 2000`) |
| Raw results | `docs/eval/cross_dataset/results.json` (the table below is generated from it) |

## How features were mapped (Option B) and why it is weak

CICIoT2023 publishes 46 features computed over **packet windows** (averages and ratios). It does not
publish CICFlowMeter's per-flow features. `CICIOT2023_COLUMN_ALIAS_MAP` (`src/features/dataset_registry.py`)
maps the columns that have a counterpart: **20 of 77** CICFlowMeter features get a value (listed in
`results.json` → `mapped_feature_names`). Even these are approximate:

- `Rate` → `Flow Packets/s` and `Header_Length` → `Fwd Header Length`: a window average, not a per-flow value.
- `syn_count`, `ack_count`, … → `SYN Flag Count`, …: counts in a packet window, not in a flow.
- `Tot sum` / `AVG` / `Std` / `Variance` → packet-length totals and moments: window statistics.
- `Number` → `Total Fwd Packets`: the window size, not the flow's forward packets.

The other **57 features** (all backward-direction stats, IAT min/max/std, active/idle times, window
sizes, …) do not exist in CICIoT2023 and must be filled. We report three ways of filling them:

1. **zero**: the registry default.
2. **CIC-DDoS2019 Benign median**: label-agnostic and conservative.
3. **production path**: what `/score/flow` does with a partial feature dict. Missing features are
   filled from per-class medians chosen by a protocol/flag heuristic (TCP + SYN → Syn medians,
   UDP → UDP-family medians). This helps the model by construction, because the heuristic has
   already "guessed" the class.

Plus a **non-ML baseline**: TCP with SYN flags → Syn, UDP → UDP, otherwise Benign.

## Results

<!-- RESULTS:START -->
| Imputation of unmapped features | Attack precision | Attack recall | Attack F1 | Benign FPR | Benign kept | SYN flood -> Syn | UDP flood -> UDP family | OOD flag rate |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| zero (registry default) | 1.000 | 1.000 | 1.000 | 0.0% | 100.0% | 100.0% | 100.0% | 0.0% |
| CIC-DDoS2019 Benign median | 0.971 | 0.025 | 0.050 | 0.1% | 99.9% | 4.9% | 0.2% | 0.0% |
| production path (heuristic class medians) | 0.933 | 1.000 | 0.966 | 14.2% | 85.8% | 100.0% | 100.0% | 0.0% |
| **baseline: protocol/flag rule (no ML)** | 0.844 | 1.000 | 0.916 | 36.9% | 63.1% | 100.0% | 100.0% | 0.0% |

Top predicted labels per true class:

| Imputation | Benign | SYN flood | UDP flood |
|---|---|---|---|
| zero (registry default) | Benign 2000 | Syn 2000 | UDP 2000 |
| CIC-DDoS2019 Benign median | Benign 1997, UDP-Reflection-Amplification 3 | Benign 1903, Syn 97 | Benign 1995, UDP-Reflection-Amplification 5 |
| production path (heuristic class medians) | Benign 1715, UDP-Reflection-Amplification 267, UDP 17, Syn 1 | Syn 2000 | UDP-Reflection-Amplification 1999, UDP 1 |
<!-- RESULTS:END -->

## What the numbers say

- **Results depend on how the missing features are filled.** The same models, on the same
  6,000 rows, range from F1 1.000 (zero fill) to F1 0.05 (benign-median fill). A model that had
  learned transferable signal would not swing like that. The 57 unmapped features carry most of
  the decision, so filling them decides the outcome.
- **Zero fill scoring perfectly is not a success claim.** These three classes are very
  separable by protocol, SYN-flag count and packet size. A two-line rule already catches every
  attack, but it misfires on 36.9% of benign traffic. The ensemble does better than that rule on
  benign traffic in this sample, and that is the only positive signal here.
- **The production fill path raises false positives** (14.2% of benign flagged; mostly as
  UDP reflection/amplification). Live traffic with missing fields would be scored this way, which
  points to a real risk: partial-feature inputs (cloud flow logs, host ingress) will over-alert.
  The API already marks such scores `degraded_confidence` when `feature_completeness < 1`.
- **The OOD detector flags almost nothing (≈0%)** even though the inputs are far from the
  training distribution. Its score is "1 − max class probability", so it inherits the classifier's
  over-confidence on shifted inputs. On shifted data it should not be relied on as a zero-day
  alarm. This matches the M1 note that OOD is a supporting signal, not a guarantee.

## Limitations (not measured here)

- Only 3 CICIoT2023 classes, from a 9.2 MB CSV subset; no Mirai, recon, web or spoofing classes.
- **No same-extractor test.** CICIoT2023 or CIC-IDS2017 pcaps were not run through
  `src/features/flow_extractor.py`. This is the test that would justify removing the
  same-dataset caveat, and it has not been done.
- No retraining or domain adaptation, no per-window → per-flow conversion, no confidence intervals
  (single fixed-seed sample; with n=2,000 per class the normal-approximation 95% half-width on a
  rate p is 1.96·√(p(1−p)/2000) ≈ 4.4·√(p(1−p)) percentage points, at most ±2.2 points; it is
  meaningless near 0% or 100%, where an exact interval would be needed).

## Reproduce

```bash
python -m src.eval.cross_dataset --per-class 2000     # ~25 min on a laptop CPU; writes results.json
pytest tests/test_cross_dataset.py -q                 # harness tests + baseline reproduction check
DDOS_RUN_SLOW=1 pytest tests/test_cross_dataset.py -q # also re-runs the ensemble and compares exactly
```
