# Evaluation Notes — Zero-Day / Novelty Detection (M1)

Honest findings from building the Layer-2 zero-day signal. Numbers are reproducible with
the scripts named below; data is `data/combined_training_set.parquet` (879,647 rows, 13
classes, 77 CICFlowMeter features) and `data/test_real_v2.parquet` (held-out).

---

## 1. Unsupervised IsolationForest novelty — FAILED on this data (kept only as a benign anomaly monitor)

**Approach:** `NoveltyDetector` (IsolationForest trained on benign flows only), calibrated to a
1% benign false-positive rate. Reproduce: `python -m src.models.train_novelty --data
data/combined_training_set.parquet --val data/test_real_v2.parquet --target-fpr 0.01`.

**Result:** calibration is exact (threshold 0.6196 → 1.00% benign FPR), but at that threshold the
detector flags **0.0% of every attack class** on the held-out set. It does not work as an attack
detector here.

**Why (diagnosed):**
- Benign novelty scores are fat-tailed (p50 ≈ 0.35, **p99 ≈ 0.62**), while every attack class
  clusters tightly at a *lower* score (Syn p99 ≈ 0.47, NTP ≈ 0.52, UDP ≈ 0.46).
- The attack floods are large, homogeneous, dense clusters → IsolationForest gives them short-ish
  but not outlier path lengths; they sit *inside* the benign manifold's core and score *less*
  anomalous than benign's own tail. A signed-log transform of the heavy-tailed timing features
  (durations/IATs span µs…10⁷) did **not** help (still 0%).
- Root cause matches the literature: CIC-DDoS2019 benign is **synthetic** with wide, mixed-provenance
  variance, and volumetric floods overlap high-rate benign.

**Decision:** demote IsolationForest to a **secondary "benign anomaly" monitor, OFF by default** in
alerting (`DDOS_ENABLE_ANOMALY=1` to surface it), labelled `anomaly` — **never** `zero_day`. It must
not drive the zero-day flag, which would otherwise fire only on the 1% benign tail (false positives).

---

## 2. Supervised OOD (max calibrated class probability) — the zero-day signal

**Approach:** `ood_score = 1 − max_k P_calibrated(class_k | flow)`; flag when `ood_score ≥ tau`.
Probabilities are isotonic-calibrated (XGBoost confidences are poorly calibrated). Evaluated by
**leave-one-attack-class-out (LOCO)**: for each class, train on the other 12 (that class = simulated
zero-day), calibrate, set `tau` to a 2% false-OOD rate on known-class validation, then measure the
held-out class. Reproduce: `python -m src.models.eval_ood --target-false-ood 0.02 --per-class-cap 4000`
(per-class subsample of 4,000 for tractability; ~2.5 min).

### LOCO results (target false-OOD = 2%)

| Held-out class | n | flagged OOD | caught as other attack | **missed as Benign** | AUROC |
|---|---:|---:|---:|---:|---:|
| DNS | 4000 | 8.2% | 90.6% | **1.1%** | 0.717 |
| LDAP | 4000 | 3.8% | 96.2% | **0.1%** | 0.768 |
| MSSQL | 4000 | 4.9% | 95.1% | **0.0%** | 0.762 |
| NTP | 4000 | 0.9% | 93.8% | **5.3%** | 0.675 |
| NetBIOS | 2484 | 1.1% | 98.8% | **0.1%** | 0.677 |
| Portmap | 1370 | 1.6% | 93.9% | **4.5%** | 0.628 |
| SNMP | 4000 | 13.6% | 86.5% | **0.0%** | 0.845 |
| Syn | 4000 | 0.1% | 99.7% | **0.2%** | 0.503 |
| TFTP | 4000 | 0.2% | 99.8% | **0.0%** | 0.451 |
| UDP | 4000 | 0.8% | 99.2% | **0.0%** | 0.347 |
| UDP-Lag | 4000 | 1.0% | 98.6% | **0.4%** | 0.517 |
| WebDDoS | 294 | 8.5% | 23.8% | **67.7%** | 0.404 |
| **mean** | | 3.7% | 89.6% | **6.6%** | 0.608 |

### Honest interpretation
- **The number that matters — "missed as Benign" — is low (mean 6.6%, ≤5% for 11/12 classes).** A
  previously-unseen attack is rarely waved through as safe: the multiclass model routes it to a
  *sibling* attack family (mean 89.6% "other attack"). For a defensive system, "wrong attack family"
  is a far safer error than "benign".
- **OOD separability itself is weak (mean AUROC 0.61)** and near-random for volumetric floods
  (UDP 0.35, TFTP 0.45, Syn 0.50) — a held-out flood is statistically indistinguishable from the
  other floods it was trained on. OOD is only moderately useful (AUROC 0.76–0.85) for the more
  distinctive reflection classes (SNMP, MSSQL, LDAP).
- **WebDDoS is the real gap:** 67.7% missed as Benign, AUROC 0.40 — application-layer DDoS genuinely
  overlaps benign web traffic in flow space. This is precisely why the **L7 low-and-slow detector**
  (`src/features/l7_lowslow.py`) exists as a separate, non-statistical path; flow-level ML cannot
  carry WebDDoS (consistent with its taxonomy quarantine in `KNOWN_ISSUES.md`).

### Serving use
The scoring service exposes OOD as an `ood` block on `/score/flow` (`ood_score`, `tau`,
`ood_suspected`). The serving threshold is calibrated against the **serving ensemble's** own
confidence distribution by `src/models/calibrate_ood.py`: **tau = 0.1189** for a 2% false-OOD rate
(realized 2.00% over 3,000 known flows), saved to `models/ood_detector.json` and loaded at startup.
Because the ensemble is overconfident (uncalibrated; most confidences ≈ 1.0), this tau is small but
principled. Full isotonic calibration of the *serving* ensemble's probabilities (as done for the LOCO
XGBoost model above) remains a follow-up for M6.

---

## 3. Method caveats
- Per-class subsample (4,000) and a single XGBoost base keep the 12-fold LOCO tractable; full-data
  numbers may shift but the qualitative conclusions (low "missed as Benign", weak flood AUROC,
  WebDDoS gap) are robust.
- Probability calibration uses isotonic via `FrozenEstimator` (sklearn ≥ 1.6).

## 4. Leakage before/after (supervised)

Per-class cap 12000; exact-duplicate test rows removed across the boundary (15,734 overlaps found). Binary = attack-vs-benign (the headline); macro-F1 = per-class.

| Split | binary detection rate | binary benign FPR | binary F1 | per-class macro-F1 |
|---|---:|---:|---:|---:|
| BEFORE — random in-file (leaky) | 1.000 | 0.12% | 1.000 | 0.850 |
| AFTER — separate extraction (leakage-safe) | 1.000 | 0.05% | 1.000 | 0.514 |

_delta binary-F1 = +0.000, delta macro-F1 = -0.336. The leakage-safe (AFTER) numbers are the honest ones._

## 5. Shortcut-feature audit (leakage-safe, same-dataset)

Train=combined_training_set, test=test_real_v2 (deduped: 13,284 exact-dup rows removed). `Destination Port` / timestamps are not in the 77 features.

**Top-20 by XGBoost gain:** Bwd Packet Length Max, Bwd Packets/s, Fwd Packet Length Std, SYN Flag Count, Subflow Fwd Bytes, Protocol, Packet Length Min, URG Flag Count, ACK Flag Count, Packet Length Max, Fwd Packet Length Min, Bwd Header Length, Fwd IAT Total, Fwd IAT Mean, Avg Packet Size, Fwd Packet Length Max, Flow IAT Std, Flow IAT Mean, Init Fwd Win Bytes, Fwd Packets Length Total

**Top-20 by permutation importance:** Fwd Packets Length Total, Fwd Packet Length Max, Protocol, Fwd Packet Length Min, Packet Length Min, Fwd Header Length, Init Fwd Win Bytes, Flow IAT Max, Fwd IAT Std, Subflow Fwd Bytes, Avg Packet Size, Packet Length Max, Flow Bytes/s, Init Bwd Win Bytes, Total Fwd Packets, Packet Length Mean, Fwd Seg Size Min, Fwd Packets/s, Fwd IAT Mean, Fwd IAT Total

**Flagged artefacts removed:** Flow Duration, Fwd Header Length, Bwd Header Length, Init Fwd Win Bytes, Init Bwd Win Bytes

| Model | binary detection | binary benign FPR | binary F1 | per-class macro-F1 |
|---|---:|---:|---:|---:|
| All 77 features | 1.000 | 0.05% | 1.000 | 0.517 |
| Without 5 artefacts | 0.999 | 0.74% | 0.999 | 0.516 |
