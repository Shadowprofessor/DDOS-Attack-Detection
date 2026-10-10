# Model Card: SequenceClassifier (BiLSTM)

## Overview
- **Model Name:** `SequenceClassifier`
- **Architecture:** PyTorch Bidirectional LSTM (`BiLSTMSequenceModel`)
- **Parameters:**
  - Hidden Size: 128 (concatenated bidirectional hidden state = 256)
  - Number of Layers: 2
  - Dropout: 0.3
  - Window Size ($W$): 10 timesteps (configurable)
  - Input Features: 77 features per timestep (`CICFLOWMETER_FEATURE_NAMES`)
  - Classification Head: `LayerNorm(77) -> BiLSTM(128, 2, dropout=0.3) -> Concat(fwd, bwd) -> FC(256 -> 128) -> ReLU -> Dropout(0.3) -> FC(128 -> 13)`
  - Taxonomy (13 Classes, identical to production RF/XGBoost bundles):
    `['Benign', 'DNS', 'LDAP', 'MSSQL', 'NTP', 'NetBIOS', 'Portmap', 'SNMP', 'Syn', 'TFTP', 'UDP', 'UDP-Lag', 'WebDDoS']`

---

## Mandatory Caveat & Data Provenance Notice

> [!WARNING]
> **Trained on synthetic pseudo-temporal windows (same-class CSV rows grouped, not real sequential flows). Advantage on genuine low-and-slow attacks is UNVERIFIED until retrained on real packet-sequence data.**

### Explanation
The original raw `.pcap` files for CICDDoS2019 are external multi-hundred gigabyte archives hosted at the University of New Brunswick and are not available in the local deployment environment. Consequently, `train_sequence.py` constructs pseudo-temporal windows by grouping same-class flows from static CSV/parquet datasets. Until retrained on live sequential packet captures stream-processed via `LibpcapBackend` / `FlowExtractor`, claims regarding empirical advantage against real low-and-slow attacks remain unverified.

---

## Slowloris Proxy Heuristic Audit & Findings
A quantitative audit across the full training dataset (17 parquet partitions, 419k flows) evaluated slow-proxy conditions:
- **Condition Audit:**
  - Naive condition (`Duration > 1s` & `Rate < 10 pkt/s`): Matched 18,950 Benign flows and 97,840 TFTP flows.
  - Tightened condition (`is_attack` & `Duration > 1s` & `Rate < 10` & `Fwd Pkts <= 20` & `Fwd Bytes < 3000`):
    - **TFTP:** 74,318 flows (75.13% of TFTP) matched due to single-packet probe timeouts.
    - **Syn:** 40,519 flows (82.07% of Syn) matched due to unreplied SYN probe timeouts.
    - **UDP-Lag:** 5,765 flows (64.58%) matched.
    - **WebDDoS:** 51 flows (100.0%) matched.
- **Strict Label-Level Allowlist Resolution:**
  To prevent massive flood classes (TFTP and Syn) from hijacking the proxy oversampling path, `is_slowloris_proxy` enforces `SLOWLORIS_PROXY_ALLOWLIST = {"WebDDoS", "slowloris", "goldeneye", "ddos-http_flood"}`.
  Under this allowlist:
  - **WebDDoS:** 51 flows (100%)
  - **TFTP:** 0 flows (0%)
  - **Syn:** 0 flows (0%)
  - **All other attacks & Benign:** 0 flows (0%)

---

## Taxonomy Harmonization (Prompt 4b Resolution)
- **13 Classes Standardized:** Production Random Forest and XGBoost bundles in `models/` contain 13 classes sorted alphabetically. The 14th class (`Other_DDoS`) observed during Phase 1 multi-dataset training originated from InSDN generic DoS/DDoS labels. Because multi-dataset models failed the performance gate (0.983 vs 0.998 baseline), production models were preserved at 13 classes.
- **Harmonization Choice:** `SequenceClassifier` standardizes strictly on the 13 canonical classes in identical alphabetical order (`['Benign', 'DNS', ..., 'WebDDoS']`). Any `Other_DDoS` integration is deferred to Prompt 5 ensemble harmonization to prevent dimensional mismatch during voting and probability averaging.

---

## Drop-In Interface Compatibility
`SequenceClassifier` implements the exact interface of `DDoSClassifier` in `src.models.classifier`:
- `predict(feature_vector) -> str`
- `predict_vector(feature_vector) -> dict` returning `{"label": str, "is_attack": bool, "confidence": float, "probabilities": dict}`
- `predict_window(window: np.ndarray) -> dict` for $(W, 77)$ temporal windows
- `predict_batch(X) -> List[dict]` accepting both 2D $(N, 77)$ and 3D $(N, W, 77)$ arrays
- `save(path)` and `load(path)` via PyTorch checkpoint bundle

---

## Latency & Safety Specifications
- **Inference Latency:** < 50ms per window (achieved mean ~1.5ms, 95th percentile ~2.8ms on CPU).
- **Fault Tolerance:**
  - Inf and NaN inputs are automatically sanitized to 0.0 or median imputed.
  - Windows shorter than $W$ (e.g. 1 to 9 steps) are automatically left-padded with zeros.
