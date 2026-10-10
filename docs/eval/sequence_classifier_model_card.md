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
  - Classification Head: `LayerNorm(77) -> BiLSTM(128, 2, dropout=0.3) -> Concat(fwd, bwd) -> FC(256 -> 128) -> ReLU -> Dropout(0.3) -> FC(128 -> 14)`

---

## Mandatory Caveat & Data Provenance Notice

> [!WARNING]
> **Trained on synthetic pseudo-temporal windows (same-class CSV rows grouped, not real sequential flows). Advantage on genuine low-and-slow attacks is UNVERIFIED until retrained on real packet-sequence data.**

### Explanation
The original raw `.pcap` files for CICDDoS2019 are external multi-hundred gigabyte archives hosted at the University of New Brunswick and are not available in the local deployment environment. Consequently, `train_sequence.py` constructs pseudo-temporal windows by grouping same-class flows from static CSV/parquet datasets. Until retrained on live sequential packet captures stream-processed via `LibpcapBackend` / `FlowExtractor`, claims regarding empirical advantage against real low-and-slow attacks remain unverified.

---

## Slowloris Proxy Heuristic Audit & Findings
Before applying oversampling for low-and-slow attacks, a quantitative audit was conducted across the training data:
- **Heuristic Exploration:** Evaluating a naive `(Flow Duration > 1s) & (Flow Packets/s < 10)` rule revealed that **18,950 Benign flows** and **97,840 TFTP flows** matched. Inspection of sampled Benign rows confirmed that normal long-lived connections (keep-alive, streaming, idle telemetry) exhibit long duration and low packet rate, but with balanced forward/backward packets (mean 20–80 packets) and large server payload responses.
- **Ground Truth Slow Attacks:** In CICDDoS2019 (`UDPLag-testing.parquet`), exactly **51 flows** carry the `WebDDoS` label. Of these, 17 flows are high-duration (>1s up to 31.5s, rate 0.24–5.0 pkt/s, with small forward payloads or 0-byte header stalls), representing genuine Slowloris/GoldenEye attacks.
- **Tightened Heuristic:** The heuristic was tightened to strictly target:
  1. `Label == 'WebDDoS'`, and
  2. Attack-only flows (`is_attack` is True) with `Flow Duration > 1e6 us`, `Flow Packets/s < 10`, `Total Fwd Packets <= 20`, and `Fwd Packets Length Total < 3000`.
  Benign traffic is explicitly protected from ever being classified or oversampled as a slow-attack proxy.

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
