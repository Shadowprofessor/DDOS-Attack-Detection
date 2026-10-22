# Adversarial & Degraded Input Evaluation Report (Phase 5 Scope / Prompt 13)

## 1. Feature Completeness Downstream Consumption Audit
- **Downstream Components Audited & Resolved**:
  - `src/models/ensemble.py` (`EnsembleClassifier`): Now ingests `feature_completeness` and `source_mode`. Flags `degraded_confidence = True` for completeness < 1.0, and attaches source-specific `degradation_reason` for completeness <= 0.75 across all model combination pathways.
  - `src/api/scoring_service.py` (`FlowFeatures` & `ScoringResult`): Exposes `feature_completeness` and `source_mode`, bridges incoming `Flow` provenance via `to_flow_features()`, and enqueues degraded telemetry to the real-time broadcaster.
  - `src/agent/nemotron_agent.py` (`NemotronThreatAgent`): Ingests `feature_completeness` in `normalize_alert`, injects an explicit input degradation warning into alert prompt context, includes Rule 6 in system instructions, and enforces `[DEGRADED INPUT]` prefix while strictly suppressing `CRITICAL` escalation in heuristic fallback.
  - `src/web/realtime_dashboard` (`broadcaster.py` & `app.js`): Preserves degradation telemetry in WebSocket event streaming, renders `⚠️ DEGRADED (XX%)` badges in the live flow feed, and displays amber degradation callouts in the operator pending actions table.
- **Status**: **Fully Resolved**. `feature_completeness` is actively propagated and consumed across all inference, triage, and visualization layers.

---

## 2. Model Feature Importance Audit: The 23 Backward Features
In `host_ingress` eBPF mode (single host endpoint without a companion TC egress hook), all 23 backward-dependent features are unobserved and zero-filled (`feature_completeness = 0.7013`).

An empirical audit of the trained Phase 1–2 production models reveals a critical divergence between Random Forest and XGBoost:

### Random Forest (`models/cicddos2019_rf.pkl`)
- **Cumulative Backward Feature Weight**: **5.94%**
- **Top Features**: Primarily forward packet lengths, forward IATs, and forward segment sizes (`Fwd Packet Length Min`: 0.0587, `Packet Length Min`: 0.0485, `Fwd Packet Length Max`: 0.0449, `Fwd IAT Mean`: 0.0429).
- **Impact**: Random Forest is relatively resilient to backward feature zero-filling because zero backward features appear in its top 15 decision paths.

### XGBoost (`models/cicddos2019_xgboost.pkl`)
- **Cumulative Backward Feature Weight**: **13.59%**
- **Critical Feature Weights**:
  - **`Bwd Packets/s`**: **Rank #2** overall with **0.0867 (8.67%)** importance gain!
  - **`Down/Up Ratio`**: **Rank #12** overall with **0.0155 (1.55%)** importance gain.
- **Finding**: **`Bwd Packets/s` and `Down/Up Ratio` carry substantial weight (over 10% combined) in the trained XGBoost model.** In `host_ingress` mode, forcing `Bwd Packets/s = 0.0` and `Down/Up Ratio = 0.0` risks inducing systematic misclassifications or confidence degradation for asymmetric floods where the model trained on bidirectional trees expects non-zero backward responses.

---

## 3. Phase 5 Adversarial Testing Scope (Prompt 13 Mandate)

For Prompt 13 (Adversarial Robustness & Input Degradation Testing):
1. **Host Ingress Evaluation (54-Feature Reality)**:
   - Measure ensemble precision, recall, and macro-F1 specifically under `host_ingress` conditions (the 23 backward features masked to 0.0), rather than only the pristine 77-feature lab condition.
   - Quantify the exact drop in XGBoost vs. RF vs. Ensemble F1 score when `Bwd Packets/s` and `Down/Up Ratio` are zero-filled.
2. **Downstream Confidence Calibration**:
   - Evaluate introducing confidence dampening in `EnsembleClassifier` or flagging in `scoring_service.py` when `feature_completeness < 1.0`.
   - Add explicit prompt context in `NemotronThreatAgent` informing the LLM that the flow was captured in `host_ingress` mode with unobserved backward traffic.

---

## 4. Named Finding: Exploitation of Fixed Ingress Zero-Features (Evasion via Asymmetric Telemetry Blindspot)

### Threat Model
An attacker with operational knowledge of a target's `host_ingress` deployment (e.g., eBPF XDP hook attached exclusively to the ingress path without a companion TC egress hook or symmetric tap) specifically targets the static zero-invariance of the 23 backward features. Because backward traffic is physically unobserved at the host ingress NIC hook, the extractor deterministically forces:
- `Bwd Packets/s = 0.0`
- `Down/Up Ratio = 0.0`
- `Total Backward Packets = 0`
- `Bwd Packet Length Mean / Std / Max / Min = 0.0`
- `Bwd IAT Total / Mean / Std / Max / Min = 0.0`

### Empirical Evidence & Vulnerability Analysis
In tree-based ensemble classifiers trained on bidirectional PCAP datasets (such as CICDDoS2019):
- **XGBoost ranks `Bwd Packets/s` #2 overall** with **0.0867 (8.67%)** total gain across all split trees.
- **XGBoost ranks `Down/Up Ratio` #12 overall** with **0.0155 (1.55%)** total gain.
Combined, over **10.22%** of XGBoost's decision weight hinges on these two backward features alone. Forced zeros are not random Gaussian noise that ensemble averaging smooths out; they constitute a **fixed, mathematically predictable constraint** that an adversary can deliberately design attack vectors around. By modulating forward-only packet lengths and inter-arrival times to align with decision tree branches that require `Bwd Packets/s <= 0.0`, an adversary can steer inference towards Benign or low-confidence unclassified leaf nodes.

### Phase 5 (Prompt 13) Test Case Specification
To quantify and harden against this asymmetric evasion vector in Phase 5:
- **Target Test Suite**: `tests/test_adversarial_evasion.py`
- **Perturbation Methodology**:
  1. Hold forward traffic characteristics realistic (valid TCP flags, plausible payload lengths, and consistent rate envelopes).
  2. Synthetically exploit the guaranteed constraint `Bwd Packets/s = 0.0` and `Down/Up Ratio = 0.0` across 3 distinct attack families:
     - **SYN Flood**: Asymmetric high-frequency forward SYN bursts with zero receiver ACKs.
     - **UDP Reflection**: Ingress UDP bursts evaluated under single-direction capture.
     - **HTTP / WebDDoS**: Slow request generation navigating tabular decision boundaries under forced zero backward volume.
  3. **Metrics**: Measure exact misclassification rate, confidence delta, and verify that the downstream degradation guardrails (`degraded_confidence=True`, `[DEGRADED INPUT]` heuristic cap, and LLM input warning) correctly trigger to prevent operator blindsiding.

---

## 5. Layer 1 Packet Sanity Filter: IP Fragmentation & Evasion Evaluation (Prompt 14)

### Evaluation Overview
Following the Prompt 13 baseline (where protocol anomaly flows achieved ~95% evasion against the pure ML ensemble), Layer 1 was hardened with a pre-ensemble `PacketSanityFilter` to intercept malformed and evasion-crafted packets. Prompt 14 extended this filter to close the fragmentation evasion gap, adding structural and stateful detection for:
- **Condition A (`IP_FRAGMENT`)**: Non-first fragments (`ip_frag_offset > 0`).
- **Condition B (`TINY_MF_FRAGMENT`)**: MF-flagged packets (`ip_flags & 0x1`) with total packet length (`header_len + payload_len`) < 576 bytes (violating RFC 791 minimum reassembly buffer requirements).
- **Condition C (`FRAGMENT_FLOOD`)**: Stateful tracking intercepting >50 fragments for the same flow key within a 1-second sliding window.

### Empirical Validation Results (`test_adversarial_fragmentation_evasion`)
Evaluated across 20 synthetic adversarial fragmentation evasion flows (`generate_fragmentation_evasion_flows(n=20, seed=202)`):

- **Total Flows Tested**: 20
- **Caught by Sanity Filter**: 20 (100.0%)
- **Evaded Sanity Filter**: 0 (0.0%)

#### Fragmentation Violation Breakdown (Exact Counts)
- **`IP_FRAGMENT` Violations**: **10**
- **`TINY_MF_FRAGMENT` Violations**: **10**
- **`FRAGMENT_FLOOD` Violations**: **5**

### Operational Impact & Safety Compliance
- **Detection-Only Enforcement**: All fragmentation violations populate `SanityResult.violations` and annotate flow metadata before reaching downstream triage. Zero automated firewall mutations, Docker actions, or OpenFlow drops are triggered without operator approval.
- **AST Safety Verification**: Full static audit passed (`tests/test_mitigation_bypass.py`: 5/5 passing) confirming strict adherence to the Layer 0 approval gate mandate.


