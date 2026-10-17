# Adversarial & Degraded Input Evaluation Report (Phase 5 Scope / Prompt 13)

## 1. Feature Completeness Downstream Consumption Audit
- **Downstream Components Audited**:
  - `src/models/ensemble.py` (`EnsembleClassifier`): Does not inspect `feature_completeness`; executes inference over the 77-dimensional vector regardless of whether backward features are zero-filled.
  - `src/agent/nemotron_agent.py` (`NemotronThreatAgent`): Prompt context builder does not ingest or reason over `feature_completeness` when triaging alerts.
  - `src/api/scoring_service.py` & `src/api/dashboard_ws.py`: Ingress WebSocket telemetry and REST scoring endpoints do not flag degraded-input flows or calibrate confidence based on `feature_completeness`.
- **Finding**: `feature_completeness` is currently a **reported-but-unused metadata field** originating in `CaptureBackend` and stored in `Flow.feature_completeness`.

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
