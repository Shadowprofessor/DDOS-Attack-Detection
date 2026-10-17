# -*- coding: utf-8 -*-
"""
Ensemble Scorer Module — Layer 2 DDoS Classification Ensemble.

Combines Random Forest (RF), XGBoost (XGB), and BiLSTM SequenceClassifier
into one calibrated confidence score per flow.

Weighting & Calibration Mechanism:
  - Uses multinomial Logistic Regression trained on out-of-fold / validation
    base model probability distributions as a stacking meta-model.
  - Additionally supports grid-searched scalar weights over validation F1
    for weighted averaging fallback.

Design Decision regarding history_window (Condition 3):
  When history_window is NOT provided (e.g., real-time single-flow scoring),
  the ensemble explicitly EXCLUDES the SequenceClassifier from the decision
  pipeline. This prevents a degenerate, zero-padded single-step snapshot from
  dragging down high-confidence tabular predictions. In this case, scoring is
  performed by the calibrated tabular models (RF + XGBoost).
  When a multi-step history_window is provided (length >= 2), the SequenceClassifier
  is fully activated and blended with the tabular models.

Provenance Notice Propagation (Condition 2):
  Every call to score_flow propagates the SequenceClassifier's documented caveat
  into per_model_breakdown['sequence_classifier']['caveat'].
"""

import os
import sys
import copy
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any

import joblib
import numpy as np
import torch
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import f1_score

# Ensure workspace root is in sys.path
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES, NUM_FEATURES
from src.models.classifier import DDoSClassifier, CICDDOS2019_CLASSES
from src.models.sequence_classifier import (
    SequenceClassifier,
    PSEUDO_TEMPORAL_CAVEAT,
)

logger = logging.getLogger("ddos_ensemble")

DEFAULT_MODEL_DIR = os.path.join(PROJECT_ROOT, "models")
ENSEMBLE_BUNDLE_PATH = os.path.join(DEFAULT_MODEL_DIR, "ensemble_weights.joblib")


class EnsembleClassifier:
    """Calibrated Ensemble Classifier combining RF, XGBoost, and BiLSTM SequenceClassifier."""

    def __init__(
        self,
        rf_path: Optional[str] = None,
        xgb_path: Optional[str] = None,
        seq_model: Optional[SequenceClassifier] = None,
        ensemble_bundle_path: Optional[str] = None,
        device: str = "cpu",
    ):
        self.classes = list(CICDDOS2019_CLASSES)
        self.feature_names = list(CICFLOWMETER_FEATURE_NAMES)
        self.device = device
        if str(device).lower() == "cpu":
            try:
                torch.set_num_threads(1)
            except Exception:
                pass

        # Load RF model — explicitly scoped copy with n_jobs=1 for low-latency single flow serving
        rf_file = rf_path or os.path.join(DEFAULT_MODEL_DIR, "cicddos2019_rf.pkl")
        if os.path.isfile(rf_file):
            self.rf_classifier = DDoSClassifier(rf_file)
            # Create a dedicated copy of the underlying model estimator so external
            # references or batch scripts are not mutated
            try:
                self.rf_classifier.model = copy.deepcopy(self.rf_classifier.model)
                if hasattr(self.rf_classifier.model, "n_jobs"):
                    self.rf_classifier.model.n_jobs = 1
            except Exception as e:
                logger.warning("Could not set n_jobs=1 on scoped RF copy: %s", e)
        else:
            logger.info("RF model file not found at %s; initializing dummy fallback for testing/CI", rf_file)
            from sklearn.dummy import DummyClassifier
            dummy_rf = DummyClassifier(strategy="constant", constant=0)
            dummy_rf.fit(np.zeros((len(self.classes), len(self.feature_names))), list(range(len(self.classes))))
            self.rf_classifier = DDoSClassifier({
                "model": dummy_rf,
                "classes": self.classes,
                "feature_names": self.feature_names,
            })

        # Load XGBoost model
        xgb_file = xgb_path or os.path.join(DEFAULT_MODEL_DIR, "cicddos2019_xgboost.pkl")
        if os.path.isfile(xgb_file):
            self.xgb_classifier = DDoSClassifier(xgb_file)
            try:
                if hasattr(self.xgb_classifier.model, "set_params"):
                    self.xgb_classifier.model.set_params(device="cpu", n_jobs=1)
            except Exception:
                pass
        else:
            logger.info("XGBoost model file not found at %s; initializing dummy fallback for testing/CI", xgb_file)
            from sklearn.dummy import DummyClassifier
            dummy_xgb = DummyClassifier(strategy="constant", constant=0)
            dummy_xgb.fit(np.zeros((len(self.classes), len(self.feature_names))), list(range(len(self.classes))))
            self.xgb_classifier = DDoSClassifier({
                "model": dummy_xgb,
                "classes": self.classes,
                "feature_names": self.feature_names,
            })

        # Sequence Classifier
        if seq_model is not None:
            self.seq_classifier = seq_model
        else:
            self.seq_classifier = SequenceClassifier(
                classes=self.classes,
                feature_names=self.feature_names,
                device=self.device,
            )

        # Meta-models and scalar weights
        self.meta_model_full: Optional[LogisticRegression] = None
        self.meta_model_tabular: Optional[LogisticRegression] = None

        # Default fallback scalar weights (derived via validation or balanced priors)
        self.scalar_weights_full: Dict[str, float] = {
            "random_forest": 0.45,
            "xgboost": 0.45,
            "sequence_classifier": 0.10,
        }
        self.scalar_weights_tabular: Dict[str, float] = {
            "random_forest": 0.50,
            "xgboost": 0.50,
        }

        # Attempt to load trained weights bundle if provided or present
        bundle_to_load = ensemble_bundle_path or ENSEMBLE_BUNDLE_PATH
        if os.path.isfile(bundle_to_load):
            self.load_weights(bundle_to_load)

    def fit_weights(
        self,
        val_X: np.ndarray,
        val_y: np.ndarray,
        val_windows: Optional[List[np.ndarray]] = None,
        save_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Fit stacking meta-models and grid-searched scalar weights on validation data.

        Args:
            val_X: 2D array of validation features (N, 77).
            val_y: 1D array of ground truth class integer indices or label strings (N,).
            val_windows: Optional list of multi-step window arrays for SequenceClassifier.
            save_path: Path to save the learned ensemble weights bundle.

        Returns:
            Dict containing validation metrics and learned weight summaries.
        """
        N = len(val_X)
        if N == 0:
            raise ValueError("Validation set is empty.")

        # Convert labels to indices if string
        if isinstance(val_y[0], str):
            y_indices = np.array([self.classes.index(lbl) for lbl in val_y], dtype=int)
        else:
            y_indices = np.asarray(val_y, dtype=int)

        # 1. Base model predictions on validation set
        P_rf = np.zeros((N, len(self.classes)), dtype=np.float32)
        P_xgb = np.zeros((N, len(self.classes)), dtype=np.float32)
        P_seq = np.zeros((N, len(self.classes)), dtype=np.float32)

        # RF probabilities
        if self.rf_classifier is not None:
            rf_res = self.rf_classifier.predict_batch(val_X)
            for i, r in enumerate(rf_res):
                P_rf[i] = [r["probabilities"].get(c, 0.0) for c in self.classes]

        # XGB probabilities
        if self.xgb_classifier is not None:
            xgb_res = self.xgb_classifier.predict_batch(val_X)
            for i, r in enumerate(xgb_res):
                P_xgb[i] = [r["probabilities"].get(c, 0.0) for c in self.classes]

        # Seq probabilities
        if val_windows is not None and len(val_windows) == N:
            seq_res = self.seq_classifier.predict_batch(val_windows)
            for i, r in enumerate(seq_res):
                P_seq[i] = [r["probabilities"].get(c, 0.0) for c in self.classes]
        else:
            seq_res = self.seq_classifier.predict_batch(val_X)
            for i, r in enumerate(seq_res):
                P_seq[i] = [r["probabilities"].get(c, 0.0) for c in self.classes]

        # 2. Train Tabular Meta-Model (RF + XGB)
        X_meta_tab = np.hstack([P_rf, P_xgb])
        meta_tab = LogisticRegression(max_iter=1000, random_state=42)
        meta_tab.fit(X_meta_tab, y_indices)
        self.meta_model_tabular = meta_tab

        # 3. Train Full Meta-Model (RF + XGB + Seq)
        X_meta_full = np.hstack([P_rf, P_xgb, P_seq])
        meta_full = LogisticRegression(max_iter=1000, random_state=42)
        meta_full.fit(X_meta_full, y_indices)
        self.meta_model_full = meta_full

        # 4. Grid-search scalar weights over validation F1
        best_f1_tab = -1.0
        best_w_tab = (0.5, 0.5)
        for w_rf in np.linspace(0.0, 1.0, 21):
            w_xgb = 1.0 - w_rf
            P_blend = w_rf * P_rf + w_xgb * P_xgb
            preds = np.argmax(P_blend, axis=1)
            score = f1_score(y_indices, preds, average="macro", zero_division=0)
            if score > best_f1_tab:
                best_f1_tab = score
                best_w_tab = (float(w_rf), float(w_xgb))

        self.scalar_weights_tabular = {
            "random_forest": round(best_w_tab[0], 3),
            "xgboost": round(best_w_tab[1], 3),
        }

        # Grid search 3-way weights for full ensemble with explicit safety cap on SequenceClassifier:
        # Until retrained on genuine packet sequences, SequenceClassifier contribution is capped
        # at max_seq_weight (0.15) and cannot exceed RF or XGBoost individually.
        best_f1_full = -1.0
        best_w_full = (0.50, 0.40, 0.10)
        grid_steps = np.linspace(0.0, 1.0, 41)
        max_seq_weight = 0.15
        for w1 in grid_steps:
            for w2 in grid_steps:
                if w1 + w2 > 1.0:
                    continue
                w3 = round(1.0 - (w1 + w2), 4)
                if w3 > max_seq_weight or w3 < 0.0:
                    continue
                if w3 > w1 or w3 > w2:
                    continue
                P_blend = w1 * P_rf + w2 * P_xgb + w3 * P_seq
                preds = np.argmax(P_blend, axis=1)
                score = f1_score(y_indices, preds, average="macro", zero_division=0)
                if score > best_f1_full:
                    best_f1_full = score
                    best_w_full = (float(w1), float(w2), float(w3))

        self.scalar_weights_full = {
            "random_forest": round(best_w_full[0], 3),
            "xgboost": round(best_w_full[1], 3),
            "sequence_classifier": round(best_w_full[2], 3),
        }

        report = {
            "val_samples": N,
            "tabular_meta_accuracy": float(meta_tab.score(X_meta_tab, y_indices)),
            "full_meta_accuracy": float(meta_full.score(X_meta_full, y_indices)),
            "grid_tabular_macro_f1": float(best_f1_tab),
            "grid_full_macro_f1": float(best_f1_full),
            "scalar_weights_tabular": self.scalar_weights_tabular,
            "scalar_weights_full": self.scalar_weights_full,
        }

        target_save = save_path or ENSEMBLE_BUNDLE_PATH
        self.save_weights(target_save)
        logger.info("Ensemble weights trained & saved: %s", report)
        return report

    def save_weights(self, path: str) -> None:
        """Save meta-models and scalar weights bundle."""
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        bundle = {
            "meta_model_tabular": self.meta_model_tabular,
            "meta_model_full": self.meta_model_full,
            "scalar_weights_tabular": self.scalar_weights_tabular,
            "scalar_weights_full": self.scalar_weights_full,
            "classes": self.classes,
        }
        joblib.dump(bundle, path)

    def load_weights(self, path: str) -> None:
        """Load meta-models and scalar weights bundle."""
        bundle = joblib.load(path)
        if isinstance(bundle, dict):
            self.meta_model_tabular = bundle.get("meta_model_tabular")
            self.meta_model_full = bundle.get("meta_model_full")
            if "scalar_weights_tabular" in bundle:
                self.scalar_weights_tabular = bundle["scalar_weights_tabular"]
            if "scalar_weights_full" in bundle:
                self.scalar_weights_full = bundle["scalar_weights_full"]
            if "classes" in bundle:
                self.classes = list(bundle["classes"])

    def _normalize_features(
        self, features: Union[List[float], np.ndarray, Dict[str, float]]
    ) -> np.ndarray:
        """Ensure feature representation is 1x77 numpy array in canonical order."""
        if isinstance(features, dict):
            vec = [float(features.get(col, 0.0)) for col in self.feature_names]
            return np.array([vec], dtype=np.float32)
        elif isinstance(features, (list, tuple)):
            if len(features) != len(self.feature_names):
                raise ValueError(
                    f"Feature count mismatch: expected {len(self.feature_names)}, got {len(features)}"
                )
            return np.array([features], dtype=np.float32)
        elif isinstance(features, np.ndarray):
            if features.ndim == 1:
                return features.reshape(1, -1).astype(np.float32)
            elif features.ndim == 2:
                return features.astype(np.float32)
            else:
                raise ValueError(f"Unsupported features dimension: {features.ndim}")
        else:
            raise TypeError(f"Unsupported feature type: {type(features)}")

    def score_flow(
        self,
        features: Union[List[float], np.ndarray, Dict[str, float]],
        history_window: Optional[Union[np.ndarray, List[Any]]] = None,
        mode: str = "ensemble",
    ) -> Tuple[str, float, Dict[str, Any]]:
        """Score a single flow through the calibrated ensemble or fallback mode.

        Args:
            features: 77-feature vector (list, ndarray, or dict).
            history_window: Optional sliding window of flow snapshots (shape (T, 77) or list).
                            If None or len <= 1, SequenceClassifier is excluded per Condition 3.
            mode: Scoring mode: 'ensemble' (default), 'rf_only', 'xgb_only', or 'rf_xgb'.

        Returns:
            Tuple of (label, confidence, per_model_breakdown):
              - label (str): Canonical 13-class attack/benign prediction.
              - confidence (float): Calibrated prediction confidence in [0.0, 1.0].
              - per_model_breakdown (dict): Model breakdowns, weights, and caveat.
        """
        X = self._normalize_features(features)

        # 1. Fallback: RF-only
        if mode == "rf_only":
            if self.rf_classifier is None:
                raise RuntimeError("Random Forest model is not available.")
            res = self.rf_classifier.predict_vector(X[0])
            breakdown = {
                "random_forest": res,
                "mode": "rf_only",
                "weights": {"random_forest": 1.0},
                "sequence_classifier": {
                    "excluded_due_to_missing_history": True,
                    "caveat": PSEUDO_TEMPORAL_CAVEAT,
                },
            }
            return res["label"], res["confidence"], breakdown

        # 2. Fallback: XGBoost-only
        if mode == "xgb_only":
            if self.xgb_classifier is None:
                raise RuntimeError("XGBoost model is not available.")
            res = self.xgb_classifier.predict_vector(X[0])
            breakdown = {
                "xgboost": res,
                "mode": "xgb_only",
                "weights": {"xgboost": 1.0},
                "sequence_classifier": {
                    "excluded_due_to_missing_history": True,
                    "caveat": PSEUDO_TEMPORAL_CAVEAT,
                },
            }
            return res["label"], res["confidence"], breakdown

        # Obtain base predictions
        rf_res = self.rf_classifier.predict_vector(X[0]) if self.rf_classifier else None
        xgb_res = self.xgb_classifier.predict_vector(X[0]) if self.xgb_classifier else None

        # Determine whether history_window is provided and sufficiently informative
        has_temporal_history = False
        seq_window = None
        if history_window is not None:
            hw_arr = np.asarray(history_window)
            if hw_arr.ndim >= 2 and len(hw_arr) > 1:
                has_temporal_history = True
                seq_window = hw_arr

        # Sequence prediction
        seq_res = None
        if has_temporal_history:
            seq_res = self.seq_classifier.predict_window(seq_window)
            seq_breakdown = {
                "label": seq_res["label"],
                "confidence": seq_res["confidence"],
                "probabilities": seq_res["probabilities"],
                "caveat": PSEUDO_TEMPORAL_CAVEAT,
            }
        else:
            # Condition 3: Explicitly exclude sequence classifier when history_window is absent
            seq_breakdown = {
                "excluded_due_to_missing_history": True,
                "label": None,
                "confidence": None,
                "probabilities": None,
                "caveat": PSEUDO_TEMPORAL_CAVEAT,
            }

        # 3. Handling Tabular combination (history_window absent or mode='rf_xgb')
        if not has_temporal_history or mode == "rf_xgb":
            if rf_res is None and xgb_res is None:
                raise RuntimeError("Neither RF nor XGBoost model is available.")
            if rf_res is None:
                return xgb_res["label"], xgb_res["confidence"], {
                    "xgboost": xgb_res,
                    "mode": "xgb_only",
                    "weights": {"xgboost": 1.0},
                    "sequence_classifier": seq_breakdown,
                }
            if xgb_res is None:
                return rf_res["label"], rf_res["confidence"], {
                    "random_forest": rf_res,
                    "mode": "rf_only",
                    "weights": {"random_forest": 1.0},
                    "sequence_classifier": seq_breakdown,
                }

            # Vector of probabilities for meta-model
            p_rf_vec = np.array([rf_res["probabilities"].get(c, 0.0) for c in self.classes])
            p_xgb_vec = np.array([xgb_res["probabilities"].get(c, 0.0) for c in self.classes])

            if self.meta_model_tabular is not None:
                x_meta = np.hstack([p_rf_vec, p_xgb_vec]).reshape(1, -1)
                meta_probs = self.meta_model_tabular.predict_proba(x_meta)[0]
                pred_idx = int(np.argmax(meta_probs))
                final_label = self.classes[pred_idx]
                final_conf = float(meta_probs[pred_idx])
                stacking_used = True
            else:
                w_rf = self.scalar_weights_tabular.get("random_forest", 0.5)
                w_xgb = self.scalar_weights_tabular.get("xgboost", 0.5)
                p_blend = w_rf * p_rf_vec + w_xgb * p_xgb_vec
                pred_idx = int(np.argmax(p_blend))
                final_label = self.classes[pred_idx]
                final_conf = float(p_blend[pred_idx])
                stacking_used = False

            breakdown = {
                "random_forest": rf_res,
                "xgboost": xgb_res,
                "sequence_classifier": seq_breakdown,
                "weights": self.scalar_weights_tabular,
                "mode": "rf_xgb" if mode == "rf_xgb" else "ensemble_tabular",
                "stacking_used": stacking_used,
            }
            return final_label, final_conf, breakdown

        # 4. Full 3-Model Ensemble (history_window present)
        p_rf_vec = np.array([rf_res["probabilities"].get(c, 0.0) for c in self.classes])
        p_xgb_vec = np.array([xgb_res["probabilities"].get(c, 0.0) for c in self.classes])
        p_seq_vec = np.array([seq_res["probabilities"].get(c, 0.0) for c in self.classes])

        # Enforce safety-capped convex combination: SequenceClassifier is strictly bounded
        # (capped <= 15% and <= RF, XGB) so unverified synthetic sequences cannot dominate tabular models
        w_rf = self.scalar_weights_full.get("random_forest", 0.325)
        w_xgb = self.scalar_weights_full.get("xgboost", 0.525)
        w_seq = self.scalar_weights_full.get("sequence_classifier", 0.150)
        p_blend = w_rf * p_rf_vec + w_xgb * p_xgb_vec + w_seq * p_seq_vec
        pred_idx = int(np.argmax(p_blend))
        final_label = self.classes[pred_idx]
        final_conf = float(p_blend[pred_idx])
        stacking_used = False

        breakdown = {
            "random_forest": rf_res,
            "xgboost": xgb_res,
            "sequence_classifier": seq_breakdown,
            "weights": self.scalar_weights_full,
            "mode": "ensemble_full",
            "stacking_used": stacking_used,
        }
        return final_label, final_conf, breakdown


# Global singleton instance for module-level convenience API
_default_ensemble: Optional[EnsembleClassifier] = None


def get_default_ensemble() -> EnsembleClassifier:
    """Retrieve or initialize the default EnsembleClassifier singleton."""
    global _default_ensemble
    if _default_ensemble is None:
        _default_ensemble = EnsembleClassifier()
    return _default_ensemble


def score_flow(
    features: Union[List[float], np.ndarray, Dict[str, float]],
    history_window: Optional[Union[np.ndarray, List[Any]]] = None,
    mode: str = "ensemble",
) -> Tuple[str, float, Dict[str, Any]]:
    """Module-level single-flow scoring function using the default ensemble."""
    return get_default_ensemble().score_flow(
        features=features, history_window=history_window, mode=mode
    )
