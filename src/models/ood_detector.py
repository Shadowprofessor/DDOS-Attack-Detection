# -*- coding: utf-8 -*-
"""
Supervised out-of-distribution (OOD) / zero-day signal.

Rather than unsupervised novelty (which does not separate CICDDoS2019 attacks from
synthetic benign — see docs/EVAL_NOTES.md), the zero-day signal is the supervised
classifier's uncertainty: a flow whose maximum CALIBRATED class probability is low
means the model is unsure it belongs to ANY known family — the signature of a
previously-unseen attack.

    ood_score = 1 - max_k P_calibrated(class_k | flow)
    ood_suspected = ood_score >= tau      # tau calibrated to a target false-OOD rate

The SAME isotonic-calibrated model + tau back both the deployed `/score/flow` path and
the leave-one-class-out evaluation, so the README numbers describe what runs in serving.
Probabilities are isotonic-calibrated (XGBoost confidences are poorly calibrated).
"""
import json
import os
from typing import Optional

import numpy as np
import joblib


def ood_scores_from_proba(proba) -> np.ndarray:
    """OOD score per row = 1 - max class probability."""
    return 1.0 - np.max(np.asarray(proba, dtype=float), axis=1)


def calibrate_tau(known_val_scores, target_false_ood: float = 0.02) -> float:
    """tau = (1 - target_false_ood) quantile of known-class OOD scores (flags ~target% of known flows)."""
    s = np.asarray(known_val_scores, dtype=float)
    return float(np.quantile(s, 1.0 - target_false_ood))


class OODDetector:
    """OOD assessor. Model-backed (calibrated classifier) when a model is provided,
    else a confidence-only fallback that scores 1 - confidence."""

    def __init__(self, tau: float = 0.5, target_false_ood: float = 0.02,
                 model=None, feature_names: Optional[list] = None, classes: Optional[list] = None):
        self.tau = float(tau)
        self.target_false_ood = float(target_false_ood)
        self.model = model
        self.feature_names = list(feature_names) if feature_names else None
        self.classes = list(classes) if classes is not None else None

    # --- model-backed path -------------------------------------------------
    def _vector(self, features: dict, medians: Optional[dict] = None) -> np.ndarray:
        medians = medians or {}
        return np.array(
            [[float(features.get(c, medians.get(c, 0.0))) for c in self.feature_names]],
            dtype=float,
        )

    def ood_score_features(self, features: dict, medians: Optional[dict] = None) -> float:
        proba = self.model.predict_proba(self._vector(features, medians))
        return float(1.0 - np.max(proba))

    def assess_features(self, features: dict, medians: Optional[dict] = None) -> dict:
        score = self.ood_score_features(features, medians)
        return {"ood_score": round(score, 4), "tau": round(self.tau, 4),
                "ood_suspected": bool(score >= self.tau)}

    def predicted_label(self, features: dict, medians: Optional[dict] = None):
        """Argmax class label (requires `classes`), used to break down non-OOD outcomes."""
        if not self.classes:
            return None
        proba = self.model.predict_proba(self._vector(features, medians))
        return self.classes[int(np.argmax(proba))]

    # --- confidence-only fallback -----------------------------------------
    def assess(self, confidence: float) -> dict:
        score = 1.0 - float(confidence)
        return {"ood_score": round(score, 4), "tau": round(self.tau, 4),
                "ood_suspected": bool(score >= self.tau)}

    @property
    def is_model_backed(self) -> bool:
        return self.model is not None and self.feature_names is not None

    # --- persistence -------------------------------------------------------
    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        if self.model is not None:
            joblib.dump({"model": self.model, "feature_names": self.feature_names,
                         "classes": self.classes,
                         "tau": self.tau, "target_false_ood": self.target_false_ood}, path)
        else:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"tau": self.tau, "target_false_ood": self.target_false_ood}, f)

    @classmethod
    def load(cls, path: str) -> "OODDetector":
        if path.endswith(".json"):
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
            return cls(tau=d.get("tau", 0.5), target_false_ood=d.get("target_false_ood", 0.02))
        bundle = joblib.load(path)
        return cls(tau=bundle.get("tau", 0.5), target_false_ood=bundle.get("target_false_ood", 0.02),
                   model=bundle.get("model"), feature_names=bundle.get("feature_names"),
                   classes=bundle.get("classes"))
