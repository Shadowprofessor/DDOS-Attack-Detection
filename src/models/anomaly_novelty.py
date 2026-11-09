# -*- coding: utf-8 -*-
"""
Layer 2 zero-day / novelty detector (unsupervised).

The supervised ensemble (RF + XGBoost) can only recognize attack families it was
trained on. This IsolationForest-based detector is trained on BENIGN flow feature
vectors only and scores how anomalous a flow is relative to learned-benign
behaviour. A high novelty score on a flow the supervised models label "Benign" is
a candidate zero-day / previously-unseen attack signal — it runs in parallel to the
supervised path, never replacing it.
"""
import os
from typing import Optional

import numpy as np
import joblib
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

try:
    from src.features.flow_extractor import NUM_FEATURES
except Exception:  # pragma: no cover - fallback if import path differs
    NUM_FEATURES = 77


class NoveltyDetector:
    """IsolationForest novelty detector trained on benign flows only."""

    def __init__(self, n_estimators: int = 200, contamination="auto", random_state: int = 42):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.model: Optional[IsolationForest] = None
        self.scaler: Optional[StandardScaler] = None
        # Calibrated decision threshold (score >= threshold => novel). Default 0.5 until
        # calibrate_threshold() sets it to hit a target benign false-positive rate.
        self.threshold: float = 0.5
        self.target_fpr: Optional[float] = None
        self.feature_names: Optional[list] = None

    @staticmethod
    def _clean(X) -> np.ndarray:
        arr = np.asarray(X, dtype=np.float64)
        if arr.ndim == 1:
            arr = arr.reshape(1, -1)
        return np.nan_to_num(arr, nan=0.0, posinf=1e9, neginf=-1e9)

    def fit(self, X_benign) -> "NoveltyDetector":
        """Fit on benign feature rows (shape N x F)."""
        X = self._clean(X_benign)
        self.scaler = StandardScaler().fit(X)
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=1,
        ).fit(self.scaler.transform(X))
        return self

    def _require_fitted(self) -> None:
        if self.model is None or self.scaler is None:
            raise RuntimeError("NoveltyDetector is not fitted or loaded.")

    def anomaly_score(self, X) -> np.ndarray:
        """Anomaly score in [0, 1] per row; higher = more anomalous (more novel)."""
        self._require_fitted()
        Xs = self.scaler.transform(self._clean(X))
        # IsolationForest.decision_function: higher => more normal. Invert and squash.
        decision = self.model.decision_function(Xs)
        return 1.0 / (1.0 + np.exp(4.0 * decision))

    def is_novel(self, X, threshold: Optional[float] = None) -> np.ndarray:
        """Boolean per row: score >= threshold (defaults to the calibrated self.threshold)."""
        thr = self.threshold if threshold is None else threshold
        return self.anomaly_score(X) >= thr

    def calibrate_threshold(self, X_benign_val, target_fpr: float = 0.01) -> float:
        """Set self.threshold so that only `target_fpr` of held-out BENIGN flows are flagged.

        Uses the (1 - target_fpr) quantile of benign novelty scores, so e.g. target_fpr=0.01
        picks the 99th percentile of benign scores -> ~1% benign false-positive rate.
        """
        scores = self.anomaly_score(X_benign_val)
        self.threshold = float(np.quantile(scores, 1.0 - target_fpr))
        self.target_fpr = float(target_fpr)
        return self.threshold

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "scaler": self.scaler,
                "n_estimators": self.n_estimators,
                "contamination": self.contamination,
                "random_state": self.random_state,
                "threshold": self.threshold,
                "target_fpr": self.target_fpr,
                "feature_names": self.feature_names,
            },
            path,
        )

    @classmethod
    def load(cls, path: str) -> "NoveltyDetector":
        bundle = joblib.load(path)
        obj = cls(
            n_estimators=bundle.get("n_estimators", 200),
            contamination=bundle.get("contamination", "auto"),
            random_state=bundle.get("random_state", 42),
        )
        obj.model = bundle["model"]
        obj.scaler = bundle["scaler"]
        obj.threshold = float(bundle.get("threshold", 0.5))
        obj.target_fpr = bundle.get("target_fpr")
        obj.feature_names = bundle.get("feature_names")
        return obj
