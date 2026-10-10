# -*- coding: utf-8 -*-
"""
DDoS Classifier — Layer 2 ML Model Wrapper.

Provides an inference interface for multi-class DDoS attack detection models
trained on CICDDoS2019 flow features (77 features).
"""
import os
import sys
from pathlib import Path

# Ensure workspace root is in sys.path
PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import joblib
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Tuple, Union
from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES, NUM_FEATURES


# Canonical 13-class taxonomy
CICDDOS2019_CLASSES = [
    "Benign",
    "NTP",
    "TFTP",
    "Syn",
    "UDP",
    "MSSQL",
    "UDP-Lag",
    "DNS",
    "LDAP",
    "SNMP",
    "NetBIOS",
    "Portmap",
    "WebDDoS",
]

LABEL_NORMALIZATION = {
    "DrDoS_UDP": "UDP",
    "DrDoS_MSSQL": "MSSQL",
    "DrDoS_LDAP": "LDAP",
    "DrDoS_NetBIOS": "NetBIOS",
    "DrDoS_NTP": "NTP",
    "DrDoS_DNS": "DNS",
    "DrDoS_SNMP": "SNMP",
    "UDP-lag": "UDP-Lag",
    "UDPLag": "UDP-Lag",
}


class DDoSClassifier:
    """Production wrapper for CICDDoS2019 trained classification models.

    Args:
        model_path: Path to serialized model bundle (.pkl) or trained model object.
    """

    def __init__(self, model_bundle: Optional[Union[str, dict]] = None):
        self.model = None
        self.scaler = None
        self.imputer = None
        self.classes = list(CICDDOS2019_CLASSES)
        self.feature_names = list(CICFLOWMETER_FEATURE_NAMES)

        if isinstance(model_bundle, str) and os.path.isfile(model_bundle):
            self.load(model_bundle)
        elif isinstance(model_bundle, dict):
            self._init_from_dict(model_bundle)

    def _init_from_dict(self, bundle: dict) -> None:
        """Initialize components from a dictionary bundle."""
        self.model = bundle.get("model")
        self.scaler = bundle.get("scaler")
        self.imputer = bundle.get("imputer")
        if "classes" in bundle:
            self.classes = list(bundle["classes"])
        if "feature_names" in bundle:
            self.feature_names = list(bundle["feature_names"])

    def load(self, path: str) -> None:
        """Load model bundle from disk."""
        bundle = joblib.load(path)
        if isinstance(bundle, dict):
            self._init_from_dict(bundle)
        else:
            # Bare model estimator
            self.model = bundle

    def save(self, path: str) -> None:
        """Save model bundle to disk."""
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        bundle = {
            "model": self.model,
            "scaler": self.scaler,
            "imputer": self.imputer,
            "classes": self.classes,
            "feature_names": self.feature_names,
        }
        joblib.dump(bundle, path)

    def _sanitize_features(self, X: np.ndarray) -> np.ndarray:
        """Replace Inf / -Inf with NaN, then impute NaNs with median/0."""
        X_clean = np.where(np.isinf(X), np.nan, X)
        if self.imputer is not None:
            X_clean = self.imputer.transform(X_clean)
        else:
            # Fallback zero-fill
            X_clean = np.nan_to_num(X_clean, nan=0.0, posinf=0.0, neginf=0.0)
        
        if self.scaler is not None:
            X_clean = self.scaler.transform(X_clean)
        return X_clean

    def predict(self, feature_vector: Union[List[float], np.ndarray, Dict[str, float]]) -> str:
        """Convenience method returning the predicted class label string."""
        res = self.predict_vector(feature_vector)
        return res["label"]

    def predict_vector(self, feature_vector: Union[List[float], np.ndarray, Dict[str, float]]) -> dict:
        """Predict class and confidence for a single 77-feature vector or dict.

        Returns:
            dict: {
                "label": str,
                "is_attack": bool,
                "confidence": float,
                "probabilities": Dict[str, float]
            }
        """
        if self.model is None:
            raise RuntimeError("No model loaded. Call load() or provide a model bundle.")

        if isinstance(feature_vector, dict):
            # Extract features in expected canonical order
            vec = [float(feature_vector.get(k, 0.0)) for k in self.feature_names]
            X = np.array([vec], dtype=np.float64)
        elif isinstance(feature_vector, (list, tuple)):
            if len(feature_vector) != len(self.feature_names):
                raise ValueError(
                    f"Expected {len(self.feature_names)} features, got {len(feature_vector)}"
                )
            X = np.array([feature_vector], dtype=np.float64)
        elif isinstance(feature_vector, np.ndarray):
            if feature_vector.ndim == 1:
                X = feature_vector.reshape(1, -1)
            else:
                X = feature_vector
        else:
            raise TypeError(f"Unsupported feature type: {type(feature_vector)}")

        X_proc = self._sanitize_features(X)

        pred_idx = self.model.predict(X_proc)[0]
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X_proc)[0]
            conf = float(np.max(probs))
            prob_dict = {self.classes[i]: float(probs[i]) for i in range(len(self.classes)) if i < len(probs)}
        else:
            conf = 1.0
            prob_dict = {self.classes[pred_idx] if isinstance(pred_idx, (int, np.integer)) else str(pred_idx): 1.0}

        if isinstance(pred_idx, (int, np.integer)):
            label = self.classes[pred_idx]
        else:
            label = str(pred_idx)

        is_attack = (label.lower() != "benign")

        return {
            "label": label,
            "is_attack": is_attack,
            "confidence": conf,
            "probabilities": prob_dict,
        }

    def predict_batch(self, X: Union[pd.DataFrame, np.ndarray]) -> List[dict]:
        """Predict a batch of flow samples."""
        if isinstance(X, pd.DataFrame):
            # Match columns
            cols = [c for c in self.feature_names if c in X.columns]
            if len(cols) == len(self.feature_names):
                X_mat = X[self.feature_names].values.astype(np.float64)
            else:
                X_mat = X.values.astype(np.float64)
        else:
            X_mat = np.asarray(X, dtype=np.float64)

        X_proc = self._sanitize_features(X_mat)
        preds = self.model.predict(X_proc)

        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X_proc)
        else:
            probs = None

        results = []
        for i in range(len(preds)):
            pred_idx = preds[i]
            label = self.classes[pred_idx] if isinstance(pred_idx, (int, np.integer)) else str(pred_idx)
            is_attack = (label.lower() != "benign")
            
            if probs is not None:
                conf = float(np.max(probs[i]))
                pdict = {self.classes[j]: float(probs[i][j]) for j in range(len(self.classes)) if j < len(probs[i])}
            else:
                conf = 1.0
                pdict = {label: 1.0}

            results.append({
                "label": label,
                "is_attack": is_attack,
                "confidence": conf,
                "probabilities": pdict,
            })
        return results
