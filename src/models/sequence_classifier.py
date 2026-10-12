# -*- coding: utf-8 -*-
"""
Sequence Classifier Module for Low-and-Slow DDoS Attack Detection.

CAVEAT / DATASET PROVENANCE NOTICE:
Trained on synthetic pseudo-temporal windows (same-class CSV rows grouped, not real
sequential flows). Advantage on genuine low-and-slow attacks is UNVERIFIED until
retrained on real packet-sequence data.

This module provides:
  - BiLSTMSequenceModel: PyTorch bidirectional LSTM operating over sliding windows
    of 77 CICFlowMeter statistical features per timestep.
  - SequenceClassifier: Drop-in alternative to DDoSClassifier exposing predict(),
    predict_vector(), predict_window(), predict_batch(), save(), and load().
"""

import os
import sys
import copy
from typing import Dict, List, Optional, Tuple, Union, Any

import numpy as np
import torch
import torch.nn as nn

from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES, NUM_FEATURES
from src.models.classifier import CICDDOS2019_CLASSES

# Exact requirement caveat from architecture specification
PSEUDO_TEMPORAL_CAVEAT: str = (
    "Trained on synthetic pseudo-temporal windows (same-class CSV rows grouped, not real "
    "sequential flows). Advantage on genuine low-and-slow attacks is UNVERIFIED until "
    "retrained on real packet-sequence data."
)


class BiLSTMSequenceModel(nn.Module):
    """PyTorch BiLSTM sequence classifier for sliding windows of flow features.

    Architecture:
        Input: (batch, window_size, num_features=77)
        LayerNorm(77)
        BiLSTM(input_size=77, hidden_size=128, num_layers=2, dropout=0.3, bidirectional=True)
        Concat last-timestep forward & first-timestep backward representations (256)
        Linear(256 -> 128) -> ReLU -> Dropout(0.3)
        Linear(128 -> num_classes)
    """

    def __init__(
        self,
        num_features: int = NUM_FEATURES,
        num_classes: int = len(CICDDOS2019_CLASSES),
        hidden_size: int = 128,
        num_layers: int = 2,
        dropout: float = 0.3,
    ):
        super().__init__()
        self.num_features = num_features
        self.num_classes = num_classes
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.dropout_rate = dropout

        self.layer_norm = nn.LayerNorm(num_features)
        self.lstm = nn.LSTM(
            input_size=num_features,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0.0,
        )
        self.fc = nn.Sequential(
            nn.Linear(hidden_size * 2, 128),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(128, num_classes),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass.

        Args:
            x: Input tensor of shape (batch, window_size, num_features) or (window_size, num_features).

        Returns:
            Logits tensor of shape (batch, num_classes).
        """
        if x.dim() == 2:
            x = x.unsqueeze(0)

        # Layer normalization across feature dimension
        x = self.layer_norm(x)

        # LSTM forward pass
        lstm_out, (hn, cn) = self.lstm(x)

        # Extract concatenated forward and backward hidden state:
        # hn shape: (num_layers * 2, batch, hidden_size)
        # hn[-2] is the last layer's forward hidden state
        # hn[-1] is the last layer's backward hidden state
        fwd_last = hn[-2]
        bwd_last = hn[-1]
        concat_hidden = torch.cat([fwd_last, bwd_last], dim=-1)

        logits = self.fc(concat_hidden)
        return logits


class SequenceClassifier:
    """Drop-in DDoSClassifier-compatible wrapper around BiLSTMSequenceModel.

    Features:
      - Sliding window prediction via predict_window()
      - Single-vector backwards compatibility via predict_vector() and predict()
      - Handles both 2D and 3D inputs in predict_batch()
      - Automatic short-window padding (left-padded with zeros)
      - NaN / Inf sanitization
      - PyTorch model checkpointing (save / load)
    """

    CAVEAT: str = PSEUDO_TEMPORAL_CAVEAT

    def __init__(
        self,
        model: Optional[BiLSTMSequenceModel] = None,
        classes: Optional[List[str]] = None,
        feature_names: Optional[List[str]] = None,
        window_size: int = 10,
        scaler: Optional[Any] = None,
        imputer: Optional[Any] = None,
        device: Optional[str] = None,
    ):
        self.window_size = int(window_size)
        self.classes = list(classes) if classes is not None else list(CICDDOS2019_CLASSES)
        self.feature_names = (
            list(feature_names) if feature_names is not None else list(CICFLOWMETER_FEATURE_NAMES)
        )
        self.scaler = scaler
        self.imputer = imputer

        if device is None:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        else:
            self.device = torch.device(device)

        if model is not None:
            self.model = model.to(self.device)
            self.model.eval()
        else:
            self.model = BiLSTMSequenceModel(
                num_features=len(self.feature_names),
                num_classes=len(self.classes),
            ).to(self.device)
            self.model.eval()

    def _sanitize_features(self, X: np.ndarray) -> np.ndarray:
        """Sanitize Inf and NaN values from raw feature matrix."""
        X_clean = np.where(np.isinf(X), np.nan, X)
        if self.imputer is not None:
            # Imputer expects 2D (samples, features)
            orig_shape = X_clean.shape
            if X_clean.ndim == 3:
                flat = X_clean.reshape(-1, orig_shape[-1])
                flat = self.imputer.transform(flat)
                X_clean = flat.reshape(orig_shape)
            else:
                X_clean = self.imputer.transform(X_clean)
        else:
            X_clean = np.nan_to_num(X_clean, nan=0.0, posinf=0.0, neginf=0.0)

        if self.scaler is not None:
            orig_shape = X_clean.shape
            if X_clean.ndim == 3:
                flat = X_clean.reshape(-1, orig_shape[-1])
                flat = self.scaler.transform(flat)
                X_clean = flat.reshape(orig_shape)
            else:
                X_clean = self.scaler.transform(X_clean)

        return X_clean

    def _pad_window(self, window: np.ndarray) -> np.ndarray:
        """Ensure a single window has exactly `window_size` steps via left-padding.

        Args:
            window: 2D array of shape (T, num_features).

        Returns:
            2D array of shape (window_size, num_features).
        """
        T, F = window.shape
        if T == self.window_size:
            return window
        elif T < self.window_size:
            pad = np.zeros((self.window_size - T, F), dtype=window.dtype)
            return np.vstack([pad, window])
        else:
            # Window longer than window_size: take the most recent window_size steps
            return window[-self.window_size:]

    def predict_window(self, window: np.ndarray) -> Dict[str, Any]:
        """Predict class and probabilities for a sliding window of feature snapshots.

        Args:
            window: 2D array of shape (T, num_features).

        Returns:
            dict: {
                "label": str,
                "is_attack": bool,
                "confidence": float,
                "probabilities": Dict[str, float]
            }
        """
        if self.model is None:
            raise RuntimeError("No model available in SequenceClassifier.")

        if not isinstance(window, np.ndarray):
            window = np.array(window, dtype=np.float32)

        if window.ndim != 2:
            raise ValueError(f"Expected 2D window (T, {len(self.feature_names)}), got shape {window.shape}")

        if window.shape[1] != len(self.feature_names):
            raise ValueError(
                f"Feature count mismatch: expected {len(self.feature_names)}, got {window.shape[1]}"
            )

        padded = self._pad_window(window)
        sanitized = self._sanitize_features(padded)

        tensor_in = torch.as_tensor(sanitized, dtype=torch.float32, device=self.device).unsqueeze(0)

        self.model.eval()
        with torch.inference_mode():
            logits = self.model(tensor_in)
            probs = torch.softmax(logits, dim=-1).squeeze(0).cpu().numpy()

        pred_idx = int(np.argmax(probs))
        pred_label = self.classes[pred_idx]
        confidence = float(probs[pred_idx])
        is_attack = (pred_label.lower() != "benign")

        prob_dict = {
            self.classes[i]: float(probs[i])
            for i in range(len(self.classes))
            if i < len(probs)
        }

        return {
            "label": pred_label,
            "is_attack": is_attack,
            "confidence": confidence,
            "probabilities": prob_dict,
        }

    def predict(self, feature_vector: Union[List[float], np.ndarray, Dict[str, float]]) -> str:
        """Convenience method returning predicted class label string for a single snapshot."""
        res = self.predict_vector(feature_vector)
        return res["label"]

    def predict_vector(
        self, feature_vector: Union[List[float], np.ndarray, Dict[str, float]]
    ) -> Dict[str, Any]:
        """DDoSClassifier-compatible single-vector inference.

        Wraps the single 77-feature vector as a 1-step window, padded to `window_size`.

        Returns:
            dict: {
                "label": str,
                "is_attack": bool,
                "confidence": float,
                "probabilities": Dict[str, float]
            }
        """
        if isinstance(feature_vector, dict):
            vec = [float(feature_vector.get(k, 0.0)) for k in self.feature_names]
            arr = np.array([vec], dtype=np.float32)
        elif isinstance(feature_vector, (list, tuple)):
            if len(feature_vector) != len(self.feature_names):
                raise ValueError(
                    f"Expected {len(self.feature_names)} features, got {len(feature_vector)}"
                )
            arr = np.array([feature_vector], dtype=np.float32)
        elif isinstance(feature_vector, np.ndarray):
            if feature_vector.ndim == 1:
                arr = feature_vector.reshape(1, -1)
            elif feature_vector.ndim == 2:
                arr = feature_vector
            else:
                raise ValueError(f"Unsupported ndarray dimension: {feature_vector.ndim}")
        else:
            raise TypeError(f"Unsupported feature type: {type(feature_vector)}")

        return self.predict_window(arr)

    def predict_batch(
        self, X: Union[np.ndarray, List[np.ndarray]]
    ) -> List[Dict[str, Any]]:
        """Batch prediction supporting both 2D (N, 77) and 3D (N, W, 77) inputs.

        Args:
            X: 2D array of shape (N, 77) or 3D array of shape (N, W, 77), or list of windows.

        Returns:
            List of prediction dictionaries.
        """
        if isinstance(X, list):
            return [
                self.predict_window(w) if np.asarray(w).ndim == 2 else self.predict_vector(w)
                for w in X
            ]

        if not isinstance(X, np.ndarray):
            X = np.asarray(X, dtype=np.float32)

        if X.ndim == 2:
            # (N, 77): treat each row as 1-step window
            return [self.predict_vector(X[i]) for i in range(len(X))]
        elif X.ndim == 3:
            # (N, W, 77): batch of sliding windows
            N, T, F = X.shape
            padded_windows = np.array([self._pad_window(X[i]) for i in range(N)], dtype=np.float32)
            sanitized = self._sanitize_features(padded_windows)
            tensor_in = torch.tensor(sanitized, dtype=torch.float32, device=self.device)

            self.model.eval()
            with torch.no_grad():
                logits = self.model(tensor_in)
                probs = torch.softmax(logits, dim=-1).cpu().numpy()

            results = []
            for i in range(N):
                pred_idx = int(np.argmax(probs[i]))
                pred_label = self.classes[pred_idx]
                results.append({
                    "label": pred_label,
                    "is_attack": (pred_label.lower() != "benign"),
                    "confidence": float(probs[i, pred_idx]),
                    "probabilities": {
                        self.classes[c]: float(probs[i, c])
                        for c in range(len(self.classes))
                        if c < probs.shape[1]
                    },
                })
            return results
        else:
            raise ValueError(f"predict_batch expects 2D or 3D array, got ndim={X.ndim}")

    def save(self, path: str) -> None:
        """Save SequenceClassifier weights and configuration bundle."""
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        checkpoint = {
            "model_state_dict": self.model.state_dict(),
            "config": {
                "num_features": self.model.num_features,
                "num_classes": self.model.num_classes,
                "hidden_size": self.model.hidden_size,
                "num_layers": self.model.num_layers,
                "dropout": self.model.dropout_rate,
            },
            "window_size": self.window_size,
            "classes": self.classes,
            "feature_names": self.feature_names,
            "scaler": self.scaler,
            "imputer": self.imputer,
            "caveat": self.CAVEAT,
        }
        torch.save(checkpoint, path)

    def load(self, path: str) -> None:
        """Load SequenceClassifier weights and configuration bundle."""
        checkpoint = torch.load(path, map_location=self.device, weights_only=False)
        cfg = checkpoint.get("config", {})

        self.window_size = int(checkpoint.get("window_size", 10))
        self.classes = list(checkpoint.get("classes", CICDDOS2019_CLASSES))
        self.feature_names = list(checkpoint.get("feature_names", CICFLOWMETER_FEATURE_NAMES))
        self.scaler = checkpoint.get("scaler", None)
        self.imputer = checkpoint.get("imputer", None)

        self.model = BiLSTMSequenceModel(
            num_features=cfg.get("num_features", len(self.feature_names)),
            num_classes=cfg.get("num_classes", len(self.classes)),
            hidden_size=cfg.get("hidden_size", 128),
            num_layers=cfg.get("num_layers", 2),
            dropout=cfg.get("dropout", 0.3),
        ).to(self.device)

        self.model.load_state_dict(checkpoint["model_state_dict"])
        self.model.eval()
