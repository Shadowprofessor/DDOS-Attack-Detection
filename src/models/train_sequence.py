# -*- coding: utf-8 -*-
"""
Training Pipeline for Sequence Classifier (BiLSTM).

CAVEAT / DATASET PROVENANCE NOTICE:
Trained on synthetic pseudo-temporal windows (same-class CSV rows grouped, not real
sequential flows). Advantage on genuine low-and-slow attacks is UNVERIFIED until
retrained on real packet-sequence data.

Features:
  - Ingests normalized flow datasets from dataset_registry (CICDDoS2019, InSDN, etc.)
  - Builds sliding pseudo-temporal windows of W consecutive snapshots per class
  - Applies tightened Slowloris proxy heuristic for targeted oversampling
  - Trains BiLSTMSequenceModel with AdamW and cosine annealing
  - Evaluates per-class metrics and outputs evaluation report
  - Checkpoints best model to models/sequence_classifier_best.pt
"""

import os
import sys
import copy
import json
import time
import argparse
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any

import numpy as np
import pandas as pd
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, accuracy_score, f1_score

PROJECT_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from src.features.flow_extractor import CICFLOWMETER_FEATURE_NAMES, NUM_FEATURES
from src.features.dataset_registry import (
    load_dataset,
    load_cicddos2019,
    load_insdn,
    load_ciciot2023,
    normalize_labels,
)
from src.models.classifier import CICDDOS2019_CLASSES
from src.models.sequence_classifier import (
    BiLSTMSequenceModel,
    SequenceClassifier,
    PSEUDO_TEMPORAL_CAVEAT,
)


class WindowDataset(Dataset):
    """PyTorch Dataset wrapping 3D window tensors (N, W, 77) and 1D label targets (N,)."""

    def __init__(self, X: np.ndarray, y: np.ndarray):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = torch.tensor(y, dtype=torch.long)

    def __len__(self) -> int:
        return len(self.X)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor]:
        return self.X[idx], self.y[idx]


# Strict allowlist of attack labels permitted for slowloris proxy oversampling.
# High-volume flood classes (TFTP, Syn, UDP, NTP, etc.) and Benign traffic are strictly excluded.
SLOWLORIS_PROXY_ALLOWLIST: Tuple[str, ...] = (
    "webddos",
    "slowloris",
    "goldeneye",
    "ddos-http_flood",
)


def is_slowloris_proxy(
    row: pd.Series,
    allowlist: Optional[Tuple[str, ...]] = None,
    require_slow_signature: bool = False,
) -> bool:
    """Tightened heuristic to detect slow-attack proxy flows with strict Label-level allowlist.

    Requires:
      1. Flow label MUST be in allowlist (defaults to WebDDoS / Slowloris / GoldenEye).
         High-volume flood traffic (e.g. TFTP, Syn, UDP, NTP) and Benign flows are strictly excluded.
      2. If require_slow_signature is True, additionally requires:
         Flow Duration > 1,000,000 us (1 second) and Flow Packets/s < 10.
    """
    target_allowlist = allowlist if allowlist is not None else SLOWLORIS_PROXY_ALLOWLIST
    lbl = str(row.get("Normalized_Label", row.get("Label", ""))).strip().lower()

    if lbl not in target_allowlist:
        return False

    if require_slow_signature:
        duration = float(row.get("Flow Duration", 0.0))
        rate = float(row.get("Flow Packets/s", 0.0))
        return (duration > 1e6) and (rate < 10.0)

    return True


def build_synthetic_windows(
    df: pd.DataFrame,
    window_size: int = 10,
    stride: int = 5,
    feature_cols: Optional[List[str]] = None,
) -> Tuple[np.ndarray, np.ndarray]:
    """Group rows by class and slide windows of length `window_size` across each group.

    Args:
        df: DataFrame with feature columns and 'Normalized_Label'.
        window_size: Number of timesteps per window (W).
        stride: Stride between successive sliding windows.
        feature_cols: Ordered list of feature names.

    Returns:
        X: 3D array of shape (N_windows, window_size, len(feature_cols))
        y: 1D array of class strings of shape (N_windows,)
    """
    if feature_cols is None:
        feature_cols = list(CICFLOWMETER_FEATURE_NAMES)

    X_windows = []
    y_labels = []

    for label, group in df.groupby("Normalized_Label"):
        vals = group[feature_cols].values
        n_rows = len(vals)
        if n_rows < window_size:
            # Pad short class to at least 1 window
            pad = np.zeros((window_size - n_rows, len(feature_cols)), dtype=np.float32)
            w = np.vstack([pad, vals])
            X_windows.append(w)
            y_labels.append(label)
        else:
            for start in range(0, n_rows - window_size + 1, stride):
                w = vals[start : start + window_size]
                X_windows.append(w)
                y_labels.append(label)

    return np.array(X_windows, dtype=np.float32), np.array(y_labels)


def oversample_slow_attacks(
    X_windows: np.ndarray,
    y_labels: np.ndarray,
    target_classes: Tuple[str, ...] = ("WebDDoS",),
    multiplier: int = 5,
) -> Tuple[np.ndarray, np.ndarray]:
    """Oversample minority slow attack windows by repeating with slight Gaussian jitter."""
    extra_X = []
    extra_y = []

    for i in range(len(y_labels)):
        if y_labels[i] in target_classes:
            for _ in range(multiplier):
                noise = np.random.normal(0, 0.01, size=X_windows[i].shape).astype(np.float32)
                extra_X.append(X_windows[i] + noise)
                extra_y.append(y_labels[i])

    if extra_X:
        X_all = np.concatenate([X_windows, np.array(extra_X, dtype=np.float32)], axis=0)
        y_all = np.concatenate([y_labels, np.array(extra_y)], axis=0)
        return X_all, y_all

    return X_windows, y_labels


def train_sequence_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
    classes: List[str],
    epochs: int = 20,
    batch_size: int = 64,
    lr: float = 1e-3,
    hidden_size: int = 128,
    num_layers: int = 2,
    dropout: float = 0.3,
    device: Optional[str] = None,
) -> Tuple[BiLSTMSequenceModel, Dict[str, Any]]:
    """Train BiLSTM sequence classifier."""
    dev = torch.device(device if device else ("cuda" if torch.cuda.is_available() else "cpu"))

    num_features = X_train.shape[-1]
    num_classes = len(classes)

    model = BiLSTMSequenceModel(
        num_features=num_features,
        num_classes=num_classes,
        hidden_size=hidden_size,
        num_layers=num_layers,
        dropout=dropout,
    ).to(dev)

    train_ds = WindowDataset(X_train, y_train)
    val_ds = WindowDataset(X_val, y_val)

    train_loader = DataLoader(train_ds, batch_size=batch_size, shuffle=True)
    val_loader = DataLoader(val_ds, batch_size=batch_size, shuffle=False)

    criterion = nn.CrossEntropyLoss()
    optimizer = torch.optim.AdamW(model.parameters(), lr=lr, weight_decay=1e-4)

    best_val_loss = float("inf")
    best_weights = copy.deepcopy(model.state_dict())
    history = {"train_loss": [], "val_loss": [], "val_acc": []}

    for epoch in range(epochs):
        model.train()
        total_loss = 0.0
        for batch_X, batch_y in train_loader:
            batch_X, batch_y = batch_X.to(dev), batch_y.to(dev)
            optimizer.zero_grad()
            logits = model(batch_X)
            loss = criterion(logits, batch_y)
            loss.backward()
            optimizer.step()
            total_loss += loss.item() * len(batch_y)

        train_loss = total_loss / len(train_ds)

        model.eval()
        val_loss = 0.0
        correct = 0
        with torch.no_grad():
            for batch_X, batch_y in val_loader:
                batch_X, batch_y = batch_X.to(dev), batch_y.to(dev)
                logits = model(batch_X)
                loss = criterion(logits, batch_y)
                val_loss += loss.item() * len(batch_y)
                preds = torch.argmax(logits, dim=-1)
                correct += (preds == batch_y).sum().item()

        val_loss /= len(val_ds)
        val_acc = correct / len(val_ds)

        history["train_loss"].append(train_loss)
        history["val_loss"].append(val_loss)
        history["val_acc"].append(val_acc)

        if val_loss < best_val_loss:
            best_val_loss = val_loss
            best_weights = copy.deepcopy(model.state_dict())

    model.load_state_dict(best_weights)
    return model, history


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sequence Classifier (BiLSTM) Training Pipeline")
    parser.add_argument("--data-dir", default="Codes/ml/datasets", help="Data directory")
    parser.add_argument("--output-dir", default="models", help="Output directory for checkpoints")
    parser.add_argument("--window-size", type=int, default=10, help="Sliding window size (timesteps)")
    parser.add_argument("--epochs", type=int, default=15, help="Training epochs")
    parser.add_argument("--batch-size", type=int, default=64, help="Batch size")
    args = parser.parse_args()

    print("[*] Sequence Classifier Training Pipeline")
    print(f"[*] Caveat notice:\n    {PSEUDO_TEMPORAL_CAVEAT}")
