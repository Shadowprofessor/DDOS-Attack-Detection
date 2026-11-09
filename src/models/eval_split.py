# -*- coding: utf-8 -*-
"""
Leakage-safe train/test splitting for DDoS flow datasets.

Stratified-random splits leak information when:
  - the same synthetic capture/day appears in both train and test (capture leakage), or
  - future flows are used to predict past ones (temporal leakage).

This module provides a by-capture (group) split and a chronological (time) split,
each with an explicit zero-overlap guarantee, plus a combined helper. Use these
instead of `train_test_split(..., stratify=y)` for honest evaluation.
"""
from typing import Optional, Tuple

import numpy as np


def group_split(groups, test_frac: float = 0.2, random_state: int = 42) -> Tuple[np.ndarray, np.ndarray]:
    """Split row indices so that NO group (capture/source id) spans train and test."""
    groups = np.asarray(groups)
    unique = np.unique(groups)
    if len(unique) < 2:
        raise ValueError("group_split needs >= 2 distinct groups to avoid overlap.")
    rng = np.random.default_rng(random_state)
    shuffled = unique.copy()
    rng.shuffle(shuffled)
    n_test = max(1, min(len(unique) - 1, int(round(len(unique) * test_frac))))
    test_groups = set(shuffled[:n_test].tolist())
    test_mask = np.array([g in test_groups for g in groups])
    return np.where(~test_mask)[0], np.where(test_mask)[0]


def time_split(timestamps, test_frac: float = 0.2) -> Tuple[np.ndarray, np.ndarray]:
    """Chronological split: earliest (1 - test_frac) to train, latest test_frac to test."""
    ts = np.asarray(timestamps, dtype=np.float64)
    order = np.argsort(ts, kind="mergesort")
    n_test = max(1, int(round(len(ts) * test_frac)))
    return order[:-n_test], order[-n_test:]


def leakage_safe_split(groups=None, timestamps=None, test_frac: float = 0.2,
                       random_state: int = 42) -> Tuple[np.ndarray, np.ndarray]:
    """Prefer by-capture group split; else chronological; else raise."""
    if groups is not None:
        return group_split(groups, test_frac, random_state)
    if timestamps is not None:
        return time_split(timestamps, test_frac)
    raise ValueError("leakage_safe_split requires `groups` or `timestamps`.")


def assert_no_group_overlap(groups, train_idx, test_idx) -> bool:
    """Raise if any group appears in both splits. Returns True when clean."""
    g = np.asarray(groups)
    overlap = set(g[train_idx].tolist()) & set(g[test_idx].tolist())
    if overlap:
        raise AssertionError(f"Group leakage: {sorted(str(x) for x in overlap)[:5]} in both splits.")
    return True
