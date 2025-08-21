"""Model/data drift detection utilities.

Provides:
 - compute_psi(reference, observed)
 - detect_drift(feature_stats, current_batch_df) -> dict with per-feature PSI & flag

Population Stability Index (PSI) bins numeric features into quantiles over the
reference (training) distribution then compares bucket occupancy.
"""
from __future__ import annotations
from typing import Dict, Any
import numpy as np
import pandas as pd


def compute_psi(expected: np.ndarray, actual: np.ndarray, bins: int = 10) -> float:
    if len(expected) == 0 or len(actual) == 0:
        return 0.0
    # Remove NaNs
    expected = expected[~np.isnan(expected)]
    actual = actual[~np.isnan(actual)]
    if len(expected) == 0 or len(actual) == 0:
        return 0.0
    quantiles = np.linspace(0, 1, bins + 1)
    cuts = np.unique(np.quantile(expected, quantiles))
    if len(cuts) <= 2:  # low variance
        return 0.0
    expected_counts, _ = np.histogram(expected, bins=cuts)
    actual_counts, _ = np.histogram(actual, bins=cuts)
    # Convert to proportions adding small epsilon
    eps = 1e-6
    expected_prop = (expected_counts + eps) / (expected_counts.sum() + eps * len(expected_counts))
    actual_prop = (actual_counts + eps) / (actual_counts.sum() + eps * len(actual_counts))
    psi = np.sum((actual_prop - expected_prop) * np.log(actual_prop / expected_prop))
    return float(psi)


def detect_drift(feature_stats: Dict[str, Any], current: pd.DataFrame, psi_threshold: float = 0.2) -> Dict[str, Any]:
    report = {}
    for feat, stats in feature_stats.items():
        if feat not in current.columns:
            continue
        # We reconstruct a synthetic reference distribution using mean/std assuming normal
        mean = stats.get('mean', 0.0)
        std = stats.get('std', 1.0) or 1.0
        ref = np.random.normal(mean, std, size=min(len(current), 500))  # synthetic
        psi = compute_psi(ref, current[feat].astype(float).values)
        report[feat] = {"psi": psi, "drift": psi > psi_threshold}
    report['summary'] = {
        'drifted_features': [f for f, v in report.items() if isinstance(v, dict) and v.get('drift')],
        'total_checked': sum(1 for f in report.keys() if f != 'summary')
    }
    return report
