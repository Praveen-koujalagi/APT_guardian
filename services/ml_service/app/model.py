"""Model abstraction layer.

The initial MVP used a single inline IsolationForest. This refactor introduces
an extensible interface so we can later plug in a graph-based GNN model without
changing the FastAPI ingestion contract.

Key ideas:
 - BaseAnomalyModel defines the methods the service expects.
 - IsolationForestModel keeps prior behaviour (pre-training on synthetic data).
 - GNNModel placeholder (will use torch / torch-geometric in Milestone M2).
 - Simple in-memory metrics registry for quick /model/info endpoint plus
   persistent metric writes handled in main background task.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest

# ------------------------- Metrics & Utilities ----------------------------- #

@dataclass
class ModelMetrics:
    model_name: str
    version: str
    trained_at: float
    train_samples: int
    notes: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)


# ---------------------------- Base Interface ------------------------------- #

class BaseAnomalyModel:
    name: str = "base"

    def __init__(self, threshold: float = 0.65):
        self.threshold = threshold
        self.metrics: ModelMetrics | None = None
        self._lock = threading.RLock()

    # --- public API expected by service ---
    def score_event(self, evt: dict) -> float:  # pragma: no cover - interface
        raise NotImplementedError

    def is_anomalous(self, evt: dict) -> Tuple[bool, float]:
        score = self.score_event(evt)
        return score >= self.threshold, score

    def fit(self, events: List[dict]) -> ModelMetrics:  # pragma: no cover
        """(Re)train the model on a batch of events.

        events: list of event dicts (same schema as /ingest).
        Returns metrics snapshot.
        """
        raise NotImplementedError

    # Utility used by main service to produce model info payload
    def info(self) -> Dict[str, Any]:
        m = self.metrics
        return {
            "name": self.name,
            "threshold": self.threshold,
            "trained": bool(m),
            "metrics": None if not m else {
                "trained_at": m.trained_at,
                "train_samples": m.train_samples,
                "version": m.version,
                "notes": m.notes,
                "extra": m.extra,
            },
        }


# ------------------------- Isolation Forest Model ------------------------- #

class IsolationForestModel(BaseAnomalyModel):
    name = "isolation_forest"

    def __init__(self, seed: int = 42, threshold: float = 0.65):
        super().__init__(threshold=threshold)
        self.model = IsolationForest(
            n_estimators=150, contamination=0.05, random_state=seed
        )
        # Initial synthetic normal pre-training replicating previous behaviour
        self._pretrain(seed)

    # Feature extraction kept identical to preserve score distribution
    def _features(self, evt: dict) -> np.ndarray:
        return np.array([
            [
                float(evt.get("bytes", 0)),
                float(evt.get("duration", 0.05)),
                float(evt.get("dport", 0)),
                float(evt.get("sport", 0)),
            ]
        ])

    def _pretrain(self, seed: int):
        rng = np.random.default_rng(seed)
        normal = np.column_stack(
            [
                rng.normal(5000, 1500, 4000).clip(50, 50000),
                rng.exponential(0.3, 4000).clip(0.001, 10.0),
                rng.integers(1000, 9000, 4000),
                rng.integers(1000, 65000, 4000),
            ]
        )
        self.model.fit(normal)
        self.metrics = ModelMetrics(
            model_name=self.name,
            version="0.1.0",
            trained_at=time.time(),
            train_samples=normal.shape[0],
            notes="synthetic pretrain",
        )

    def fit(self, events: List[dict]) -> ModelMetrics:
        with self._lock:
            if not events:
                return self.metrics or ModelMetrics(
                    model_name=self.name,
                    version="0.1.0",
                    trained_at=time.time(),
                    train_samples=0,
                    notes="no-op (no events)",
                )
            X = np.vstack([self._features(e) for e in events])
            self.model.fit(X)
            self.metrics = ModelMetrics(
                model_name=self.name,
                version="0.1.1",  # bump when we retrain
                trained_at=time.time(),
                train_samples=len(events),
                notes="retrain from batch",
                extra={"n_estimators": len(self.model.estimators_)}
            )
            return self.metrics

    def score_event(self, evt: dict) -> float:
        with self._lock:
            f = self._features(evt)
            # IsolationForest: higher = more normal; invert & squash to [0,1]
            s = -self.model.score_samples(f)[0]
            return 1.0 - np.exp(-s)


# ----------------------------- GNN Placeholder ----------------------------- #

class GNNModel(BaseAnomalyModel):  # pragma: no cover - future work
    name = "gnn_placeholder"

    def __init__(self, threshold: float = 0.65):
        super().__init__(threshold=threshold)
        # Real implementation will initialize torch modules here.

    def fit(self, events: List[dict]) -> ModelMetrics:
        # Placeholder: just records metadata; real training in M2.
        self.metrics = ModelMetrics(
            model_name=self.name,
            version="0.0.0",
            trained_at=time.time(),
            train_samples=len(events),
            notes="placeholder (no training)",
        )
        return self.metrics

    def score_event(self, evt: dict) -> float:
        # Random-ish stable hash-based pseudo score so interface works.
        h = hash((evt.get("src"), evt.get("dst"), evt.get("bytes", 0))) & 0xFFFF
        return (h % 1000) / 1000.0  # deterministic pseudo score


# ------------------------- Factory / Convenience --------------------------- #

def build_model(kind: str | None, threshold: float) -> BaseAnomalyModel:
    kind = (kind or "iforest").lower()
    if kind in {"iforest", "isolation_forest", "iso"}:
        return IsolationForestModel(threshold=threshold)
    if kind in {"gnn", "graph"}:
        return GNNModel(threshold=threshold)
    raise ValueError(f"Unknown model kind: {kind}")

