"""Training orchestration with automatic preprocessing & metrics."""
from __future__ import annotations
from typing import Dict, Any, List
import json
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

from .preprocessing import load_dataset, auto_preprocess
try:  # Lazy optional deep import
    from .deep import train_sequence_model, train_gnn_model  # type: ignore
    _HAS_DEEP = True
except Exception:
    _HAS_DEEP = False


def _build_models(scale_pos_weight: float):
    return {
        "RandomForest": lambda: RandomForestClassifier(
            n_estimators=160,
            max_depth=None,
            n_jobs=-1,
            random_state=42,
            class_weight="balanced",
        ),
        "XGBoost": lambda: XGBClassifier(
            n_estimators=300,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.9,
            colsample_bytree=0.9,
            tree_method="hist",
            random_state=42,
            eval_metric="logloss",
            scale_pos_weight=scale_pos_weight if scale_pos_weight > 0 else 1.0,
        ),
        # Deep learning models handled separately (saved as .pt) but keys included for validation
        "LSTM": lambda: "__DEEP__",
        "GRU": lambda: "__DEEP__",
        "GNN": lambda: "__DEEP__",
    }


def _compute_scale_pos_weight(y) -> float:
    try:
        import numpy as np
        y_arr = np.array(y)
        pos = (y_arr == 1).sum()
        neg = (y_arr == 0).sum()
        if pos == 0:
            return 1.0
        return max(neg / pos, 1.0)
    except Exception:
        return 1.0


def train_models(config: Dict[str, Any]):
    """Automatic preprocessing + model training + metrics persistence.

    config keys:
      dataset_path: str
      models: List[str]
      output_dir: str
    """
    dataset_path = config.get("dataset_path")
    model_names: List[str] = config.get("models", ["RandomForest"])
    output_dir = Path(config.get("output_dir", "models"))
    output_dir.mkdir(parents=True, exist_ok=True)

    # Accept pre-supplied dataframe to avoid re-reading large CSV
    if "dataframe" in config and config["dataframe"] is not None:
        df = config["dataframe"]
    else:
        df = load_dataset(dataset_path)
    pipe = auto_preprocess(df, scaler_type="standard")
    if pipe["X_train"].empty:
        return {}
    X_train = pipe["X_train"]
    X_test = pipe["X_test"]
    y_train = pipe["y_train"]
    y_test = pipe["y_test"]
    scaler = pipe["artifacts"]["scaler"]
    feature_list = pipe["artifacts"]["feature_list"]
    smote_applied = pipe["artifacts"].get("smote_applied", False)

    scale_pos_weight = _compute_scale_pos_weight(y_train)
    models_def = _build_models(scale_pos_weight)

    metrics_summary = {}
    trained = {}
    for name in model_names:
        if name not in models_def:
            continue
        if name in {"LSTM", "GRU"}:  # Deep sequence
            if not _HAS_DEEP:
                metrics_summary[name] = {"error": "deep_stack_unavailable"}
                continue
            try:
                rnn_type = "lstm" if name == "LSTM" else "gru"
                seq_model, seq_metrics = train_sequence_model(X_train, y_train, epochs=3, rnn_type=rnn_type)
                # Simple probability threshold at 0.5 for test set
                import torch
                seq_model.eval()
                with torch.no_grad():
                    import pandas as pd
                    X_test_tensor = torch.tensor(X_test.values, dtype=torch.float32)
                    # Reuse train function's inference packaging (flatten by grouping) minimal: direct forward on single-step sequences
                    logits = seq_model.rnn(X_test_tensor.unsqueeze(1))[0][:, -1, :]
                    probs = torch.sigmoid(seq_model.head(logits).squeeze(-1))
                    preds = (probs >= 0.5).int().numpy()
                acc = accuracy_score(y_test, preds) if len(y_test) else 0.0
                precision, recall, f1, _ = precision_recall_fscore_support(y_test, preds, average="binary", zero_division=0)
                cm = confusion_matrix(y_test, preds).tolist() if len(y_test) else []
                metrics_summary[name] = {
                    "accuracy": acc,
                    "precision": precision,
                    "recall": recall,
                    "f1": f1,
                    "confusion_matrix": cm,
                    "scale_pos_weight": scale_pos_weight,
                    "n_train": len(y_train),
                    "n_test": len(y_test),
                    "smote_applied": smote_applied,
                    **seq_metrics,
                }
                import torch
                torch.save(seq_model.state_dict(), output_dir / f"{name}.pt")
                trained[name] = seq_model
            except Exception as e:  # pragma: no cover
                metrics_summary[name] = {"error": str(e)}
        elif name == "GNN":
            if not _HAS_DEEP:
                metrics_summary[name] = {"error": "deep_stack_unavailable"}
                continue
            try:
                gnn_model, gnn_metrics = train_gnn_model(X_train, y_train, epochs=3)
                # For evaluation produce dummy uniform predictions (placeholder)
                import numpy as np
                preds = np.zeros(len(y_test))
                metrics_summary[name] = {
                    "accuracy": 0.0,
                    "precision": 0.0,
                    "recall": 0.0,
                    "f1": 0.0,
                    "confusion_matrix": [],
                    "n_train": len(y_train),
                    "n_test": len(y_test),
                    **gnn_metrics,
                }
                import torch
                torch.save(getattr(gnn_model, 'state_dict', lambda: {})(), output_dir / f"{name}.pt")
                trained[name] = gnn_model
            except Exception as e:  # pragma: no cover
                metrics_summary[name] = {"error": str(e)}
        else:
            model = models_def[name]()
            model.fit(X_train, y_train)
            preds = model.predict(X_test)
            acc = accuracy_score(y_test, preds) if len(y_test) else 0.0
            precision, recall, f1, _ = precision_recall_fscore_support(y_test, preds, average="binary", zero_division=0)
            cm = confusion_matrix(y_test, preds).tolist() if len(y_test) else []
            metrics_summary[name] = {
                "accuracy": acc,
                "precision": precision,
                "recall": recall,
                "f1": f1,
                "confusion_matrix": cm,
                "scale_pos_weight": scale_pos_weight,
                "n_train": len(y_train),
                "n_test": len(y_test),
                "smote_applied": smote_applied,
            }
            joblib.dump(model, output_dir / f"{name}.joblib")
            trained[name] = model

    # Persist shared artifacts
    joblib.dump(scaler, output_dir / "scaler.joblib")
    with (output_dir / "features.json").open("w", encoding="utf-8") as f:
        json.dump({
            "numeric_features": feature_list,
            "metrics": metrics_summary,
            "smote_applied": smote_applied,
        }, f, indent=2)
    with (output_dir / "metrics.json").open("w", encoding="utf-8") as f:
        json.dump(metrics_summary, f, indent=2)
    return trained
