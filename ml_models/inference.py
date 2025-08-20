"""Inference utilities (placeholder implementations)."""
from __future__ import annotations
from typing import List, Dict, Any
from pathlib import Path
import pandas as pd
import joblib


def load_models(model_names: List[str], models_dir: str = "models"):
    loaded = {}
    base = Path(models_dir)
    for m in model_names:
        file = base / f"{m}.joblib"
        if file.exists():
            try:
                loaded[m] = joblib.load(file)
            except Exception:
                loaded[m] = f"{m}_failed_to_load"
        else:
            loaded[m] = f"{m}_placeholder"
    scaler_path = base / "scaler.joblib"
    scaler = joblib.load(scaler_path) if scaler_path.exists() else None
    return {"models": loaded, "scaler": scaler}


def _numeric_features(flow: Dict[str, Any]):
    return {
        k: v for k, v in flow.items() if isinstance(v, (int, float)) and k not in {"prediction", "risk_score"}
    }


def predict_flows(model_bundle: Dict[str, Any], flows: List[Dict[str, Any]]):
    models = model_bundle.get("models", {}) if isinstance(model_bundle, dict) else model_bundle
    scaler = model_bundle.get("scaler") if isinstance(model_bundle, dict) else None
    rows = []
    for f in flows:
        # Baseline heuristic risk score
        risk_score = (hash(f['src_ip']) % 100) / 100
        label = "APT" if risk_score > 0.7 else ("Suspicious" if risk_score > 0.4 else "Benign")
        # If real ML model(s) available, attempt numeric prediction majority vote
        preds = []
        numeric_vector = _numeric_features(f)
        if models:
            import numpy as np
            if numeric_vector:
                import pandas as pd
                vec_df = pd.DataFrame([numeric_vector])
                if scaler is not None:
                    try:
                        vec_df[numeric_vector.keys()] = scaler.transform(vec_df[numeric_vector.keys()])
                    except Exception:
                        pass
                for name, model in models.items():
                    if hasattr(model, "predict"):
                        try:
                            p = model.predict(vec_df.select_dtypes(include=["number"]))
                            preds.append(int(p[0]))
                        except Exception:
                            continue
        if preds:
            avg = sum(preds) / len(preds)
            # Map numeric to label override
            if avg >= 0.7:
                label = "APT"
            elif avg >= 0.4:
                label = "Suspicious"
            else:
                label = "Benign"
            risk_score = max(risk_score, avg)
        rows.append({
            **f,
            "risk_score": round(risk_score, 3),
            "prediction": label,
            "models_used": ",".join(models.keys()) if isinstance(models, dict) else ""
        })
    return pd.DataFrame(rows)
