"""Inference utilities (placeholder implementations)."""
from __future__ import annotations
from typing import List, Dict, Any
from pathlib import Path
import pandas as pd
import joblib
import json
try:  # Optional torch
    import torch  # type: ignore
    _HAS_TORCH = True
except Exception:  # pragma: no cover
    _HAS_TORCH = False
    class _Dummy:
        def __getattr__(self, item):
            raise RuntimeError("Torch not available")
    torch = _Dummy()  # type: ignore
try:  # Deep components optional
    from .deep import SequenceModel, SequenceConfig  # type: ignore
    _HAS_DEEP = True
except Exception:
    _HAS_DEEP = False


def load_models(model_names: List[str], models_dir: str = "models"):
    loaded = {}
    base = Path(models_dir)
    feature_meta: Dict[str, Any] = {}
    feat_file = base / "features.json"
    if feat_file.exists():
        try:
            feature_meta = json.loads(feat_file.read_text())
        except Exception:
            feature_meta = {}
    for m in model_names:
        joblib_path = base / f"{m}.joblib"
        pt_path = base / f"{m}.pt"
        if joblib_path.exists():
            try:
                loaded[m] = joblib.load(joblib_path)
                continue
            except Exception:
                loaded[m] = f"{m}_failed_to_load"
        if pt_path.exists():  # deep model
            try:
                input_dim = len(feature_meta.get("numeric_features", []))
                if _HAS_DEEP and m in {"LSTM", "GRU"} and input_dim > 0:
                    cfg = SequenceConfig(input_dim=input_dim, rnn_type=m.lower())
                    seq_model = SequenceModel(cfg)
                    state = torch.load(pt_path, map_location="cpu")
                    seq_model.load_state_dict(state, strict=False)
                    loaded[m] = seq_model
                else:
                    loaded[m] = torch.load(pt_path, map_location="cpu")
            except Exception as e:  # pragma: no cover
                loaded[m] = f"{m}_failed_to_load:{e}";
        if m not in loaded:
            loaded[m] = f"{m}_placeholder"
    scaler_path = base / "scaler.joblib"
    scaler = joblib.load(scaler_path) if scaler_path.exists() else None
    return {"models": loaded, "scaler": scaler, "meta": feature_meta}


def _numeric_features(flow: Dict[str, Any]):
    return {
        k: v for k, v in flow.items() if isinstance(v, (int, float)) and k not in {"prediction", "risk_score"}
    }


def _align_features(vec_df: pd.DataFrame, feature_meta: Dict[str, Any]) -> pd.DataFrame:
    """Align dataframe columns with training numeric feature set if available."""
    train_feats = feature_meta.get("numeric_features") or feature_meta.get("feature_list")
    if not train_feats:
        return vec_df
    # Add any missing columns as 0
    for col in train_feats:
        if col not in vec_df.columns:
            vec_df[col] = 0
    # Restrict order
    return vec_df[train_feats]


def predict_flows(model_bundle: Dict[str, Any], flows: List[Dict[str, Any]]):
    models = model_bundle.get("models", {}) if isinstance(model_bundle, dict) else model_bundle
    scaler = model_bundle.get("scaler") if isinstance(model_bundle, dict) else None
    feature_meta = model_bundle.get("meta", {}) if isinstance(model_bundle, dict) else {}
    rows = []
    for f in flows:
        # Baseline heuristic risk score
        risk_score = (hash(f.get('src_ip', '0')) % 100) / 100
        label = "APT" if risk_score > 0.7 else ("Suspicious" if risk_score > 0.4 else "Benign")
        # If real ML model(s) available, attempt numeric prediction majority vote / prob average
        prob_accum = []
        numeric_vector = _numeric_features(f)
        if models and numeric_vector:
            vec_df = pd.DataFrame([numeric_vector])
            vec_df = _align_features(vec_df, feature_meta)
            if scaler is not None:
                try:
                    vec_df[vec_df.columns] = scaler.transform(vec_df[vec_df.columns])
                except Exception:
                    pass
            for name, model in models.items():
                try:
                    if hasattr(model, 'predict_proba'):
                        proba = model.predict_proba(vec_df.select_dtypes(include=['number']))[0][1]
                        prob_accum.append(float(proba))
                    elif hasattr(model, 'predict') and name not in {"LSTM", "GRU", "GNN"}:
                        pred = model.predict(vec_df.select_dtypes(include=['number']))
                        prob_accum.append(float(pred[0]))
                    elif _HAS_DEEP and name in {"LSTM", "GRU"} and isinstance(model, SequenceModel):
                        model.eval()
                        with torch.no_grad():
                            x = torch.tensor(vec_df.select_dtypes(include=['number']).values, dtype=torch.float32)
                            # Add time dimension (1,1,F)
                            logits = model.rnn(x.unsqueeze(1))[0][:, -1, :]
                            p = torch.sigmoid(model.head(logits)).item()
                            prob_accum.append(float(p))
                    # GNN placeholder: treat as neutral 0.5 if loaded
                    elif name == "GNN" and model not in {f"GNN_placeholder"}:
                        prob_accum.append(0.5)
                except Exception:
                    continue
        if prob_accum:
            avg = sum(prob_accum) / len(prob_accum)
            if avg >= 0.7:
                label = "APT"
            elif avg >= 0.4:
                label = "Suspicious"
            else:
                label = "Benign"
            risk_score = max(risk_score, avg)
        rows.append({**f, "risk_score": round(risk_score, 3), "prediction": label, "models_used": ",".join(models.keys())})
    return pd.DataFrame(rows)
