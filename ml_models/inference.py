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
    
    # Try to use APT detector for enhanced analysis
    try:
        from ml_models.apt_detector import APTDetector
        apt_detector = APTDetector()
        apt_indicators = apt_detector.analyze_packet_batch(flows)
        apt_risk_scores = apt_detector.get_host_risk_scores()
    except ImportError:
        apt_indicators = []
        apt_risk_scores = {}
    
    for f in flows:
        src_ip = f.get('src_ip', 'unknown')
        
        # Enhanced risk scoring with APT analysis
        base_risk = (hash(src_ip) % 100) / 100
        apt_risk = apt_risk_scores.get(src_ip, 0.0)
        
        # Combine APT risk with base heuristics
        risk_score = min((base_risk + apt_risk) / 2, 1.0)
        
        # Check if this flow has associated APT indicators
        flow_indicators = [ind for ind in apt_indicators 
                          if ind.source_ip == src_ip or ind.target_ip == f.get('dst_ip', '')]
        
        # Adjust risk based on APT indicators
        if flow_indicators:
            high_conf_indicators = [ind for ind in flow_indicators if ind.confidence > 0.8]
            if high_conf_indicators:
                risk_score = max(risk_score, 0.9)
            elif any(ind.severity == "HIGH" for ind in flow_indicators):
                risk_score = max(risk_score, 0.8)
            elif any(ind.severity == "MEDIUM" for ind in flow_indicators):
                risk_score = max(risk_score, 0.6)
        
        # Determine label based on enhanced risk score
        if risk_score > 0.8:
            label = "APT"
        elif risk_score > 0.5:
            label = "Suspicious"
        else:
            label = "Benign"
        
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
        
        # Combine ML predictions with APT analysis
        if preds:
            ml_avg = sum(preds) / len(preds)
            # Weight ML prediction with APT analysis
            combined_score = (risk_score * 0.6) + (ml_avg * 0.4)
            
            if combined_score >= 0.7:
                label = "APT"
            elif combined_score >= 0.4:
                label = "Suspicious"
            else:
                label = "Benign"
            risk_score = max(risk_score, combined_score)
        
        # Add APT-specific metadata
        apt_metadata = {
            "apt_indicators_count": len(flow_indicators),
            "high_confidence_indicators": len([ind for ind in flow_indicators if ind.confidence > 0.8]),
            "apt_risk_score": apt_risk,
            "indicator_types": list(set(ind.indicator_type for ind in flow_indicators))
        }
        
        rows.append({
            **f,
            "risk_score": round(risk_score, 3),
            "prediction": label,
            "models_used": ",".join(models.keys()) if isinstance(models, dict) else "",
            **apt_metadata
        })
    return pd.DataFrame(rows)
