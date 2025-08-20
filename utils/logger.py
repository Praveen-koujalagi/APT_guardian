"""Logging & MongoDB stub utilities."""
from __future__ import annotations
from typing import List, Dict, Any
import pandas as pd


def get_mongo_client():  # placeholder
    return {"mongo": "connected"}


def fetch_recent_alerts(limit: int = 10):
    rows: List[Dict[str, Any]] = []
    for i in range(limit):
        rows.append({
            "timestamp": f"2025-01-01T00:00:{i:02d}Z",
            "src_ip": f"10.0.0.{i+1}",
            "dst_ip": f"192.168.1.{(i*3)%255}",
            "severity": "High" if i % 4 == 0 else "Medium",
            "prediction": "APT" if i % 5 == 0 else "Suspicious"
        })
    return pd.DataFrame(rows)
