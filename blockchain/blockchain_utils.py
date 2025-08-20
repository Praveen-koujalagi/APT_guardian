"""Blockchain helper stubs."""
from __future__ import annotations
from typing import List, Dict, Any
import pandas as pd


def get_blockchain_client(auto_connect: bool = True):  # placeholder
    return {"provider": "http://localhost:8545", "status": "connected" if auto_connect else "disconnected"}


def fetch_recent_events(limit: int = 10):
    rows = []
    for i in range(limit):
        rows.append({
            "block": 100 + i,
            "tx_hash": f"0xhash{i:02d}",
            "timestamp": "2025-01-01T00:00:00Z",
            "severity": "High" if i % 3 == 0 else "Low",
            "details": "Placeholder event"
        })
    return pd.DataFrame(rows)
