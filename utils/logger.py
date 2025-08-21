"""Logging & MongoDB utilities (graceful fallback if Mongo unreachable)."""
from __future__ import annotations
from typing import List, Dict, Any, Optional
import pandas as pd
import time

try:  # pragma: no cover optional
    from pymongo import MongoClient
    _HAS_MONGO = True
except Exception:
    _HAS_MONGO = False

_ALERT_BUFFER: List[Dict[str, Any]] = []


def get_mongo_client(uri: str = "mongodb://localhost:27017", db_name: str = "apt_guardian"):
    if not _HAS_MONGO:
        return {"stub": True, "uri": uri}
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=2000)
        client.server_info()  # trigger connection
        return {"stub": False, "client": client, "db": client[db_name]}
    except Exception as e:  # pragma: no cover
        return {"stub": True, "uri": uri, "error": str(e)}


def log_alert(mongo, alert: Dict[str, Any]):
    alert = dict(alert)
    alert.setdefault('timestamp', int(time.time()))
    if not mongo or mongo.get('stub'):
        _ALERT_BUFFER.append(alert)
        return True
    try:  # pragma: no cover
        mongo['db']['alerts'].insert_one(alert)
        return True
    except Exception:
        _ALERT_BUFFER.append(alert)
        return False


def fetch_recent_alerts(limit: int = 10):
    if _ALERT_BUFFER:
        return pd.DataFrame(list(reversed(_ALERT_BUFFER[-limit:])))
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


def query_alerts(mongo, severity: Optional[str] = None, limit: int = 100, last_minutes: Optional[int] = None) -> pd.DataFrame:
    """Query alerts from MongoDB (or in-memory) with optional filters.

    Parameters:
        mongo: mongo handle from get_mongo_client
        severity: filter severity level
        limit: max results
        last_minutes: restrict to recent time window
    """
    now = int(time.time())
    if not mongo or mongo.get('stub'):
        df = fetch_recent_alerts(limit=limit)
        if severity and not df.empty:
            df = df[df['severity'] == severity]
        return df
    query: Dict[str, Any] = {}
    if severity:
        query['severity'] = severity
    if last_minutes:
        query['timestamp'] = {"$gte": now - last_minutes * 60}
    try:  # pragma: no cover
        cur = mongo['db']['alerts'].find(query).sort('timestamp', -1).limit(limit)
        data = list(cur)
        if not data:
            return pd.DataFrame()
        for d in data:
            d.pop('_id', None)
        return pd.DataFrame(data)
    except Exception:
        return pd.DataFrame()
