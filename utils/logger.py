"""Logging & MongoDB stub utilities."""
from __future__ import annotations
from typing import List, Dict, Any
import pandas as pd
import logging
from blockchain.blockchain_utils import log_event_to_blockchain

def setup_logger(name: str = "APT_Guardian", level: int = logging.INFO):
    """Set up a logger for the application."""
    logger = logging.getLogger(name)
    
    # Avoid adding multiple handlers if logger already exists
    if logger.handlers:
        return logger
    
    logger.setLevel(level)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(console_handler)
    
    return logger

def log_security_event(src_ip: str, dst_ip: str, severity: str, details: str):
    """
    Log a security event to the blockchain and (optionally) to other log sinks.
    """
    # Log to blockchain
    log_event_to_blockchain(src_ip, dst_ip, severity, details)
    # You can also add local logging here if needed
    print(f"[SECURITY EVENT] src_ip={src_ip}, dst_ip={dst_ip}, severity={severity}, details={details}")


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
