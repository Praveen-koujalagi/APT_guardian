"""Real blockchain logging utilities for APT Guardian."""
from __future__ import annotations
from typing import List, Dict, Any, Optional
import pandas as pd
import json
import time
from datetime import datetime
import hashlib
import os

print("Script for blockchain utilities loaded.")

# Simple blockchain simulation for local storage
class LocalBlockchain:
    def __init__(self, storage_path: str = "blockchain_data.json"):
        self.storage_path = storage_path
        self.chain = self._load_chain()
        
    def _load_chain(self) -> List[Dict[str, Any]]:
        """Load existing blockchain data from file."""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                pass
        return []
    
    def _save_chain(self):
        """Save blockchain data to file."""
        with open(self.storage_path, 'w') as f:
            json.dump(self.chain, f, indent=2)
    
    def add_block(self, data: Dict[str, Any]) -> str:
        """Add a new block to the blockchain."""
        timestamp = int(time.time())
        block_id = len(self.chain)
        
        # Create block hash
        block_data = {
            "id": block_id,
            "timestamp": timestamp,
            "data": data,
            "previous_hash": self.chain[-1]["hash"] if self.chain else "0"
        }
        
        # Calculate hash
        block_string = json.dumps(block_data, sort_keys=True)
        block_hash = hashlib.sha256(block_string.encode()).hexdigest()
        block_data["hash"] = block_hash
        
        self.chain.append(block_data)
        self._save_chain()
        
        return block_hash
    
    def get_recent_blocks(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get recent blocks from the chain."""
        return self.chain[-limit:] if self.chain else []
    
    def get_block_count(self) -> int:
        """Get total number of blocks."""
        return len(self.chain)

# Global blockchain instance
_blockchain = LocalBlockchain()

def get_blockchain_client(auto_connect: bool = True):
    """Get blockchain client status."""
    return {
        "provider": "Local Blockchain Storage", 
        "status": "connected" if auto_connect else "disconnected",
        "block_count": _blockchain.get_block_count()
    }

def fetch_recent_events(limit: int = 10) -> pd.DataFrame:
    """Fetch recent security events from blockchain."""
    blocks = _blockchain.get_recent_blocks(limit)
    rows = []
    
    for block in blocks:
        data = block.get("data", {})
        rows.append({
            "block": block["id"],
            "tx_hash": block["hash"][:16] + "...",
            "timestamp": datetime.fromtimestamp(block["timestamp"]).isoformat(),
            "severity": data.get("severity", "Unknown"),
            "details": data.get("details", "No details"),
            "src_ip": data.get("src_ip", "N/A"),
            "dst_ip": data.get("dst_ip", "N/A"),
            "event_type": data.get("event_type", "Security Event")
        })
    
    return pd.DataFrame(rows)

def log_event_to_blockchain(src_ip: str, dst_ip: str, severity: str, details: str, 
                          event_type: str = "Security Event", **kwargs) -> bool:
    """Log a security event to the blockchain."""
    try:
        event_data = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "severity": severity,
            "details": details,
            "event_type": event_type,
            "logged_at": datetime.now().isoformat(),
            **kwargs  # Additional metadata
        }
        
        block_hash = _blockchain.add_block(event_data)
        print(f"[BLOCKCHAIN LOG] Event logged to block {_blockchain.get_block_count()-1} (hash: {block_hash[:16]}...)")
        print(f"  Event: {event_type} | {severity} | {src_ip} -> {dst_ip}")
        print(f"  Details: {details}")
        
        return True
    except Exception as e:
        print(f"[BLOCKCHAIN ERROR] Failed to log event: {e}")
        return False

def log_packet_to_blockchain(packet_info: Dict[str, Any]) -> bool:
    """Log a captured packet to blockchain for security auditing."""
    try:
        # Extract key packet information
        src_ip = packet_info.get('src_ip', 'Unknown')
        dst_ip = packet_info.get('dst_ip', 'Unknown')
        protocol = packet_info.get('protocol', 'Unknown')
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        packet_size = packet_info.get('size', 0)
        
        # Determine severity based on packet characteristics
        severity = "Low"
        details = f"Packet capture: {protocol} {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({packet_size} bytes)"
        
        # Check for suspicious characteristics
        suspicious_ports = [22, 23, 135, 139, 445, 1433, 3389, 5900]
        if dst_port in suspicious_ports or src_port in suspicious_ports:
            severity = "Medium"
            details += f" [Suspicious port: {dst_port}]"
        
        # Check for large packets (potential data exfiltration)
        if packet_size > 1400:
            severity = "Medium"
            details += f" [Large packet: {packet_size} bytes]"
        
        return log_event_to_blockchain(
            src_ip=src_ip,
            dst_ip=dst_ip,
            severity=severity,
            details=details,
            event_type="Packet Capture",
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            packet_size=packet_size
        )
    except Exception as e:
        print(f"[BLOCKCHAIN ERROR] Failed to log packet: {e}")
        return False

def log_apt_indicator_to_blockchain(indicator) -> bool:
    """Log an APT indicator to blockchain."""
    try:
        return log_event_to_blockchain(
            src_ip=indicator.source_ip,
            dst_ip=indicator.target_ip,
            severity=indicator.severity,
            details=f"APT Indicator: {indicator.description}",
            event_type="APT Detection",
            indicator_type=indicator.indicator_type,
            confidence=indicator.confidence,
            timestamp=indicator.timestamp
        )
    except Exception as e:
        print(f"[BLOCKCHAIN ERROR] Failed to log APT indicator: {e}")
        return False

if __name__ == "__main__":
    # Simulate a security attack event
    log_event_to_blockchain(
        src_ip="203.0.113.5",
        dst_ip="192.168.1.100",
        severity="Critical",
        details="Simulated attack: Port scan detected from external IP",
        event_type="Security Event"
    )