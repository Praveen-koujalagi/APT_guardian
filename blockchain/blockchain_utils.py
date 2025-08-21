"""Blockchain helper utilities for IncidentLog contract.

Gracefully degrades to stub mode if web3 / compiler unavailable.
"""
from __future__ import annotations
from typing import Dict, Any, List, Optional
import json
from pathlib import Path
import time
import pandas as pd

try:  # pragma: no cover - blockchain optional in tests
    from web3 import Web3
    from solcx import compile_source, install_solc
    _HAS_WEB3 = True
except Exception:
    _HAS_WEB3 = False

_STUB_EVENTS: List[Dict[str, Any]] = []


def get_blockchain_client(auto_connect: bool = True, provider: str = "http://127.0.0.1:8545"):
    if not _HAS_WEB3 or not auto_connect:
        return {"stub": True, "provider": provider}
    try:
        w3 = Web3(Web3.HTTPProvider(provider))
        if not w3.is_connected():  # type: ignore
            return {"stub": True, "provider": provider, "error": "not_connected"}
        return {"stub": False, "w3": w3, "provider": provider}
    except Exception as e:  # pragma: no cover
        return {"stub": True, "provider": provider, "error": str(e)}


def _compile_contract(source_path: str) -> Dict[str, Any]:  # pragma: no cover
    source = Path(source_path).read_text()
    try:
        install_solc('0.8.20')
    except Exception:
        pass
    compiled = compile_source(source, output_values=['abi', 'bin'])
    return next(iter(compiled.values()))


def deploy_contract(client: Dict[str, Any], contract_path: str) -> Dict[str, Any]:
    if client.get('stub'):  # Return dummy address
        return {"address": "0xStub", "abi": [], "stub": True}
    try:  # pragma: no cover heavy path
        compiled = _compile_contract(contract_path)
        abi = compiled['abi']
        bytecode = compiled['bin']
        w3 = client['w3']
        acct = w3.eth.accounts[0]
        Contract = w3.eth.contract(abi=abi, bytecode=bytecode)
        tx_hash = Contract.constructor().transact({'from': acct})
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        addr = receipt.contractAddress
        return {"address": addr, "abi": abi, "stub": False}
    except Exception as e:
        return {"address": "0xStub", "abi": [], "stub": True, "error": str(e)}


def get_contract(client: Dict[str, Any], address: str, abi: List[Dict[str, Any]]):
    if client.get('stub'):
        return {"stub": True, "address": address, "abi": abi}
    return client['w3'].eth.contract(address=address, abi=abi)


def log_threat_event(contract, client: Dict[str, Any], src_ip: str, dst_ip: str,
                     severity: str, details: str) -> Dict[str, Any]:
    record = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "severity": severity,
        "details": details[:200],
        "timestamp": int(time.time())
    }
    if isinstance(contract, dict) and contract.get('stub'):
        # Append to in-memory stub list
        _STUB_EVENTS.append({**record, "block": len(_STUB_EVENTS)+1, "tx_hash": f"0xstub{len(_STUB_EVENTS)+1:02d}"})
        return {"tx_hash": _STUB_EVENTS[-1]['tx_hash'], "stub": True}
    try:  # pragma: no cover
        w3 = client['w3']
        acct = w3.eth.accounts[0]
        tx = contract.functions.logThreat(src_ip, dst_ip, severity, details).transact({'from': acct})
        receipt = w3.eth.wait_for_transaction_receipt(tx)
        return {"tx_hash": receipt.transactionHash.hex(), "stub": False}
    except Exception as e:
        return {"error": str(e), "stub": True}


def fetch_recent_events(limit: int = 10):
    # Stub path
    if _STUB_EVENTS:
        rows = list(reversed(_STUB_EVENTS[-limit:]))
        return pd.DataFrame(rows)
    # Fallback placeholder
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

