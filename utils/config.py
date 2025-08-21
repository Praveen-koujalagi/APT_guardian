"""Central configuration handling for APT Guardian.

Loads defaults, then overrides with values from an optional `config.yaml`
file and finally environment variables. A light-weight approach keeps the
runtime flexible without introducing heavy external dependencies.

Environment variable overrides use the prefix `APT_` and upper snake case of
the key names (e.g. `APT_MONGODB_URI`).
"""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any
import os

try:  # optional dependency for YAML config
    import yaml  # type: ignore
    _HAS_YAML = True
except Exception:  # pragma: no cover
    _HAS_YAML = False


@dataclass
class Settings:
    mongodb_uri: str = "mongodb://localhost:27017"
    mongodb_db: str = "apt_guardian"
    neo4j_uri: str = "bolt://localhost:7687"
    neo4j_user: str = "neo4j"
    neo4j_password: str = "neo4j"
    blockchain_rpc: str = "http://127.0.0.1:8545"
    contract_path: str = "blockchain/contract.sol"
    # Persisted (previously deployed) contract info (optional)
    contract_address: str | None = None
    contract_abi_file: str | None = None  # JSON file containing ABI

    def as_dict(self) -> Dict[str, Any]:
        return self.__dict__.copy()


def _load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists() or not _HAS_YAML:
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if not isinstance(data, dict):
            return {}
        return data
    except Exception:
        return {}


def load_settings(config_file: str = "config.yaml") -> Settings:
    settings = Settings()
    # YAML overrides
    yaml_conf = _load_yaml(Path(config_file))
    for k, v in yaml_conf.items():
        if hasattr(settings, k):
            setattr(settings, k, v)
    # Environment overrides
    env_map = {
        'mongodb_uri': os.getenv('APT_MONGODB_URI'),
        'mongodb_db': os.getenv('APT_MONGODB_DB'),
        'neo4j_uri': os.getenv('APT_NEO4J_URI'),
        'neo4j_user': os.getenv('APT_NEO4J_USER'),
        'neo4j_password': os.getenv('APT_NEO4J_PASSWORD'),
        'blockchain_rpc': os.getenv('APT_BLOCKCHAIN_RPC'),
        'contract_address': os.getenv('APT_CONTRACT_ADDRESS'),
        'contract_abi_file': os.getenv('APT_CONTRACT_ABI_FILE'),
    }
    for k, v in env_map.items():
        if v:
            setattr(settings, k, v)
    return settings


GLOBAL_SETTINGS = load_settings()
