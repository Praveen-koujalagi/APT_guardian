import json, os
from web3 import Web3

RPC_URL = os.getenv("RPC_URL", "http://127.0.0.1:8545")
CONTRACT_JSON = os.getenv("CONTRACT_JSON", "../blockchain/deployments/localhost/IncidentLog.json")
PRIVATE_KEY = os.getenv("PRIVATE_KEY", "")  # not required on Hardhat if using unlocked account

class ChainClient:
    def __init__(self):
        self.w3 = Web3(Web3.HTTPProvider(RPC_URL))
        # Load deployment JSON written by Hardhat deploy script
        try:
            with open(CONTRACT_JSON, "r") as f:
                data = json.load(f)
            self.contract_address = data["address"]
            self.abi = data["abi"]
            self.contract = self.w3.eth.contract(address=self.contract_address, abi=self.abi)
        except Exception as e:
            print(f"[Blockchain] Could not load contract JSON at {CONTRACT_JSON}: {e}")
            self.contract = None

    def log_incident(self, details: str, severity: str, ipfs_hash: str = "") -> str | None:
        if not self.contract:
            return None
        account = self.w3.eth.accounts[0]  # unlocked on Hardhat
        tx = self.contract.functions.logIncident(details, severity, ipfs_hash).build_transaction({
            "from": account,
            "nonce": self.w3.eth.get_transaction_count(account),
            "gas": 3_000_000,
        })
        tx_hash = self.w3.eth.send_transaction(tx)
        receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        return receipt.transactionHash.hex()
