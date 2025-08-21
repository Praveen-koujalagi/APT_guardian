from blockchain.blockchain_utils import get_blockchain_client, deploy_contract, get_contract, log_threat_event, fetch_recent_events

def test_blockchain_stub_logging():
    client = get_blockchain_client(auto_connect=False)
    contract_info = deploy_contract(client, 'blockchain/contract.sol')
    contract = get_contract(client, contract_info['address'], contract_info['abi'])
    res = log_threat_event(contract, client, '1.1.1.1','2.2.2.2','High','Test event')
    assert 'tx_hash' in res
    events = fetch_recent_events(limit=5)
    assert not events.empty
