# APT Guardian – AI-Powered APT Detection (Prototype Skeleton)

This directory contains the initial project skeleton for an AI-driven Advanced Persistent Threat (APT) detection & visualization system with planned integrations for blockchain logging, graph analytics, and real-time packet capture.

## Current Status
Prototype UI skeleton only. All functional modules are placeholders and will be incrementally implemented.

## Run the Streamlit App
Install dependencies (consider using a virtual environment):

```
pip install -r requirements.txt
streamlit run app.py
```

## Planned Components
- Dataset-based detection (offline batch inference)
- Live packet capture (Scapy / PyShark)
- ML models: RandomForest, XGBoost, LSTM/GRU, GNN (torch-geometric)
- Blockchain: Solidity smart contract `IncidentLog` for immutable threat logging
- MongoDB + Neo4j for alert storage & attack graph relationships
- Streamlit dashboard with tabs:
  - Dashboard (metrics & predictions)
  - Network Analysis (attack graph)
  - Threat Intelligence (alerts table)
  - Blockchain Logs (on-chain events)

## Folder Layout
```
apt-detection-system/
  app.py
  ml_models/
  blockchain/
  utils/
  data/
  requirements.txt
```

## Next Steps
1. Implement real dataset loading & preprocessing.
2. Add model training scripts & persistence (joblib / torch save).
3. Integrate live packet feature extraction & sliding window flow assembly.
4. Connect to local Hardhat/Ganache, deploy contract, wire Web3 logging.
5. Add MongoDB + Neo4j connectivity & attack graph derivation.
6. Replace placeholder graph rendering with PyVis / Plotly dynamic graph.
7. Implement auto-refresh logic with stateful buffering for live capture.

---
_This is an initial scaffold; expand functionality in subsequent iterations._
