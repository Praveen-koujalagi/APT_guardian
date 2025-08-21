# APT Guardian – AI-Powered Advanced Persistent Threat Detection

An AI-driven platform for detecting Advanced Persistent Threats (APTs) with multi-model analytics, automatic preprocessing, blockchain-backed incident logging, and graph-based network context visualization.

> Status: Baseline + deep model scaffolds implemented (RandomForest, XGBoost, LSTM/GRU placeholder, GNN placeholder), synthetic live capture, blockchain stub logging, graph visualization, drift detection and test harness operational. Further hardening & real environment integrations (real packet sniff, full GNN) remain.

---
## ✨ Features (Current & Planned)
**Implemented**
- Streamlit dashboard with modular tabs (Dashboard, Network Analysis, Threat Intelligence, Blockchain Logs)
- Automatic preprocessing pipeline (feature dropping, categorical encoding, scaling, outlier capping, optional SMOTE)
- Multi-dataset aggregation & training script (`train_baseline.py`)
- RandomForest & XGBoost model training + persisted artifacts (models, scaler, metrics, feature list, feature stats)
- Deep model stubs: LSTM/GRU sequence trainer & GNN (GraphSAGE fallback) with `.pt` persistence
- Ensemble inference across classical + deep models (probability averaging)
- Synthetic / real (scapy if available) packet capture with flow assembly
- Blockchain IncidentLog contract, stub deployment & event logging API (Web3 optional)
- MongoDB alert logging / stub buffer; PyVis-based network graph visualization with risk coloring
- Drift detection (PSI) & adversarial input sanitation
- Test harness (`pytest`) covering preprocessing, training/inference, blockchain stub, drift detection
- GitHub Actions CI (lightweight dependency set) running tests on push/PR

**Planned / Roadmap**
- Packet capture flow assembler (Scapy / PyShark) feeding live mode
- LSTM / GRU temporal sequence model (PyTorch)
- Graph Neural Network (torch-geometric) over host/flow graph
- MongoDB alert storage & Neo4j attack graph persistence
- Real Web3 event logging (deploy & interact with contract)
- Threat intel enrichment & risk scoring
- Advanced graph visualization (PyVis / Plotly interactive)

---
## 🗂 Repository Structure
```
app.py                  # Streamlit entrypoint
train_baseline.py       # Dataset aggregation + training orchestration
ml_models/
  preprocessing.py      # auto_preprocess pipeline
  train.py              # model training + metrics persistence
  inference.py          # model/scaler loading + prediction
blockchain/
  hardhat/ (future)     # placeholder for deployment configs
  contract(s)           # IncidentLog.sol (smart contract scaffold)
utils/
  packet_capture.py     # live capture stub
  graph_utils.py        # placeholder graph builder
  logger.py             # placeholder Mongo/Metrics
models/                 # persisted model artifacts (gitignored except metrics)
data/                   # raw datasets (gitignored)
requirements.txt
```

---
## 🚀 Quick Start
Create & activate a virtual environment (recommended) then install dependencies:
```bash
pip install -r requirements.txt
```
Train baseline models (sampling caps applied for speed):
```bash
python train_baseline.py --models RandomForest XGBoost --sample_limit 40000
```
Run the dashboard:
```bash
streamlit run app.py
```
If `streamlit` is not on PATH inside Windows PowerShell with a venv:
```bash
python -m streamlit run app.py
```

---
## 🧪 Training Artifacts
Saved under `models/`:
- `RandomForest.joblib`, `XGBoost.joblib`
- `scaler.joblib`
- `features.json` (feature list + metrics)
- `metrics.json` (per-model metrics)
- `merged_training_snapshot.csv` (preview subset)

Metrics are surfaced in the Dashboard tab (future enhancement: explicit metrics visualization panel).

---
## 🔄 Automatic Preprocessing Summary
The `auto_preprocess` pipeline performs:
1. Label column detection / synthesis & binary normalization
2. Irrelevant identifier/time field dropping (regex-driven)
3. Categorical cardinality control + one-hot encoding
4. Numeric coercion, NaN + inf handling, median filling
5. Outlier capping (0.999 quantile) pre-scaling
6. Scaling (StandardScaler default)
7. Optional SMOTE (if `imbalanced-learn` present & class imbalance severe)

Artifacts preserve feature ordering for inference consistency.

---
## ⛓ Blockchain (Planned Flow)
1. Deploy `IncidentLog` via Hardhat/Ganache
2. Emit events on confirmed high-severity detections
3. Stream events into dashboard & persist hash references

Current contract & client stubs are placeholders; deployment scripts to come.

---
## 🧬 Future ML Enhancements
| Model | Purpose | Status |
|-------|---------|--------|
| RandomForest | Baseline tabular detection | Implemented |
| XGBoost | Gradient boosting performance baseline | Implemented |
| LSTM / GRU | Temporal patterns in sequential flows | Prototype (sequence batching simplification) |
| GNN (GraphSAGE / GAT) | Host-communication graph inference | Prototype (fallback if torch-geometric missing) |

---
## 🛣 Roadmap (Next Milestones)
1. Elevate packet capture to full flow feature enrichment (rolling stats, time deltas)
2. Harden blockchain path (real deployment, event polling & confirmations)
3. Neo4j integration (persistence + advanced queries) & risk propagation algorithms
4. Replace prototype GNN with full GraphSAGE/GAT training on host graph
5. True temporal sequence construction per host/session for LSTM/GRU
6. Threat intel enrichment (external feeds, reputation scores) & correlation
7. Expand tests (drift scenario simulations, security sanitation edge cases)
8. Add model artifact signing & verification

---
## 🏷 Versioning & Releases
Semantic version tags (`vMAJOR.MINOR.PATCH`). Example to create first release tag:
```bash
git tag -a v0.1.0 -m "Initial baseline models & dashboard"
git push origin v0.1.0
```
Then draft a GitHub Release attaching notes & future changelog.

---
## ⚙️ Development Notes
- Large raw datasets are excluded via `.gitignore`.
- Heavy deep learning libs included; install selectively if environment constraints (comment out in `requirements.txt`).
- Streamlit `experimental_autorefresh` removed in newer versions; meta refresh tag used instead.

---
## 🔐 Security & Validation (Planned)
- Model drift monitoring
- Adversarial feature sanity checks
- Signed model artifact verification
- Blockchain integrity audits

---
## 🤝 Contributions
Roadmap items welcome; open issues or PRs once base architecture stabilizes.

---
## 📄 License
TBD (add an OSS license file e.g., MIT or Apache-2.0).

---
_APT Guardian is an evolving research-grade prototype – expect rapid iteration._
