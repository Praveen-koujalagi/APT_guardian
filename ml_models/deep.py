"""Deep learning models: LSTM/GRU sequence model & Graph Neural Network placeholder.

The implementations are intentionally lightweight so they can run inside CI
without GPU acceleration. They gracefully degrade if torch-geometric is not
installed (skips GNN training while still reporting status).

Design:
 - SequenceModel wraps an LSTM or GRU followed by a small MLP head.
 - GraphModel (GraphSAGE-style) uses torch-geometric if present, else a
   simple linear classifier over aggregated node features.
 - Helper train functions accept already preprocessed feature matrices and
   labels; for sequence training we reshape flat samples into faux sequences
   (sequence length default=5) by padding / repeating as needed. This keeps
   code simple while allowing later replacement with true temporal batching.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Any, Tuple, Optional
import math

try:  # Allow absence of torch in minimal environments
    import torch  # type: ignore
    import torch.nn as nn  # type: ignore
    import torch.optim as optim  # type: ignore
    _HAS_TORCH = True
except Exception:  # pragma: no cover
    _HAS_TORCH = False
    class _Dummy:
        def __getattr__(self, item):
            raise RuntimeError("Torch not available; deep model functionality disabled")
    torch = _Dummy()  # type: ignore
    nn = _Dummy()  # type: ignore
    optim = _Dummy()  # type: ignore

try:  # Optional torch-geometric
    from torch_geometric.data import Data as GeoData  # type: ignore
    from torch_geometric.nn import SAGEConv  # type: ignore
    _HAS_GEOMETRIC = True
except Exception:  # pragma: no cover - optional dependency
    _HAS_GEOMETRIC = False


@dataclass
class SequenceConfig:
    input_dim: int
    hidden_dim: int = 64
    num_layers: int = 1
    rnn_type: str = "lstm"  # or "gru"
    dropout: float = 0.1
    seq_len: int = 5
    epochs: int = 5
    batch_size: int = 64
    lr: float = 1e-3
    device: str = "cpu"


class SequenceModel(nn.Module):
    def __init__(self, cfg: SequenceConfig):
        super().__init__()
        rnn_cls = nn.LSTM if cfg.rnn_type.lower() == "lstm" else nn.GRU
        self.rnn = rnn_cls(
            input_size=cfg.input_dim,
            hidden_size=cfg.hidden_dim,
            num_layers=cfg.num_layers,
            batch_first=True,
            dropout=cfg.dropout if cfg.num_layers > 1 else 0.0,
        )
        self.head = nn.Sequential(
            nn.Linear(cfg.hidden_dim, cfg.hidden_dim // 2),
            nn.ReLU(),
            nn.Dropout(cfg.dropout),
            nn.Linear(cfg.hidden_dim // 2, 1)
        )

    def forward(self, x):  # x: (B, T, F)
        out, _ = self.rnn(x)
        # Use last timestep
        last = out[:, -1, :]
        return self.head(last).squeeze(-1)


def train_sequence_model(X, y, epochs: int = 5, rnn_type: str = "lstm", seq_len: int = 5,
                         device: Optional[str] = None) -> Tuple[SequenceModel, Dict[str, Any]]:
    """Train an LSTM/GRU over faux sequences constructed from flat feature rows.

    We create sequences by grouping consecutive samples; if number of samples
    isn't divisible by seq_len we pad the last group by repeating final row.
    Labels use majority of the seq (equivalent to max) because of binary case.
    """
    if device is None:
        device = "cuda" if torch.cuda.is_available() else "cpu"
    if not _HAS_TORCH:  # Return dummy object & metrics
        class DummyModel:
            def state_dict(self): return {}
        return DummyModel(), {"train_loss": None, "seqs": 0, "skipped": True}
    X_tensor = torch.tensor(X.values, dtype=torch.float32)
    y_tensor = torch.tensor(y.values, dtype=torch.float32)
    n, f = X_tensor.shape
    cfg = SequenceConfig(input_dim=f, rnn_type=rnn_type, epochs=epochs, seq_len=seq_len, device=device)
    model = SequenceModel(cfg).to(device)
    # Build sequences
    num_seqs = math.ceil(n / seq_len)
    seq_data = []
    seq_labels = []
    for i in range(num_seqs):
        start = i * seq_len
        end = min(start + seq_len, n)
        chunk = X_tensor[start:end]
        # Pad if needed
        if chunk.shape[0] < seq_len:
            pad = chunk[-1:].repeat(seq_len - chunk.shape[0], 1)
            chunk = torch.cat([chunk, pad], dim=0)
        seq_data.append(chunk.unsqueeze(0))
        # Majority / any positive -> 1
        lbl = y_tensor[start:end].max().item()
        seq_labels.append(lbl)
    seq_X = torch.cat(seq_data, dim=0).to(device)  # (S, T, F)
    seq_y = torch.tensor(seq_labels, dtype=torch.float32).to(device)
    optimizer = optim.Adam(model.parameters(), lr=cfg.lr)
    criterion = nn.BCEWithLogitsLoss()
    model.train()
    for ep in range(cfg.epochs):
        optimizer.zero_grad()
        logits = model(seq_X)
        loss = criterion(logits, seq_y)
        loss.backward()
        optimizer.step()
    metrics = {"train_loss": float(loss.item()), "seqs": int(num_seqs)}
    return model.cpu(), metrics


# ----------------------------------------------------------------------------------
# Graph Model (GraphSAGE style) – optional torch-geometric
# ----------------------------------------------------------------------------------
class SimpleGraphSAGE(nn.Module):  # pragma: no cover - heavy dependency path
    def __init__(self, in_channels: int, hidden: int = 64):
        super().__init__()
        self.conv1 = SAGEConv(in_channels, hidden)
        self.conv2 = SAGEConv(hidden, hidden)
        self.lin = nn.Linear(hidden, 1)

    def forward(self, x, edge_index):
        h = self.conv1(x, edge_index).relu()
        h = self.conv2(h, edge_index).relu()
        out = self.lin(h)
        return out.squeeze(-1)


def build_graph_from_flows(X, y) -> Tuple[Any, Any, Any]:  # type: ignore
    """Construct a trivial host graph: nodes=host ips (src+dst) with averaged features.
    Because original IP columns are removed during preprocessing we accept that
    caller may have appended `src_ip`/`dst_ip` columns (if present, must be str).
    If absent, we simulate a single-node graph.
    Returns (x, edge_index, y_node).
    """
    import pandas as pd
    if "src_ip" not in X.columns or "dst_ip" not in X.columns:
        # Single node fallback
        feats = torch.tensor(X.select_dtypes(include=['number']).mean().values, dtype=torch.float32).unsqueeze(0)
        edge_index = torch.zeros((2, 0), dtype=torch.long)
        y_node = torch.tensor([int(y.max())], dtype=torch.float32)
        return feats, edge_index, y_node
    df = X.copy()
    df_num = df.select_dtypes(include=["number"]).copy()
    # Build node feature by averaging features for each IP (appearing as src or dst)
    ips = set(df["src_ip"].astype(str)).union(set(df["dst_ip"].astype(str)))
    ip_to_idx = {ip: i for i, ip in enumerate(sorted(ips))}
    import numpy as np
    node_feats = torch.zeros((len(ip_to_idx), df_num.shape[1]), dtype=torch.float32)
    counts = torch.zeros(len(ip_to_idx), dtype=torch.float32)
    for idx, row in df_num.iterrows():
        sip = str(df.loc[idx, "src_ip"])
        dip = str(df.loc[idx, "dst_ip"])
        s_idx = ip_to_idx[sip]
        node_feats[s_idx] += torch.tensor(row.values, dtype=torch.float32)
        counts[s_idx] += 1
        d_idx = ip_to_idx[dip]
        node_feats[d_idx] += torch.tensor(row.values, dtype=torch.float32)
        counts[d_idx] += 1
    counts[counts == 0] = 1
    node_feats = node_feats / counts.unsqueeze(1)
    # Edges: directed src->dst for each flow
    edges = []
    for idx, row in df.iterrows():
        edges.append([ip_to_idx[str(row.src_ip)], ip_to_idx[str(row.dst_ip)]])
    if edges:
        edge_index = torch.tensor(edges, dtype=torch.long).t().contiguous()
    else:
        edge_index = torch.zeros((2, 0), dtype=torch.long)
    # Node labels: mark node malicious if any flow with node src had y=1
    node_labels = torch.zeros(len(ip_to_idx), dtype=torch.float32)
    for idx, lbl in enumerate(y):
        if int(lbl) == 1:
            sip = str(df.iloc[idx].src_ip)
            node_labels[ip_to_idx[sip]] = 1
    return node_feats, edge_index, node_labels


def train_gnn_model(X, y, epochs: int = 5) -> Tuple[Optional[Any], Dict[str, Any]]:
    if not _HAS_TORCH:
        return None, {"skipped": True, "reason": "torch_missing"}
    if not _HAS_GEOMETRIC:  # Fallback simple logistic regression over mean feature vector
        import numpy as np
        feats = torch.tensor(X.select_dtypes(include=['number']).mean().values, dtype=torch.float32)
        lin = nn.Linear(feats.shape[0], 1)
        optimizer = optim.Adam(lin.parameters(), lr=1e-3)
        criterion = nn.BCEWithLogitsLoss()
        for _ in range(epochs):
            optimizer.zero_grad()
            logits = lin(feats)
            target = torch.tensor([float(int(y.max()))])
            loss = criterion(logits, target)
            loss.backward(); optimizer.step()
        return lin, {"train_loss": float(loss.item()), "mode": "fallback_linear"}
    # Build graph data
    x, edge_index, y_node = build_graph_from_flows(X, y)
    model = SimpleGraphSAGE(x.shape[1])
    optimizer = optim.Adam(model.parameters(), lr=1e-3)
    criterion = nn.BCEWithLogitsLoss()
    model.train()
    for _ in range(epochs):
        optimizer.zero_grad()
        logits = model(x, edge_index)
        # Align labels (some nodes may not have label info -> treat missing as 0)
        if y_node.shape[0] != logits.shape[0]:  # safety
            min_len = min(y_node.shape[0], logits.shape[0])
            logits = logits[:min_len]
            y_aligned = y_node[:min_len]
        else:
            y_aligned = y_node
        loss = criterion(logits, y_aligned)
        loss.backward(); optimizer.step()
    return model, {"train_loss": float(loss.item()), "nodes": int(x.shape[0]), "edges": int(edge_index.shape[1])}


def inference_sequence(model: Any, X):
    model.eval()
    with torch.no_grad():
        X_tensor = torch.tensor(X.values, dtype=torch.float32)
        n, f = X_tensor.shape
        seq_len = 5
        num_seqs = math.ceil(n / seq_len)
        preds = []
        for i in range(num_seqs):
            start = i * seq_len
            end = min(start + seq_len, n)
            chunk = X_tensor[start:end]
            if chunk.shape[0] < seq_len:
                pad = chunk[-1:].repeat(seq_len - chunk.shape[0], 1)
                chunk = torch.cat([chunk, pad], dim=0)
            logit = model(chunk.unsqueeze(0))
            preds.append(torch.sigmoid(logit))
        return torch.cat(preds)


def inference_gnn(model, X):  # pragma: no cover simple wrapper
    if model is None:
        return torch.zeros(X.shape[0])
    model.eval()
    with torch.no_grad():
        # For fallback linear case
        if isinstance(model, nn.Linear) and not _HAS_GEOMETRIC:
            feats = torch.tensor(X.select_dtypes(include=['number']).values, dtype=torch.float32)
            logits = model(feats.mean(0))
            return torch.sigmoid(logits.repeat(X.shape[0]))
        # Graph case: build graph and propagate
        x, edge_index, _ = build_graph_from_flows(X, y_node := [0]*len(X))  # y_node not used
        logits = model(x, edge_index)
        probs = torch.sigmoid(logits)
        # Broadcast average prob to each row (simplification)
        return probs.mean().repeat(X.shape[0])
