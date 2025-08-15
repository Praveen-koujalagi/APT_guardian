"""Utility to build graph snapshots from recent raw events.

This supports future GNN training by transforming flow events into a graph
structure with node & edge features. For now we only compute a few basic
aggregations to keep it lightweight.
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import Dict, Any, Iterable, Tuple

import numpy as np


def build_snapshot(events: Iterable[dict]) -> Dict[str, Any]:
    """Return a snapshot dictionary with node_features and edge_index arrays.

    Output format (agnostic to torch-geometric for now):
    {
        'nodes': [ip1, ip2, ...],
        'node_features': ndarray [N, F],
        'edge_index': ndarray [2, E],
        'edge_features': ndarray [E, F_e],
        'generated_at': timestamp
    }
    """
    node_stats = defaultdict(lambda: {
        "out_bytes": 0,
        "in_bytes": 0,
        "out_flows": 0,
        "in_flows": 0,
        "ports": set(),
    })
    edge_map: Dict[Tuple[str, str], Dict[str, Any]] = defaultdict(lambda: {
        "flows": 0,
        "bytes": 0,
    })

    for e in events:
        s = e.get("src"); d = e.get("dst")
        if not s or not d:
            continue
        b = float(e.get("bytes", 0))
        node_stats[s]["out_bytes"] += b
        node_stats[s]["out_flows"] += 1
        node_stats[s]["ports"].add(e.get("dport", 0))
        node_stats[d]["in_bytes"] += b
        node_stats[d]["in_flows"] += 1
        node_stats[d]["ports"].add(e.get("dport", 0))
        edge = edge_map[(s, d)]
        edge["flows"] += 1
        edge["bytes"] += b

    nodes = list(node_stats.keys())
    node_index = {n: i for i, n in enumerate(nodes)}
    node_features = []
    for n in nodes:
        st = node_stats[n]
        uniq_ports = len(st["ports"]) or 1
        node_features.append([
            st["out_bytes"], st["in_bytes"], st["out_flows"], st["in_flows"], uniq_ports
        ])
    node_features = np.asarray(node_features, dtype=float)
    if len(node_features):
        # scale roughly (log) to reduce magnitude spread; keep simple for now
        node_features = np.log1p(node_features)

    edges = list(edge_map.keys())
    edge_index = np.asarray([[node_index[s] for s, _ in edges], [node_index[d] for _, d in edges]]) if edges else np.zeros((2,0), dtype=int)
    edge_features = []
    for (s, d) in edges:
        em = edge_map[(s, d)]
        edge_features.append([em["flows"], em["bytes"]])
    edge_features = np.asarray(edge_features, dtype=float)
    if len(edge_features):
        edge_features = np.log1p(edge_features)

    return {
        "nodes": nodes,
        "node_features": node_features,
        "edge_index": edge_index,
        "edge_features": edge_features,
        "generated_at": time.time(),
    }
