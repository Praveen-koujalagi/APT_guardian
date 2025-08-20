"""Graph utilities (placeholder)."""
from __future__ import annotations
import networkx as nx
import streamlit as st


def build_attack_graph_placeholder():
    g = nx.DiGraph()
    g.add_edge("Attacker", "HostA", severity="High")
    g.add_edge("Attacker", "HostB", severity="Medium")
    g.add_edge("HostA", "DBServer", severity="High")
    return g


def render_attack_graph(graph):
    # Simple textual placeholder until PyVis integration
    st.subheader("Graph Edges")
    edges = [f"{u} -> {v} (sev={d.get('severity')})" for u, v, d in graph.edges(data=True)]
    st.write("\n".join(edges))
