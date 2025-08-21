"""Graph utilities for building and visualising host communication graphs."""
from __future__ import annotations
from typing import Iterable, Dict, Any
import networkx as nx
import streamlit as st

try:  # pragma: no cover optional
    from pyvis.network import Network  # type: ignore
    _HAS_PYVIS = True
except Exception:  # pragma: no cover
    _HAS_PYVIS = False

# Optional Neo4j
try:
    from neo4j import GraphDatabase  # type: ignore
    _HAS_NEO4J = True
except Exception:  # pragma: no cover
    _HAS_NEO4J = False


def build_attack_graph(flows_df) -> nx.DiGraph:
    g = nx.DiGraph()
    if flows_df is None or getattr(flows_df, 'empty', True):
        return g
    for _, row in flows_df.iterrows():
        src = row.get('src_ip'); dst = row.get('dst_ip')
        if not src or not dst:
            continue
        risk = float(row.get('risk_score', 0.0))
        sev = row.get('prediction', 'Unknown')
        if not g.has_node(src):
            g.add_node(src, risk=0.0, alerts=0)
        if not g.has_node(dst):
            g.add_node(dst, risk=0.0, alerts=0)
        # Update edge
        if g.has_edge(src, dst):
            g[src][dst]['count'] += 1
            g[src][dst]['risk'] = max(g[src][dst]['risk'], risk)
        else:
            g.add_edge(src, dst, count=1, risk=risk, severity=sev)
        # Update node risk (running max & count)
        g.nodes[src]['risk'] = max(g.nodes[src]['risk'], risk)
        g.nodes[src]['alerts'] += 1 if sev != 'Benign' else 0
        g.nodes[dst]['risk'] = max(g.nodes[dst]['risk'], risk * 0.8)
    return g


def _color_for_risk(risk: float) -> str:
    if risk >= 0.7:
        return '#ff4d4d'
    if risk >= 0.4:
        return '#ffa64d'
    return '#7fd1b9'


def render_attack_graph(graph: nx.DiGraph):
    if _HAS_PYVIS and len(graph.nodes) <= 400:  # avoid huge graphs in PyVis
        net = Network(height='600px', width='100%', directed=True, bgcolor='#111', font_color='white')
        for n, data in graph.nodes(data=True):
            risk = float(data.get('risk', 0.0))
            label = f"{n}\nRisk:{risk:.2f}\nAlerts:{data.get('alerts',0)}"
            net.add_node(n, label=label, color=_color_for_risk(risk), title=label)
        for u, v, d in graph.edges(data=True):
            title = f"Flows:{d.get('count')} Risk:{d.get('risk',0):.2f} Sev:{d.get('severity')}"
            net.add_edge(u, v, value=d.get('count', 1), title=title, color=_color_for_risk(d.get('risk',0)))
        # Correct JSON options string for physics stabilization
        net.set_options('{"physics": {"stabilization": true}}')
        html = net.generate_html(notebook=False)
        st.components.v1.html(html, height=620, scrolling=True)
    else:
        st.subheader("Graph Summary")
        st.write(f"Nodes: {graph.number_of_nodes()}  Edges: {graph.number_of_edges()}")
        top = sorted(graph.nodes(data=True), key=lambda x: x[1].get('risk', 0), reverse=True)[:10]
        st.write("Top Risk Nodes:")
        st.table([{ 'node': n, 'risk': f"{d.get('risk',0):.2f}", 'alerts': d.get('alerts',0)} for n,d in top])


def push_graph_to_neo4j(graph: nx.DiGraph, uri: str, user: str, password: str, max_nodes: int = 1000) -> bool:
    """Persist graph nodes & edges into Neo4j.

    Creates (Host {ip, risk, alerts}) nodes and (CONNECTS {count, risk, severity}) relationships.
    Returns True on success (best-effort; failures are swallowed).
    """
    if not _HAS_NEO4J or graph is None or graph.number_of_nodes() == 0:
        return False
    if graph.number_of_nodes() > max_nodes:
        return False
    try:  # pragma: no cover heavy IO
        driver = GraphDatabase.driver(uri, auth=(user, password))
        cypher = (
            "MERGE (s:Host {ip:$src}) SET s.risk = max(coalesce(s.risk,0), $srisk), s.alerts = coalesce(s.alerts,0)+$salerts "
            "MERGE (d:Host {ip:$dst}) SET d.risk = max(coalesce(d.risk,0), $drisk), d.alerts = coalesce(d.alerts,0)+$dalerts "
            "MERGE (s)-[r:CONNECTS]->(d) SET r.count = coalesce(r.count,0)+$count, r.risk = max(coalesce(r.risk,0), $risk), r.severity = $severity"
        )
        with driver.session() as sess:
            for u, v, d in graph.edges(data=True):
                sess.run(cypher, src=u, dst=v, srisk=graph.nodes[u].get('risk',0.0), drisk=graph.nodes[v].get('risk',0.0),
                         salerts=graph.nodes[u].get('alerts',0), dalerts=graph.nodes[v].get('alerts',0),
                         count=d.get('count',1), risk=d.get('risk',0.0), severity=d.get('severity','Unknown'))
        driver.close()
        return True
    except Exception:
        return False
