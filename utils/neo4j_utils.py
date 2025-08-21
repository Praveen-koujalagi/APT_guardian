"""Neo4j integration helpers.

Provides light-weight helper functions to connect, push and retrieve graph
information. All functions degrade gracefully if the neo4j driver is not
available or the database is unreachable.
"""
from __future__ import annotations
from typing import Any, Dict, Optional
import networkx as nx

try:  # pragma: no cover (optional dependency)
    from neo4j import GraphDatabase  # type: ignore
    _HAS_NEO4J = True
except Exception:  # pragma: no cover
    _HAS_NEO4J = False


def get_driver(uri: str, user: str, password: str):
    if not _HAS_NEO4J:
        return {"stub": True, "error": "neo4j_driver_missing"}
    try:  # pragma: no cover heavy IO
        driver = GraphDatabase.driver(uri, auth=(user, password))
        # Probe connection quickly
        with driver.session() as sess:
            sess.run("RETURN 1 LIMIT 1")
        return {"stub": False, "driver": driver}
    except Exception as e:
        return {"stub": True, "error": str(e)}


def fetch_attack_graph(driver_obj, limit_nodes: int = 1000, limit_edges: int = 5000) -> nx.DiGraph:
    g = nx.DiGraph()
    if not driver_obj or driver_obj.get("stub"):
        return g
    driver = driver_obj["driver"]
    try:  # pragma: no cover heavy IO
        with driver.session() as sess:
            node_res = sess.run(
                "MATCH (h:Host) RETURN h.ip as ip, coalesce(h.risk,0) as risk, coalesce(h.alerts,0) as alerts LIMIT $n", n=limit_nodes
            )
            for rec in node_res:
                g.add_node(rec["ip"], risk=float(rec["risk"]), alerts=int(rec["alerts"]))
            edge_res = sess.run(
                "MATCH (a:Host)-[r:CONNECTS]->(b:Host) RETURN a.ip as src, b.ip as dst, coalesce(r.count,0) as count, coalesce(r.risk,0) as risk, r.severity as severity LIMIT $m",
                m=limit_edges,
            )
            for rec in edge_res:
                g.add_edge(rec["src"], rec["dst"], count=int(rec["count"]), risk=float(rec["risk"]), severity=rec.get("severity") or "Unknown")
    except Exception:
        return g
    return g


def close_driver(driver_obj):
    if driver_obj and not driver_obj.get("stub"):
        try:
            driver_obj["driver"].close()
        except Exception:
            pass
