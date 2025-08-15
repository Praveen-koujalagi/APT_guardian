import os, time, io
import streamlit as st
from pymongo import MongoClient
from py2neo import Graph
import networkx as nx
import matplotlib.pyplot as plt
from dotenv import load_dotenv

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "apt_guardian")
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "neo4jpassword")

mongo = MongoClient(MONGO_URI)[MONGO_DB]
graph = Graph(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

st.set_page_config(page_title="APT Guardian", layout="wide")
st.title("🔎 APT Guardian — Alerts & Attack Graph")

col1, col2 = st.columns([1,2])

with col1:
    st.subheader("Latest Alerts")
    limit = st.slider("How many alerts", 5, 100, 25)
    rows = list(mongo.alerts.find().sort("createdAt", -1).limit(limit))
    if not rows:
        st.info("No alerts yet. Start the generator to produce traffic.")
    else:
        for r in rows:
            st.write(f"**{r.get('src')} → {r.get('dst')}**  score={r.get('score'):.3f}  proto={r.get('proto')}  bytes={r.get('bytes')}")

with col2:
    st.subheader("Attack Path Graph (Neo4j → NetworkX)")
    # Pull a small subgraph
    query = """    MATCH (a:Host)-[r:SUSPICIOUS]->(b:Host)
    RETURN a.ip as src, b.ip as dst, r.score as score
    """
    data = list(graph.run(query))
    G = nx.DiGraph()
    for rec in data:
        G.add_edge(rec["src"], rec["dst"], score=rec["score"])

    if len(G) == 0:
        st.info("Graph is empty yet.")
    else:
        fig = plt.figure(figsize=(8,6))
        pos = nx.spring_layout(G, seed=42)
        nx.draw(G, pos, with_labels=True, node_size=900, font_size=8)
        # edge labels (score)
        edge_labels = {(u,v): f"{d['score']:.2f}" for u,v,d in G.edges(data=True)}
        nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=7)
        st.pyplot(fig)

st.caption("This MVP uses IsolationForest; replace with GNNs later.")
