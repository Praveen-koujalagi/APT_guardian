import time
from datetime import datetime, timezone
from typing import List, Dict, Any

import streamlit as st

# Local module imports (all currently lightweight stubs)
from ml_models.inference import load_models, predict_flows
from utils.packet_capture import LivePacketCapture
from utils.graph_utils import build_attack_graph_placeholder, render_attack_graph
from blockchain.blockchain_utils import get_blockchain_client, fetch_recent_events
from utils.logger import get_mongo_client, fetch_recent_alerts


st.set_page_config(
    page_title="APT Guardian – AI-Powered APT Detection",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --------------------------------------------------------------------------------------
# Sidebar: Run Mode & Controls
# --------------------------------------------------------------------------------------
st.sidebar.title("⚙️ Configuration")
run_mode = st.sidebar.radio("Run Mode", ["Dataset Mode", "Live Capture Mode"], index=0)
auto_refresh = False
refresh_interval = 10
if run_mode == "Live Capture Mode":
    auto_refresh = st.sidebar.checkbox("Auto-refresh", value=True, help="Continuously update dashboard with new packets & alerts.")
    refresh_interval = st.sidebar.slider("Refresh every (seconds)", 5, 60, 10)

st.sidebar.markdown("---")
st.sidebar.markdown("### Model Selection")
selected_models = st.sidebar.multiselect(
    "Models to use",
    options=["RandomForest", "XGBoost", "LSTM", "GNN"],
    default=["RandomForest"],
    help="Multiple selections will ensemble predictions (majority vote / averaging)."
)

st.sidebar.markdown("---")
st.sidebar.markdown("### Blockchain")
enable_chain = st.sidebar.checkbox("Enable Blockchain Logging", value=True)

st.sidebar.markdown("### Databases")
enable_mongo = st.sidebar.checkbox("MongoDB Logging", value=True)
enable_neo4j = st.sidebar.checkbox("Neo4j Graph", value=True)

st.sidebar.markdown("---")
st.sidebar.caption("APT Guardian Prototype • Streamlit UI Skeleton")


# --------------------------------------------------------------------------------------
# Lazy initialize resources (st.session_state used to avoid reloading)
# --------------------------------------------------------------------------------------
def init_state():
    if "models" not in st.session_state or set(selected_models) != set(st.session_state.get("active_model_names", [])):
        st.session_state.models = load_models(selected_models)
        st.session_state.active_model_names = selected_models
    if "packet_capture" not in st.session_state:
        st.session_state.packet_capture = LivePacketCapture(interface=None)  # None -> default
    if "blockchain" not in st.session_state and enable_chain:
        st.session_state.blockchain = get_blockchain_client(auto_connect=True)
    if "mongo" not in st.session_state and enable_mongo:
        st.session_state.mongo = get_mongo_client()
    if "last_refresh" not in st.session_state:
        st.session_state.last_refresh = time.time()


init_state()


# --------------------------------------------------------------------------------------
# Tabs (Main Navigation Areas)
# --------------------------------------------------------------------------------------
tab_labels = [
    "📊 Dashboard",
    "🌐 Network Analysis",
    "🧠 Threat Intelligence",
    "⛓ Blockchain Logs"
]

tab_dashboard, tab_network, tab_threat_intel, tab_blockchain = st.tabs(tab_labels)


# --------------------------------------------------------------------------------------
# Helper placeholder data generation (to make skeleton interactive now)
# --------------------------------------------------------------------------------------
def _dummy_flow_batch(n: int = 5) -> List[Dict[str, Any]]:
    base_ts = datetime.now(timezone.utc)
    flows = []
    for i in range(n):
        flows.append({
            "src_ip": f"10.0.0.{i+1}",
            "dst_ip": f"192.168.1.{(i*3)%255}",
            "src_port": 10000 + i,
            "dst_port": 443,
            "protocol": "TCP",
            "packet_count": 10 + i,
            "byte_count": 2048 + (i * 300),
            "timestamp": (base_ts).isoformat() + "Z"
        })
    return flows


def run_dataset_mode():
    st.info("Dataset Mode active. This will load flows from a dataset (placeholder).")
    flows = _dummy_flow_batch(10)
    preds = predict_flows(st.session_state.models, flows)
    st.subheader("Sample Predictions")
    st.dataframe(preds)


def run_live_mode():
    st.warning("Live Capture Mode active. Real packet capture not yet implemented – using placeholder flows.")
    flows = _dummy_flow_batch(3)
    preds = predict_flows(st.session_state.models, flows)
    st.subheader("Latest Live Predictions")
    st.dataframe(preds)

    if auto_refresh:
        st.caption(f"Auto-refresh every {refresh_interval}s enabled.")
        st.session_state._refresh_count = st.session_state.get('_refresh_count', 0) + 1
        st.write(f"Refresh count: {st.session_state._refresh_count}")
        st.markdown(f"<meta http-equiv='refresh' content='{refresh_interval}'>", unsafe_allow_html=True)


# --------------------------------------------------------------------------------------
# Tab: Dashboard
# --------------------------------------------------------------------------------------
with tab_dashboard:
    st.header("📊 Operational Dashboard")
    st.write("High-level metrics & current detection status.")

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Monitored Hosts", 12, "+2")
    col2.metric("Alerts (24h)", 8, "+1")
    col3.metric("High Severity", 2)
    col4.metric("Models Active", len(selected_models))

    st.markdown("### Mode Output")
    if run_mode == "Dataset Mode":
        run_dataset_mode()
    else:
        run_live_mode()


# --------------------------------------------------------------------------------------
# Tab: Network Analysis (Graph)
# --------------------------------------------------------------------------------------
with tab_network:
    st.header("🌐 Network Attack Graph")
    st.write("Visual representation of relationships (attacker → victim) (placeholder graph).")
    graph = build_attack_graph_placeholder()  # networkx graph placeholder
    render_attack_graph(graph)


# --------------------------------------------------------------------------------------
# Tab: Threat Intelligence
# --------------------------------------------------------------------------------------
with tab_threat_intel:
    st.header("🧠 Threat Intelligence Feed")
    st.write("Aggregated alerts with enrichment (placeholder).")
    placeholder_alerts = fetch_recent_alerts(limit=15)
    st.dataframe(placeholder_alerts)


# --------------------------------------------------------------------------------------
# Tab: Blockchain Logs
# --------------------------------------------------------------------------------------
with tab_blockchain:
    st.header("⛓ Blockchain Event Log")
    if enable_chain and "blockchain" in st.session_state:
        events = fetch_recent_events(limit=10)
        st.dataframe(events)
    else:
        st.info("Blockchain logging disabled or not initialized.")


# --------------------------------------------------------------------------------------
# Footer
# --------------------------------------------------------------------------------------
st.markdown("---")
st.caption("Prototype UI • Functionality will expand with real data, models, and integrations.")
