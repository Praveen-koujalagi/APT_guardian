import time
from datetime import datetime, timezone
from typing import List, Dict, Any

import streamlit as st
import pandas as pd
import plotly.express as px

# Local module imports
from ml_models.inference import load_models, predict_flows
from utils.packet_capture import LivePacketCapture
from utils.graph_utils import build_attack_graph, render_attack_graph, push_graph_to_neo4j
from utils.neo4j_utils import get_driver as get_neo_driver, fetch_attack_graph as neo_fetch_graph
from blockchain.blockchain_utils import (
    get_blockchain_client, fetch_recent_events, deploy_contract, get_contract, log_threat_event
)
from utils.logger import get_mongo_client, fetch_recent_alerts, log_alert, query_alerts
from utils.security import batch_sanitize
from ml_models.drift import detect_drift
from utils.config import GLOBAL_SETTINGS, load_settings

# Allow runtime reload of config (small button)
if st.sidebar.button("Reload Config"):
    st.session_state._settings = load_settings()

settings = st.session_state.get('_settings', GLOBAL_SETTINGS)

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
# New toggle to completely disable live capture (for systems without Npcap)
enable_live_capture = st.sidebar.checkbox(
    "Enable Live Packet Capture", value=True,
    help="Uncheck if Npcap/WinPcap driver is not installed; synthetic flows will be used instead."
)

# Live capture interface selection (only when enabled & in live mode)
selected_iface = None
if enable_live_capture and run_mode == "Live Capture Mode":
    try:
        from scapy.all import get_if_list  # type: ignore
        if_list = []
        try:
            if_list = get_if_list()
        except Exception:
            if_list = []
    except Exception:
        if_list = []
    iface_options = ["Auto"] + if_list
    chosen = st.sidebar.selectbox("Capture Interface", iface_options, index=0)
    selected_iface = None if chosen == "Auto" else chosen
    # Persist selection
    st.session_state._capture_iface = selected_iface
    if st.sidebar.button("Restart Capture", help="Stops current capture (if any) and restarts with selected interface"):
        if 'packet_capture' in st.session_state:
            try:
                st.session_state.packet_capture.stop()
            except Exception:
                pass
            st.session_state.pop('packet_capture')

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

with st.sidebar.expander("Connection Settings"):
    st.write("Using values from config / env (override via config.yaml or env vars)")
    st.code(f"MongoDB: {settings.mongodb_uri}\nNeo4j: {settings.neo4j_uri}\nBlockchain RPC: {settings.blockchain_rpc}", language="text")

st.sidebar.markdown("---")
severity_filter = st.sidebar.selectbox("Alert Severity Filter", ["All", "High", "Medium", "Low"])
recent_minutes = st.sidebar.selectbox("Recent Window (min)", [None, 5, 15, 60, 240], index=0)

st.sidebar.caption("APT Guardian Prototype • Streamlit UI")


# --------------------------------------------------------------------------------------
# Lazy initialize resources (st.session_state used to avoid reloading)
# --------------------------------------------------------------------------------------
def init_state():
    if "models" not in st.session_state or set(selected_models) != set(st.session_state.get("active_model_names", [])):
        st.session_state.models = load_models(selected_models)
        st.session_state.active_model_names = selected_models
    if "packet_capture" not in st.session_state:
        if run_mode == "Live Capture Mode" and enable_live_capture:
            iface = st.session_state.get('_capture_iface')
            st.session_state.packet_capture = LivePacketCapture(interface=iface)
            st.session_state.packet_capture.start()
    # If user disabled capture but a previous session had one, stop it
    if not enable_live_capture and "packet_capture" in st.session_state:
        try:
            st.session_state.packet_capture.stop()
        except Exception:
            pass
        st.session_state.pop("packet_capture", None)
    if "blockchain" not in st.session_state and enable_chain:
        st.session_state.blockchain = get_blockchain_client(auto_connect=True, provider=settings.blockchain_rpc)
        # Attempt contract deployment (or stub)
        contract_info = deploy_contract(st.session_state.blockchain, settings.contract_path)
        st.session_state.chain_contract = get_contract(st.session_state.blockchain, contract_info.get('address', '0xStub'), contract_info.get('abi', []))
    if "mongo" not in st.session_state and enable_mongo:
        st.session_state.mongo = get_mongo_client(settings.mongodb_uri, settings.mongodb_db)
    if "last_refresh" not in st.session_state:
        st.session_state.last_refresh = time.time()
    if "drift_report" not in st.session_state:
        st.session_state.drift_report = None
    if "pred_history" not in st.session_state:
        st.session_state.pred_history = []  # time-series accumulation
    if "neo4j" not in st.session_state and enable_neo4j:
        st.session_state.neo4j = get_neo_driver(settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)


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
    return [
        {
            "src_ip": f"10.0.0.{i+1}",
            "dst_ip": f"192.168.1.{(i*3)%255}",
            "src_port": 10000 + i,
            "dst_port": 443,
            "protocol": "TCP",
            "packet_count": 10 + i,
            "byte_count": 2048 + (i * 300),
            "timestamp": base_ts.isoformat() + "Z"
        } for i in range(n)
    ]


def run_dataset_mode():
    st.info("Dataset Mode active. Loading synthetic sample flows (placeholder for dataset selection UI).")
    flows = batch_sanitize(_dummy_flow_batch(12))
    preds = predict_flows(st.session_state.models, flows)
    # Ensure timestamp column is string for Arrow compatibility
    if 'timestamp' in preds.columns:
        preds['timestamp'] = preds['timestamp'].astype(str)
    _post_prediction_actions(preds)
    st.subheader("Sample Predictions")
    st.dataframe(preds, use_container_width=True)


def run_live_mode():
    st.warning("Live Capture Mode active.")
    packet_capture = st.session_state.packet_capture if enable_live_capture and 'packet_capture' in st.session_state else None
    flows = packet_capture.get_recent_flows(limit=80) if packet_capture else []
    if not flows:
        st.info("Using synthetic flows (live capture disabled or no packets yet).")
        flows = _dummy_flow_batch(5)
    flows = batch_sanitize(flows)
    preds = predict_flows(st.session_state.models, flows)
    if 'timestamp' in preds.columns:
        preds['timestamp'] = preds['timestamp'].astype(str)
    _post_prediction_actions(preds)
    st.subheader("Latest Live Predictions")
    st.dataframe(preds.tail(30), use_container_width=True)
    # Show capture mode (synthetic vs real)
    cap = st.session_state.packet_capture if 'packet_capture' in st.session_state else None
    if not enable_live_capture:
        st.caption("Live capture disabled (toggle in sidebar). Synthetic data in use.")
    else:
        cap = st.session_state.packet_capture if 'packet_capture' in st.session_state else None
        if cap and getattr(cap, '_synthetic_mode', False):
            st.caption("Packet capture fallback synthetic mode (driver/interface issue).")
        else:
            active_iface = st.session_state.get('_capture_iface') or 'Auto'
            st.caption(f"Live capture active on interface: {active_iface}")


def _post_prediction_actions(pred_df: pd.DataFrame):
    if pred_df is None or pred_df.empty:
        return
    st.session_state.last_predictions = pred_df
    # Append to history for time-series (truncate to 500)
    ts = int(time.time())
    for _, r in pred_df.iterrows():
        st.session_state.pred_history.append({"t": ts, "risk": r.get('risk_score', 0), "label": r.get('prediction')})
    if len(st.session_state.pred_history) > 500:
        st.session_state.pred_history = st.session_state.pred_history[-500:]
    # Blockchain logging for high severity
    if enable_chain and 'chain_contract' in st.session_state:
        severe = pred_df[pred_df['prediction'] == 'APT'].tail(5)
        for _, row in severe.iterrows():
            tx = log_threat_event(st.session_state.chain_contract, st.session_state.blockchain,
                             row.get('src_ip', 'n/a'), row.get('dst_ip', 'n/a'), 'High', 'Auto-logged high severity')
            if enable_mongo and 'mongo' in st.session_state:
                log_alert(st.session_state.mongo, {
                    'src_ip': row.get('src_ip'),
                    'dst_ip': row.get('dst_ip'),
                    'severity': 'High',
                    'prediction': 'APT',
                    'tx_hash': tx.get('tx_hash')
                })
    # Mongo logging (non-benign)
    if enable_mongo and 'mongo' in st.session_state:
        for _, row in pred_df.tail(10).iterrows():
            if row.get('prediction') != 'Benign':
                log_alert(st.session_state.mongo, row.to_dict())
    # Drift detection (compute on numeric subset)
    meta = st.session_state.models.get('meta', {}) if isinstance(st.session_state.models, dict) else {}
    feat_stats = meta.get('numeric_features') or meta.get('feature_stats', {})
    if isinstance(feat_stats, dict) and 'feature_stats' in meta:
        from ml_models.drift import detect_drift
        numeric_df = pred_df.select_dtypes(include=['number'])
        if not numeric_df.empty:
            st.session_state.drift_report = detect_drift(meta['feature_stats'], numeric_df)
    # Push to Neo4j
    if enable_neo4j and st.session_state.get('last_predictions') is not None:
        push_graph_to_neo4j(build_attack_graph(st.session_state.last_predictions), settings.neo4j_uri, settings.neo4j_user, settings.neo4j_password)


# --------------------------------------------------------------------------------------
# Tab: Dashboard
# --------------------------------------------------------------------------------------
with tab_dashboard:
    st.header("📊 Operational Dashboard")
    st.write("Real-time metrics & current detection status.")

    recent_alerts = fetch_recent_alerts(limit=50)
    high_sev = (recent_alerts['severity'] == 'High').sum() if 'severity' in recent_alerts else 0
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Monitored Hosts", int(recent_alerts['src_ip'].nunique()) if 'src_ip' in recent_alerts else 0)
    col2.metric("Alerts (buffer)", len(recent_alerts))
    col3.metric("High Severity", int(high_sev))
    col4.metric("Models Active", len(selected_models))

    st.markdown("### Mode Output")
    if run_mode == "Dataset Mode":
        run_dataset_mode()
    else:
        run_live_mode()

    # Metrics JSON if available
    meta = st.session_state.models.get('meta', {})
    if meta and 'metrics' in meta:
        st.markdown("### Model Performance Metrics")
        metrics_df = pd.DataFrame(meta['metrics']).T
        st.dataframe(metrics_df, use_container_width=True)
        if not metrics_df.empty:
            fig = px.bar(metrics_df.reset_index(), x='index', y='f1', title='Model F1 Scores')
            st.plotly_chart(fig, use_container_width=True)
    if st.session_state.drift_report:
        drifted = st.session_state.drift_report['summary']['drifted_features']
        if drifted:
            st.error(f"Drift detected in features: {', '.join(drifted)}")
        else:
            st.caption("No significant drift detected in latest batch.")
    # Time-series risk view
    if st.session_state.pred_history:
        hist_df = pd.DataFrame(st.session_state.pred_history)
        hist_df['dt'] = pd.to_datetime(hist_df['t'], unit='s')
        ts_fig = px.line(hist_df, x='dt', y='risk', title='Risk Score Timeline')
        st.plotly_chart(ts_fig, use_container_width=True)


# --------------------------------------------------------------------------------------
# Tab: Network Analysis (Graph)
# --------------------------------------------------------------------------------------
with tab_network:
    st.header("🌐 Network Attack Graph")
    st.write("Visual representation of host communication with risk overlays.")
    col_a, col_b = st.columns([1,1])
    if enable_neo4j and 'neo4j' in st.session_state:
        if col_a.button("Reload From Neo4j"):
            st.session_state._neo_cached = neo_fetch_graph(st.session_state.neo4j)
        if '_neo_cached' not in st.session_state:
            st.session_state._neo_cached = neo_fetch_graph(st.session_state.neo4j)
        g_db = st.session_state._neo_cached
        col_a.caption(f"Neo4j graph: {g_db.number_of_nodes()} nodes / {g_db.number_of_edges()} edges")
    else:
        col_a.caption("Neo4j disabled or not connected; showing in-memory predictions graph.")

    if 'last_predictions' in st.session_state:
        graph_local = build_attack_graph(st.session_state.last_predictions)
    else:
        graph_local = build_attack_graph(pd.DataFrame(_dummy_flow_batch(5)))

    source_choice = col_b.radio("Graph Source", ["In-Memory", "Neo4j" if enable_neo4j and 'neo4j' in st.session_state else "In-Memory"], horizontal=True)
    if source_choice == "Neo4j" and enable_neo4j and 'neo4j' in st.session_state:
        render_attack_graph(st.session_state._neo_cached)
    else:
        render_attack_graph(graph_local)


# --------------------------------------------------------------------------------------
# Tab: Threat Intelligence
# --------------------------------------------------------------------------------------
with tab_threat_intel:
    st.header("🧠 Threat Intelligence Feed")
    st.write("Aggregated recent alerts.")
    severity = None if severity_filter == 'All' else severity_filter
    alerts = query_alerts(st.session_state.get('mongo'), severity=severity, limit=200, last_minutes=recent_minutes)
    st.dataframe(alerts, use_container_width=True)


# --------------------------------------------------------------------------------------
# Tab: Blockchain Logs
# --------------------------------------------------------------------------------------
with tab_blockchain:
    st.header("⛓ Blockchain Event Log")
    if enable_chain and "blockchain" in st.session_state:
        events = fetch_recent_events(limit=25)
        st.dataframe(events, use_container_width=True)
    else:
        st.info("Blockchain logging disabled or not initialized.")


# --------------------------------------------------------------------------------------
# Footer
# --------------------------------------------------------------------------------------
st.markdown("---")
st.caption("APT Guardian • Enhanced prototype with live capture simulation, deep model hooks, blockchain & drift checks.")
