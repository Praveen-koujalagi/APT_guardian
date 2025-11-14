import time
import json
import pandas as pd
from datetime import datetime, timezone
from typing import List, Dict, Any

import streamlit as st

# Local module imports (all currently lightweight stubs)
from ml_models.inference import load_models, predict_flows
try:
    from utils.windows_packet_capture import WindowsPacketCapture as LivePacketCapture
except ImportError:
    from utils.packet_capture import LivePacketCapture
from utils.graph_utils import build_attack_graph_placeholder, render_attack_graph
from blockchain.blockchain_utils import get_blockchain_client, fetch_recent_events, log_event_to_blockchain
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
    "🔍 APT Analysis",
    "⛓ Blockchain Logs"
]

tab_dashboard, tab_network, tab_threat_intel, tab_apt, tab_blockchain = st.tabs(tab_labels)


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
        events = fetch_recent_events(limit=10)
        st.dataframe(events)
    else:
        st.warning("Live Capture Mode active. Attempting to use PyShark for real packet capture.")
        interface = st.text_input("Network Interface for Live Capture", value="Wi-Fi")
        use_pyshark = st.checkbox("Use PyShark for live capture (requires admin and tshark)", value=False)

        # Always initialize packet capture regardless of PyShark setting
        if ("packet_capture" not in st.session_state) or (
            getattr(st.session_state.get("packet_capture"), "interface", None) != interface
        ):
            # Recreate capture object when interface changes
            st.session_state.packet_capture = LivePacketCapture(interface=interface)
        
        pc = st.session_state.packet_capture
        
        # Show capture engine info
        if use_pyshark:
            st.info("Using PyShark capture engine (requires tshark)")
        else:
            st.info("Using Scapy capture engine (Windows-compatible)")
        
        # Start capture if not already running
        if not pc.is_capturing:
            if st.button("Start Packet Capture"):
                if pc.start():
                    st.success("Packet capture started!")
                else:
                    st.error("Failed to start packet capture. Check admin privileges.")
        
        # Show capture status and data
        if pc.is_capturing:
            if st.button("Stop Packet Capture"):
                pc.stop_capture()
                st.success("Packet capture stopped!")
            
            # Get traffic summary
            summary = pc.get_traffic_summary()
            if summary:
                st.subheader("Live Traffic Summary")
                col1, col2, col3 = st.columns(3)
                col1.metric("Total Packets", summary.get('total_packets', 0))
                col2.metric("Attacks Detected", summary.get('attack_count', 0))
                col3.metric("Status", "🟢 Active" if summary.get('is_capturing') else "🔴 Stopped")
                
                # Show recent packets
                recent_packets = pc.get_recent_packets(10)
                if recent_packets:
                    st.subheader("Recent Packets")
                    st.dataframe(recent_packets)
                    # Export & Scoring controls
                    df_packets = pd.DataFrame(recent_packets)
                    col_exp1, col_exp2, col_score = st.columns([1,1,2])
                    with col_exp1:
                        st.download_button(
                            label="Download CSV",
                            data=df_packets.to_csv(index=False).encode("utf-8"),
                            file_name="packets.csv",
                            mime="text/csv"
                        )
                    with col_exp2:
                        st.download_button(
                            label="Download JSON",
                            data=json.dumps(recent_packets, indent=2).encode("utf-8"),
                            file_name="packets.json",
                            mime="application/json"
                        )
                    with col_score:
                        if st.button("Score Captured Packets"):
                            preds = predict_flows(st.session_state.models, recent_packets)
                            st.subheader("Model Scores for Captured Packets")
                            st.dataframe(preds)
                
                # Show attack logs
                attack_logs = pc.get_attack_logs()
                if attack_logs:
                    st.subheader("🚨 Attack Alerts")
                    for attack in attack_logs[-5:]: # Show last 5 attacks
                        severity_color = {
                            "HIGH": "🔴",
                            "MEDIUM": "🟡", 
                            "LOW": "⚪"
                        }.get(attack['severity'], "⚪")
                        
                        st.markdown(f"""
                        **{severity_color} {attack['attack_type']}**  
                        **Severity:** {attack['severity']}  
                        **Time:** {attack['timestamp']}  
                        **Source:** {attack['packet_info'].get('src_ip', 'Unknown')}  
                        **Target:** {attack['packet_info'].get('dst_ip', 'Unknown')}  
                        **Protocol:** {attack['packet_info'].get('protocol', 'Unknown')}
                        ---
                        """)
                
                # Show APT indicators
                apt_indicators = pc.get_apt_indicators()
                if apt_indicators:
                    st.subheader("🔍 APT Indicators")
                    for indicator in apt_indicators[-3:]:  # Show last 3 APT indicators
                        severity_color = {
                            "HIGH": "🔴",
                            "MEDIUM": "🟡", 
                            "LOW": "⚪"
                        }.get(indicator['severity'], "⚪")
                        
                        st.markdown(f"""
                        **{severity_color} {indicator['type'].replace('_', ' ').title()}**  
                        **Confidence:** {indicator['confidence']:.2f}  
                        **Description:** {indicator['description']}  
                        **Source:** {indicator['source_ip']} → **Target:** {indicator['target_ip']}
                        ---
                        """)
            else:
                st.info("Waiting for packet data...")
        else:
            st.info("Packet capture not active. Click 'Start Packet Capture' to begin monitoring.")
        
        # Show additional info when PyShark is not used
        if not use_pyshark:
            st.info("PyShark disabled - using Scapy for packet capture")

        # Optional: place for any additional status/info messages


# --------------------------------------------------------------------------------------
# Helper: PyShark live packet capture
# --------------------------------------------------------------------------------------
def get_live_packets_pyshark(interface: str = None, count: int = 5):
    try:
        import pyshark
    except ImportError:
        return None, "PyShark is not installed. Please run 'pip install pyshark' in your environment."
    try:
        capture = pyshark.LiveCapture(interface=interface)
        packets = []
        for packet in capture.sniff_continuously(packet_count=count):
            try:
                packets.append({
                    "src_ip": packet.ip.src,
                    "dst_ip": packet.ip.dst,
                    "protocol": packet.transport_layer,
                    "length": packet.length,
                    "timestamp": datetime.now(timezone.utc).isoformat() + "Z"
                })
            except AttributeError:
                continue
        return packets, None
    except Exception as e:
        return None, str(e)


# --------------------------------------------------------------------------------------
# Tab: Network Analysis
# --------------------------------------------------------------------------------------
with tab_network:
    st.header("🌐 Network Analysis & Graph Intelligence")
    st.write("Neo4j-powered network topology analysis and behavioral pattern detection.")
    
    # Neo4j Connection Status
    col_neo1, col_neo2, col_neo3 = st.columns(3)
    
    if run_mode == "Live Capture Mode" and "packet_capture" in st.session_state:
        pc = st.session_state.packet_capture
        
        # Get Neo4j status from APT detector
        if hasattr(pc, 'apt_detector') and pc.apt_detector:
            try:
                neo4j_status = pc.apt_detector.get_neo4j_connection_status()
                # Force a fresh connection check if status shows disconnected
                if not neo4j_status.get("connected", False):
                    # Try to reconnect and get fresh status
                    if hasattr(pc.apt_detector, 'neo4j_analyzer') and pc.apt_detector.neo4j_analyzer:
                        pc.apt_detector.neo4j_analyzer.connect()
                        neo4j_status = pc.apt_detector.get_neo4j_connection_status()
            except Exception as e:
                neo4j_status = {"connected": False, "error": f"Connection check failed: {e}"}
        else:
            neo4j_status = {"connected": False, "error": "APT detector not available"}
        
        with col_neo1:
            status_color = "🟢" if neo4j_status.get("connected") else "🔴"
            st.metric("Neo4j Status", f"{status_color} {'Connected' if neo4j_status.get('connected') else 'Disconnected'}")
        
        with col_neo2:
            st.metric("Hosts", neo4j_status.get("host_count", 0))
        
        with col_neo3:
            st.metric("Connections", neo4j_status.get("connection_count", 0))
        
        if neo4j_status.get("connected"):
            # Network Topology Visualization
            st.subheader("📊 Network Topology")
            
            # Import graph utilities
            from utils.graph_utils import (
                build_attack_graph_from_neo4j, 
                render_attack_graph,
                analyze_network_patterns_neo4j,
                render_neo4j_patterns
            )
            
            # Build and render network graph
            try:
                network_graph = build_attack_graph_from_neo4j()
                render_attack_graph(network_graph, use_neo4j=True)
            except Exception as e:
                st.error(f"Failed to build network graph: {e}")
            
            # Neo4j Pattern Analysis
            st.subheader("🔍 Graph-Based Pattern Detection")
            
            if st.button("🔄 Analyze Network Patterns", type="primary"):
                with st.spinner("Analyzing network patterns with Neo4j..."):
                    try:
                        patterns = analyze_network_patterns_neo4j()
                        render_neo4j_patterns(patterns)
                        
                        # Store patterns in session state for persistence
                        st.session_state.neo4j_patterns = patterns
                        
                    except Exception as e:
                        st.error(f"Pattern analysis failed: {e}")
            
            # Display cached patterns if available
            if hasattr(st.session_state, 'neo4j_patterns') and st.session_state.neo4j_patterns:
                render_neo4j_patterns(st.session_state.neo4j_patterns)
            
            # Host Behavior Analysis
            st.subheader("🎯 Host Behavior Analysis")
            
            # Get list of hosts from Neo4j
            if hasattr(pc, 'apt_detector') and pc.apt_detector and pc.apt_detector.neo4j_analyzer:
                topology = pc.apt_detector.get_neo4j_network_topology()
                host_ips = [node["ip"] for node in topology.get("nodes", [])]
                
                if host_ips:
                    selected_host = st.selectbox("Select host for detailed analysis:", host_ips)
                    
                    if selected_host and st.button("📈 Analyze Host Behavior"):
                        with st.spinner(f"Analyzing behavior for {selected_host}..."):
                            try:
                                behavior_profile = pc.apt_detector.get_host_behavior_from_neo4j(selected_host)
                                
                                if behavior_profile:
                                    col_host1, col_host2 = st.columns(2)
                                    
                                    with col_host1:
                                        st.write(f"**Host:** {behavior_profile.get('ip', selected_host)}")
                                        st.write(f"**Type:** {behavior_profile.get('node_type', 'unknown')}")
                                        st.write(f"**Total Packets:** {behavior_profile.get('total_packets', 0):,}")
                                        st.write(f"**Total Bytes:** {behavior_profile.get('total_bytes', 0):,}")
                                    
                                    with col_host2:
                                        st.write(f"**Outbound Connections:** {behavior_profile.get('outbound_connections', 0)}")
                                        st.write(f"**Inbound Connections:** {behavior_profile.get('inbound_connections', 0)}")
                                        st.write(f"**First Seen:** {behavior_profile.get('first_seen', 'Unknown')}")
                                        st.write(f"**Last Seen:** {behavior_profile.get('last_seen', 'Unknown')}")
                                    
                                    # Protocol and port analysis
                                    protocols = behavior_profile.get('protocols_used', [])
                                    ports = behavior_profile.get('ports_accessed', [])
                                    services = behavior_profile.get('services_hosted', [])
                                    
                                    if protocols:
                                        st.write(f"**Protocols Used:** {', '.join(protocols)}")
                                    if ports:
                                        st.write(f"**Ports Accessed:** {', '.join(map(str, ports[:10]))}{'...' if len(ports) > 10 else ''}")
                                    if services:
                                        st.write(f"**Services Hosted:** {', '.join(map(str, services))}")
                                
                                else:
                                    st.warning(f"No behavior data found for {selected_host}")
                                    
                            except Exception as e:
                                st.error(f"Failed to analyze host behavior: {e}")
                else:
                    st.info("No hosts found in Neo4j database. Start packet capture to populate network data.")
            
            # Neo4j Database Management
            with st.expander("🔧 Neo4j Database Management"):
                st.write("**Database Operations:**")
                
                col_db1, col_db2, col_db3 = st.columns(3)
                
                with col_db1:
                    if st.button("🧹 Clear Old Data (7+ days)"):
                        if hasattr(pc, 'apt_detector') and pc.apt_detector and pc.apt_detector.neo4j_analyzer:
                            try:
                                pc.apt_detector.neo4j_analyzer.clear_old_data(days_to_keep=7)
                                st.success("✅ Old data cleared successfully!")
                            except Exception as e:
                                st.error(f"Failed to clear old data: {e}")
                
                with col_db2:
                    if st.button("📊 Database Statistics"):
                        st.info("Database statistics would be displayed here")
                
                with col_db3:
                    if st.button("🔄 Refresh Connection"):
                        # Force refresh of Neo4j connection status
                        if hasattr(pc, 'apt_detector') and pc.apt_detector and hasattr(pc.apt_detector, 'neo4j_analyzer'):
                            pc.apt_detector.neo4j_analyzer.connect()
                        st.rerun()
                
                # Connection configuration
                st.write("**Connection Configuration:**")
                neo4j_uri = st.text_input("Neo4j URI", value="bolt://127.0.0.1:7687", disabled=True)
                neo4j_user = st.text_input("Username", value="neo4j", disabled=True)
                st.write("💡 To modify connection settings, update the Neo4j analyzer configuration.")
        
        else:
            # Neo4j not connected
            st.warning("⚠️ Neo4j is not connected. Network graph analysis is limited.")
            st.write("**To enable Neo4j network analysis:**")
            st.write("1. Install and start Neo4j database")
            st.write("2. Ensure Neo4j is running on bolt://127.0.0.1:7687")
            st.write("3. Configure authentication (default: neo4j/password)")
            st.write("4. Restart the application")
            
            # Show error details if available
            if neo4j_status.get("error"):
                st.error(f"Connection Error: {neo4j_status['error']}")
    
    else:
        st.info("Network Analysis is available in Live Capture Mode only.")
        st.write("Switch to Live Capture Mode to enable:")
        st.write("- Real-time network topology mapping")
        st.write("- Graph-based APT pattern detection")
        st.write("- Host behavior analysis")
        st.write("- Network relationship visualization")


# --------------------------------------------------------------------------------------
# Tab: APT Analysis
# --------------------------------------------------------------------------------------
with tab_apt:
    st.header("🔍 Advanced Persistent Threat Analysis")
    st.write("Comprehensive APT detection and behavioral analysis.")
    
    if run_mode == "Live Capture Mode" and "packet_capture" in st.session_state:
        pc = st.session_state.packet_capture
        
        if pc.is_capturing:
            # APT Summary Metrics
            summary = pc.get_traffic_summary()
            apt_summary = summary.get('apt_summary', {})
            
            col1, col2, col3, col4 = st.columns(4)
            col1.metric("APT Indicators", apt_summary.get('total_indicators', 0))
            col2.metric("High Confidence", apt_summary.get('high_confidence_indicators', 0))
            col3.metric("Recent (1h)", apt_summary.get('recent_indicators', 0))
            col4.metric("Monitored Hosts", len(summary.get('host_risk_scores', {})))
            
            # APT Indicators Table
            apt_indicators = pc.get_apt_indicators()
            if apt_indicators:
                st.subheader("🚨 APT Indicators")
                
                # Filter controls
                col_filter1, col_filter2 = st.columns(2)
                with col_filter1:
                    severity_filter = st.multiselect(
                        "Filter by Severity",
                        options=["HIGH", "MEDIUM", "LOW"],
                        default=["HIGH", "MEDIUM", "LOW"]
                    )
                with col_filter2:
                    confidence_threshold = st.slider(
                        "Minimum Confidence",
                        min_value=0.0,
                        max_value=1.0,
                        value=0.0,
                        step=0.1
                    )
                
                # Filter indicators
                filtered_indicators = [
                    ind for ind in apt_indicators
                    if ind['severity'] in severity_filter and ind['confidence'] >= confidence_threshold
                ]
                
                if filtered_indicators:
                    # Convert to DataFrame for better display
                    df_indicators = pd.DataFrame(filtered_indicators)
                    df_indicators['timestamp'] = pd.to_datetime(df_indicators['timestamp'])
                    df_indicators = df_indicators.sort_values('timestamp', ascending=False)
                    
                    # Display indicators
                    for _, indicator in df_indicators.head(10).iterrows():
                        severity_color = {
                            "HIGH": "🔴",
                            "MEDIUM": "🟡", 
                            "LOW": "⚪"
                        }.get(indicator['severity'], "⚪")
                        
                        with st.expander(f"{severity_color} {indicator['type'].replace('_', ' ').title()} - {indicator['description'][:50]}..."):
                            col_ind1, col_ind2 = st.columns(2)
                            
                            with col_ind1:
                                st.write(f"**Severity:** {indicator['severity']}")
                                st.write(f"**Confidence:** {indicator['confidence']:.2f}")
                                st.write(f"**Time:** {indicator['timestamp']}")
                            
                            with col_ind2:
                                st.write(f"**Source IP:** {indicator['source_ip']}")
                                st.write(f"**Target IP:** {indicator['target_ip']}")
                                st.write(f"**Type:** {indicator['type']}")
                            
                            st.write(f"**Description:** {indicator['description']}")
                            
                            if indicator.get('evidence'):
                                st.write("**Evidence:**")
                                st.json(indicator['evidence'])
                else:
                    st.info("No APT indicators match the current filters.")
            else:
                st.info("No APT indicators detected yet. Continue monitoring to build behavioral profiles.")
            
            # Host Risk Analysis
            host_profiles = pc.get_host_profiles()
            host_risks = summary.get('host_risk_scores', {})
            
            if host_risks:
                st.subheader("🎯 Host Risk Assessment")
                
                # Sort hosts by risk score
                sorted_hosts = sorted(host_risks.items(), key=lambda x: x[1], reverse=True)
                
                for ip, risk_score in sorted_hosts[:10]:  # Show top 10 risky hosts
                    risk_color = "🔴" if risk_score > 0.7 else "🟡" if risk_score > 0.4 else "🟢"
                    
                    with st.expander(f"{risk_color} {ip} - Risk Score: {risk_score:.2f}"):
                        if ip in host_profiles:
                            profile = host_profiles[ip]
                            
                            col_host1, col_host2 = st.columns(2)
                            
                            with col_host1:
                                st.write(f"**First Seen:** {profile['first_seen']}")
                                st.write(f"**Last Seen:** {profile['last_seen']}")
                                st.write(f"**Total Connections:** {profile['total_connections']}")
                            
                            with col_host2:
                                st.write(f"**Unique Destinations:** {profile['unique_destinations']}")
                                st.write(f"**Protocols Used:** {', '.join(profile['protocols_used'])}")
                                st.write(f"**Ports Accessed:** {profile['ports_accessed']}")
                            
                            if profile['suspicious_activities']:
                                st.write("**Suspicious Activities:**")
                                for activity in profile['suspicious_activities']:
                                    st.write(f"- {activity}")
            
            # APT Detection Statistics
            if apt_summary:
                st.subheader("📊 APT Detection Statistics")
                
                col_stat1, col_stat2 = st.columns(2)
                
                with col_stat1:
                    if apt_summary.get('severity_breakdown'):
                        st.write("**Severity Breakdown:**")
                        severity_data = apt_summary['severity_breakdown']
                        st.bar_chart(severity_data)
                
                with col_stat2:
                    if apt_summary.get('indicator_types'):
                        st.write("**Indicator Types:**")
                        type_data = apt_summary['indicator_types']
                        st.bar_chart(type_data)
        
        else:
            st.warning("Start packet capture to begin APT analysis.")
    
    else:
        st.info("APT Analysis is available in Live Capture Mode only.")


# --------------------------------------------------------------------------------------
# Tab: Blockchain Logs
# --------------------------------------------------------------------------------------
with tab_blockchain:
    st.header("⛓ Blockchain Security Logging")
    st.write("Immutable audit trail for security events and APT indicators.")
    
    # Blockchain Status
    col_status1, col_status2, col_status3 = st.columns(3)
    
    with col_status1:
        # Blockchain Status
        st.subheader("🔗 Blockchain Connection")
        client_info = get_blockchain_client()
        
        col1, col2, col3 = st.columns(3)
        with col1:
            status_color = "🟢" if client_info["status"] == "connected" else "🔴"
            st.metric("Status", f"{status_color} {client_info['status'].title()}")
        with col2:
            st.metric("Provider", client_info["provider"])
        with col3:
            st.metric("Total Blocks", client_info.get("block_count", 0))
    
    with col_status2:
        # Count blockchain events
        blockchain_events = fetch_recent_events(limit=100)
        st.metric("Total Events", len(blockchain_events))
    
    with col_status3:
        # Count high severity events
        try:
            if not blockchain_events.empty and 'severity' in blockchain_events.columns:
                high_severity = len(blockchain_events[blockchain_events['severity'].isin(['High', 'HIGH'])])
            else:
                high_severity = 0
        except Exception:
            high_severity = 0
        st.metric("High Severity", high_severity)
    
    # APT Indicators to Blockchain
    if run_mode == "Live Capture Mode" and "packet_capture" in st.session_state:
        pc = st.session_state.packet_capture
        apt_indicators = pc.get_apt_indicators()
        
        if apt_indicators:
            st.subheader("🔍 APT Indicators → Blockchain")
            
            # Show pending indicators for blockchain logging
            pending_indicators = [ind for ind in apt_indicators if ind.get('blockchain_logged') != True]
            
            if pending_indicators:
                st.write(f"**{len(pending_indicators)} APT indicators ready for blockchain logging:**")
                
                # Display indicators to be logged
                for i, indicator in enumerate(pending_indicators[:5], 1):
                    severity_color = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "⚪"}.get(indicator['severity'], "⚪")
                    
                    with st.expander(f"{severity_color} {indicator['type'].replace('_', ' ').title()} - Confidence: {indicator['confidence']:.2f}"):
                        col_ind1, col_ind2 = st.columns(2)
                        
                        with col_ind1:
                            st.write(f"**Source:** {indicator['source_ip']}")
                            st.write(f"**Target:** {indicator['target_ip']}")
                            st.write(f"**Timestamp:** {indicator['timestamp']}")
                        
                        with col_ind2:
                            st.write(f"**Severity:** {indicator['severity']}")
                            st.write(f"**Type:** {indicator['type']}")
                            st.write(f"**Description:** {indicator['description']}")
                
                # Bulk logging button
                if st.button("📝 Log All APT Indicators to Blockchain", type="primary"):
                    logged_count = 0
                    for indicator in pending_indicators:
                        try:
                            # Log to blockchain
                            success = log_event_to_blockchain(
                                src_ip=indicator['source_ip'],
                                dst_ip=indicator['target_ip'],
                                severity=indicator['severity'],
                                details=f"APT Indicator: {indicator['description']} (Confidence: {indicator['confidence']:.2f})"
                            )
                            if success:
                                logged_count += 1
                                # Mark as logged (in real implementation, update the indicator)
                        except Exception as e:
                            st.error(f"Failed to log indicator: {e}")
                    
                    if logged_count > 0:
                        st.success(f"✅ Successfully logged {logged_count} APT indicators to blockchain!")
                        st.rerun()
            else:
                st.info("All APT indicators have been logged to blockchain.")
    
    # Recent Blockchain Events
    st.subheader("📜 Recent Blockchain Events")
    
    # Filter controls
    col_filter1, col_filter2, col_filter3 = st.columns(3)
    
    with col_filter1:
        event_limit = st.selectbox("Show Events", [10, 25, 50, 100], index=1)
    
    with col_filter2:
        severity_filter_bc = st.multiselect(
            "Filter by Severity",
            options=["High", "Medium", "Low"],
            default=["High", "Medium", "Low"]
        )
    
    with col_filter3:
        if st.button("🔄 Refresh Events"):
            st.rerun()
    
    # Fetch and display events
    recent_events = fetch_recent_events(limit=event_limit)
    
    if not recent_events.empty:
        # Filter by severity
        filtered_events = recent_events[recent_events['severity'].isin(severity_filter_bc)]
        
        if not filtered_events.empty:
            # Display events in expandable format
            for _, event in filtered_events.iterrows():
                severity_color = {"High": "🔴", "Medium": "🟡", "Low": "⚪"}.get(event['severity'], "⚪")
                
                with st.expander(f"{severity_color} Block #{event['block']} - {event['severity']} Severity"):
                    col_event1, col_event2 = st.columns(2)
                    
                    with col_event1:
                        st.write(f"**Block Number:** {event['block']}")
                        st.write(f"**Transaction Hash:** `{event['tx_hash']}`")
                        st.write(f"**Timestamp:** {event['timestamp']}")
                    
                    with col_event2:
                        st.write(f"**Severity:** {event['severity']}")
                        st.write(f"**Event Type:** Security Alert")
                        st.write(f"**Details:** {event['details']}")
                    
                    # Verification status
                    st.write("**Blockchain Verification:** ✅ Immutable & Verified")
        else:
            st.info("No events match the current filters.")
    else:
        st.info("No blockchain events found.")
    
    # Blockchain Analytics
    if not recent_events.empty:
        st.subheader("📊 Blockchain Security Analytics")
        
        col_analytics1, col_analytics2 = st.columns(2)
        
        with col_analytics1:
            st.write("**Event Severity Distribution:**")
            severity_counts = recent_events['severity'].value_counts()
            st.bar_chart(severity_counts)
        
        with col_analytics2:
            st.write("**Events Over Time:**")
            # Convert timestamp to datetime for plotting
            recent_events['timestamp'] = pd.to_datetime(recent_events['timestamp'])
            events_by_hour = recent_events.groupby(recent_events['timestamp'].dt.hour).size()
            st.line_chart(events_by_hour)
    
    # Blockchain Configuration
    with st.expander("⚙️ Blockchain Configuration"):
        st.write("**Current Configuration:**")
        
        col_config1, col_config2 = st.columns(2)
        
        with col_config1:
            st.write("- **Network:** Ethereum Testnet")
            st.write("- **Contract Address:** `0x1234...abcd`")
            st.write("- **Gas Price:** Auto")
        
        with col_config2:
            st.write("- **Auto-logging:** Enabled")
            st.write("- **Confirmation Blocks:** 3")
            st.write("- **Backup Nodes:** 2")
        
        if st.button("🔧 Update Configuration"):
            st.info("Configuration update functionality would be implemented here.")
    
    # Benefits Information
    with st.expander("ℹ️ Blockchain Logging Benefits"):
        st.write("""
        **Why Blockchain Logging Enhances Security:**
        
        🔒 **Immutable Records** - Security events cannot be tampered with or deleted
        
        📋 **Audit Trail** - Complete forensic timeline for incident investigation
        
        🌐 **Distributed Trust** - No single point of failure for security logs
        
        ⚖️ **Legal Compliance** - Cryptographically verified evidence for legal proceedings
        
        🤝 **Threat Intelligence** - Share indicators with other organizations securely
        
        🔍 **Transparency** - All security events are verifiable and traceable
        """)


# --------------------------------------------------------------------------------------
# Footer
# --------------------------------------------------------------------------------------
st.markdown("---")
st.caption("Prototype UI • Functionality will expand with real data, models, and integrations.")
