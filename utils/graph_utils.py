"""Graph utilities with Neo4j integration for network analysis."""
from __future__ import annotations
import networkx as nx
import streamlit as st
from typing import Dict, Any, Optional
import pandas as pd

from .neo4j_network_analyzer import get_neo4j_analyzer, Neo4jNetworkAnalyzer


def build_attack_graph_from_neo4j(analyzer: Optional[Neo4jNetworkAnalyzer] = None) -> nx.DiGraph:
    """Build attack graph from Neo4j network data."""
    if analyzer is None:
        analyzer = get_neo4j_analyzer()
    
    if not analyzer.connected:
        return build_attack_graph_placeholder()
    
    # Get network topology from Neo4j
    topology = analyzer.get_network_topology(limit=200)
    
    # Create NetworkX graph
    g = nx.DiGraph()
    
    # Add nodes
    for node in topology["nodes"]:
        node_id = node["ip"]
        g.add_node(node_id, **{
            "type": node.get("type", "unknown"),
            "packet_count": node.get("packet_count", 0),
            "byte_count": node.get("byte_count", 0),
            "first_seen": node.get("first_seen"),
            "last_seen": node.get("last_seen")
        })
    
    # Add edges
    for rel in topology["relationships"]:
        source = rel["source"]
        target = rel["target"]
        
        # Determine edge severity based on traffic patterns
        packet_count = rel.get("packet_count", 0)
        byte_count = rel.get("byte_count", 0)
        
        severity = "Low"
        if packet_count > 1000 or byte_count > 1000000:  # 1MB
            severity = "High"
        elif packet_count > 100 or byte_count > 100000:  # 100KB
            severity = "Medium"
        
        g.add_edge(source, target, **{
            "protocol": rel.get("protocol", "unknown"),
            "port": rel.get("port", 0),
            "packet_count": packet_count,
            "byte_count": byte_count,
            "severity": severity
        })
    
    return g


def build_attack_graph_placeholder():
    """Fallback placeholder graph when Neo4j is not available."""
    g = nx.DiGraph()
    g.add_edge("Attacker", "HostA", severity="High")
    g.add_edge("Attacker", "HostB", severity="Medium")
    g.add_edge("HostA", "DBServer", severity="High")
    return g


def render_attack_graph(graph: nx.DiGraph, use_neo4j: bool = True):
    """Render attack graph with enhanced Neo4j-powered visualization."""
    if not graph.nodes():
        st.warning("No network data available for visualization.")
        return
    
    st.subheader("🌐 Network Topology Analysis")
    
    # Display graph statistics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Nodes", len(graph.nodes()))
    col2.metric("Connections", len(graph.edges()))
    col3.metric("High Severity", len([e for _, _, d in graph.edges(data=True) if d.get('severity') == 'High']))
    col4.metric("External Nodes", len([n for n, d in graph.nodes(data=True) if d.get('type') == 'external']))
    
    # Network analysis tabs
    tab1, tab2, tab3 = st.tabs(["📊 Graph Overview", "🔍 Node Analysis", "⚠️ Suspicious Patterns"])
    
    with tab1:
        # Graph edges table
        st.write("**Network Connections:**")
        edges_data = []
        for u, v, data in graph.edges(data=True):
            edges_data.append({
                "Source": u,
                "Target": v,
                "Protocol": data.get("protocol", "unknown"),
                "Port": data.get("port", 0),
                "Packets": data.get("packet_count", 0),
                "Bytes": data.get("byte_count", 0),
                "Severity": data.get("severity", "Low")
            })
        
        if edges_data:
            df_edges = pd.DataFrame(edges_data)
            st.dataframe(df_edges, use_container_width=True)
        
        # Network statistics
        st.write("**Network Statistics:**")
        if len(graph.nodes()) > 0:
            # Calculate centrality measures
            try:
                degree_centrality = nx.degree_centrality(graph)
                betweenness_centrality = nx.betweenness_centrality(graph)
                
                centrality_data = []
                for node in graph.nodes():
                    centrality_data.append({
                        "Node": node,
                        "Degree Centrality": f"{degree_centrality.get(node, 0):.3f}",
                        "Betweenness Centrality": f"{betweenness_centrality.get(node, 0):.3f}",
                        "Type": graph.nodes[node].get("type", "unknown")
                    })
                
                df_centrality = pd.DataFrame(centrality_data)
                st.dataframe(df_centrality, use_container_width=True)
                
            except Exception as e:
                st.error(f"Error calculating network metrics: {e}")
    
    with tab2:
        # Node selection for detailed analysis
        selected_node = st.selectbox("Select node for analysis:", list(graph.nodes()))
        
        if selected_node:
            node_data = graph.nodes[selected_node]
            
            col_node1, col_node2 = st.columns(2)
            
            with col_node1:
                st.write(f"**Node:** {selected_node}")
                st.write(f"**Type:** {node_data.get('type', 'unknown')}")
                st.write(f"**Packet Count:** {node_data.get('packet_count', 0):,}")
                st.write(f"**Byte Count:** {node_data.get('byte_count', 0):,}")
            
            with col_node2:
                # Connections analysis
                in_degree = graph.in_degree(selected_node)
                out_degree = graph.out_degree(selected_node)
                
                st.write(f"**Incoming Connections:** {in_degree}")
                st.write(f"**Outgoing Connections:** {out_degree}")
                st.write(f"**Total Degree:** {in_degree + out_degree}")
            
            # Show connected nodes
            neighbors = list(graph.neighbors(selected_node))
            predecessors = list(graph.predecessors(selected_node))
            
            if neighbors:
                st.write(f"**Outgoing Connections ({len(neighbors)}):**")
                for neighbor in neighbors[:10]:  # Show first 10
                    edge_data = graph[selected_node][neighbor]
                    st.write(f"→ {neighbor} ({edge_data.get('protocol', 'unknown')}:{edge_data.get('port', 0)})")
            
            if predecessors:
                st.write(f"**Incoming Connections ({len(predecessors)}):**")
                for pred in predecessors[:10]:  # Show first 10
                    edge_data = graph[pred][selected_node]
                    st.write(f"← {pred} ({edge_data.get('protocol', 'unknown')}:{edge_data.get('port', 0)})")
    
    with tab3:
        # Suspicious pattern analysis
        st.write("**Suspicious Network Patterns:**")
        
        # High degree nodes (potential C2 or compromised hosts)
        high_degree_nodes = [(node, graph.degree(node)) for node in graph.nodes()]
        high_degree_nodes.sort(key=lambda x: x[1], reverse=True)
        
        if high_degree_nodes:
            st.write("**High-Degree Nodes (Potential C2 or Hub Nodes):**")
            for node, degree in high_degree_nodes[:5]:
                node_type = graph.nodes[node].get('type', 'unknown')
                severity = "🔴" if degree > 10 else "🟡" if degree > 5 else "🟢"
                st.write(f"{severity} {node} ({node_type}) - {degree} connections")
        
        # External connections from internal hosts
        external_connections = []
        for u, v, data in graph.edges(data=True):
            u_type = graph.nodes[u].get('type', 'unknown')
            v_type = graph.nodes[v].get('type', 'unknown')
            
            if u_type == 'internal' and v_type == 'external':
                external_connections.append((u, v, data))
        
        if external_connections:
            st.write("**Internal → External Connections:**")
            for src, dst, data in external_connections[:10]:
                severity_color = {"High": "🔴", "Medium": "🟡", "Low": "🟢"}.get(data.get('severity', 'Low'), "🟢")
                st.write(f"{severity_color} {src} → {dst} ({data.get('protocol', 'unknown')}:{data.get('port', 0)})")


def analyze_network_patterns_neo4j(analyzer: Optional[Neo4jNetworkAnalyzer] = None) -> Dict[str, Any]:
    """Analyze network patterns using Neo4j queries."""
    if analyzer is None:
        analyzer = get_neo4j_analyzer()
    
    if not analyzer.connected:
        return {"error": "Neo4j not connected"}
    
    patterns = {}
    
    # Detect various APT patterns
    patterns["beaconing"] = analyzer.detect_beaconing_patterns()
    patterns["lateral_movement"] = analyzer.detect_lateral_movement()
    patterns["data_exfiltration"] = analyzer.detect_data_exfiltration()
    patterns["port_scanning"] = analyzer.detect_port_scanning()
    
    return patterns


def render_neo4j_patterns(patterns: Dict[str, Any]):
    """Render Neo4j-detected patterns in Streamlit."""
    if not patterns or "error" in patterns:
        st.error("Unable to analyze network patterns. Check Neo4j connection.")
        return
    
    st.subheader("🔍 APT Pattern Detection (Neo4j)")
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Beaconing", len(patterns.get("beaconing", [])))
    col2.metric("Lateral Movement", len(patterns.get("lateral_movement", [])))
    col3.metric("Data Exfiltration", len(patterns.get("data_exfiltration", [])))
    col4.metric("Port Scanning", len(patterns.get("port_scanning", [])))
    
    # Pattern details
    for pattern_type, pattern_list in patterns.items():
        if pattern_list:
            with st.expander(f"🚨 {pattern_type.replace('_', ' ').title()} ({len(pattern_list)} detected)"):
                for i, pattern in enumerate(pattern_list[:5], 1):  # Show first 5
                    st.write(f"**{i}. {pattern.get('source_ip', 'Unknown')} → {pattern.get('target_ip', 'Multiple')}**")
                    
                    if pattern_type == "beaconing":
                        st.write(f"   - Connections: {pattern.get('connections', 0)}")
                        st.write(f"   - Duration: {pattern.get('duration_seconds', 0)} seconds")
                        st.write(f"   - Protocol: {pattern.get('protocol', 'unknown')}:{pattern.get('port', 0)}")
                    
                    elif pattern_type == "lateral_movement":
                        st.write(f"   - Targets: {pattern.get('target_count', 0)}")
                        st.write(f"   - Target IPs: {', '.join(pattern.get('targets', [])[:3])}...")
                    
                    elif pattern_type == "data_exfiltration":
                        bytes_mb = pattern.get('bytes_transferred', 0) / (1024 * 1024)
                        st.write(f"   - Data: {bytes_mb:.1f} MB")
                        st.write(f"   - Packets: {pattern.get('packet_count', 0)}")
                        st.write(f"   - Protocol: {pattern.get('protocol', 'unknown')}:{pattern.get('port', 0)}")
                    
                    elif pattern_type == "port_scanning":
                        st.write(f"   - Unique Ports: {pattern.get('unique_ports', 0)}")
                        st.write(f"   - Sample Ports: {', '.join(map(str, pattern.get('sample_ports', [])[:5]))}")
                    
                    st.write("---")
