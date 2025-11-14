"""Neo4j Network Analysis Module for APT Guardian.

This module provides comprehensive network analysis capabilities using Neo4j
for modeling packet relationships, network topology, and behavioral patterns.
"""

from __future__ import annotations
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass
import json
import logging
from collections import defaultdict

try:
    from neo4j import GraphDatabase, Driver
    from neo4j.exceptions import ServiceUnavailable, AuthError
except ImportError:
    GraphDatabase = None
    Driver = None


@dataclass
class NetworkNode:
    """Represents a network node (host, service, etc.)."""
    ip: str
    node_type: str  # 'host', 'service', 'external'
    first_seen: datetime
    last_seen: datetime
    properties: Dict[str, Any]


@dataclass
class NetworkRelationship:
    """Represents a network relationship between nodes."""
    source_ip: str
    target_ip: str
    relationship_type: str  # 'CONNECTS_TO', 'ATTACKS', 'COMMUNICATES_WITH'
    protocol: str
    port: int
    packet_count: int
    byte_count: int
    first_seen: datetime
    last_seen: datetime
    properties: Dict[str, Any]


class Neo4jNetworkAnalyzer:
    """Neo4j-powered network analysis for APT detection."""
    
    def __init__(self, uri: str = "bolt://127.0.0.1:7687", 
                 username: str = "neo4j", 
                 password: str = "VNPS6437"):
        """Initialize Neo4j connection."""
        self.uri = uri
        self.username = username
        self.password = password
        self.driver: Optional[Driver] = None
        self.logger = logging.getLogger(__name__)
        
        # Connection status
        self.connected = False
        
        # Initialize connection
        self.connect()
        
        # Create constraints and indexes
        if self.connected:
            self._create_schema()
    
    def connect(self) -> bool:
        """Establish connection to Neo4j database."""
        if not GraphDatabase:
            self.logger.error("Neo4j driver not available. Install with: pip install neo4j")
            return False
        
        try:
            self.driver = GraphDatabase.driver(
                self.uri, 
                auth=(self.username, self.password)
            )
            
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            
            self.connected = True
            self.logger.info(f"Connected to Neo4j at {self.uri}")
            return True
            
        except (ServiceUnavailable, AuthError) as e:
            self.logger.error(f"Failed to connect to Neo4j: {e}")
            self.connected = False
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error connecting to Neo4j: {e}")
            self.connected = False
            return False
    
    def disconnect(self):
        """Close Neo4j connection."""
        if self.driver:
            self.driver.close()
            self.connected = False
            self.logger.info("Disconnected from Neo4j")
    
    def _create_schema(self):
        """Create Neo4j schema (constraints and indexes)."""
        if not self.connected:
            return
        
        schema_queries = [
            # Constraints
            "CREATE CONSTRAINT host_ip IF NOT EXISTS FOR (h:Host) REQUIRE h.ip IS UNIQUE",
            "CREATE CONSTRAINT service_id IF NOT EXISTS FOR (s:Service) REQUIRE s.service_id IS UNIQUE",
            "CREATE CONSTRAINT packet_id IF NOT EXISTS FOR (p:Packet) REQUIRE p.packet_id IS UNIQUE",
            
            # Indexes for performance
            "CREATE INDEX host_last_seen IF NOT EXISTS FOR (h:Host) ON (h.last_seen)",
            "CREATE INDEX packet_timestamp IF NOT EXISTS FOR (p:Packet) ON (p.timestamp)",
            "CREATE INDEX connection_timestamp IF NOT EXISTS FOR ()-[c:CONNECTS_TO]-() ON (c.timestamp)",
            "CREATE INDEX attack_severity IF NOT EXISTS FOR ()-[a:ATTACKS]-() ON (a.severity)"
        ]
        
        with self.driver.session() as session:
            for query in schema_queries:
                try:
                    session.run(query)
                except Exception as e:
                    # Constraints might already exist
                    self.logger.debug(f"Schema query failed (might already exist): {e}")
    
    def ingest_packet_batch(self, packets: List[Dict[str, Any]]) -> bool:
        """Ingest a batch of packets into Neo4j."""
        if not self.connected:
            return False
        
        try:
            with self.driver.session() as session:
                # Process packets in transaction
                session.execute_write(self._process_packet_batch, packets)
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to ingest packet batch: {e}")
            return False
    
    def _process_packet_batch(self, tx, packets: List[Dict[str, Any]]):
        """Process packet batch in Neo4j transaction."""
        for packet in packets:
            self._create_packet_relationships(tx, packet)
    
    def _create_packet_relationships(self, tx, packet: Dict[str, Any]):
        """Create packet relationships in Neo4j."""
        src_ip = packet.get('src_ip')
        dst_ip = packet.get('dst_ip')
        
        print(f"🔍 Processing packet: {src_ip} -> {dst_ip}")
        
        if not src_ip or not dst_ip:
            print(f"⚠️ Skipping packet - missing IPs: src={src_ip}, dst={dst_ip}")
            return
        
        timestamp = packet.get('timestamp', datetime.now(timezone.utc).isoformat())
        protocol = packet.get('protocol', 'UNKNOWN')
        dst_port = packet.get('dst_port', 0)
        length = packet.get('length', 0)
        
        # Create or update source host
        tx.run("""
            MERGE (src:Host {ip: $src_ip})
            ON CREATE SET 
                src.first_seen = datetime($timestamp),
                src.node_type = CASE 
                    WHEN $src_ip STARTS WITH '192.168.' OR 
                         $src_ip STARTS WITH '10.' OR 
                         $src_ip STARTS WITH '172.' THEN 'internal'
                    ELSE 'external'
                END,
                src.packet_count = 1,
                src.byte_count = $length
            ON MATCH SET 
                src.last_seen = datetime($timestamp),
                src.packet_count = src.packet_count + 1,
                src.byte_count = src.byte_count + $length
        """, src_ip=src_ip, timestamp=timestamp, length=length)
        
        # Create or update destination host
        tx.run("""
            MERGE (dst:Host {ip: $dst_ip})
            ON CREATE SET 
                dst.first_seen = datetime($timestamp),
                dst.node_type = CASE 
                    WHEN $dst_ip STARTS WITH '192.168.' OR 
                         $dst_ip STARTS WITH '10.' OR 
                         $dst_ip STARTS WITH '172.' THEN 'internal'
                    ELSE 'external'
                END,
                dst.packet_count = 0,
                dst.byte_count = 0
            ON MATCH SET 
                dst.last_seen = datetime($timestamp)
        """, dst_ip=dst_ip, timestamp=timestamp)
        
        # Create service node for destination port
        if dst_port > 0:
            tx.run("""
                MERGE (svc:Service {service_id: $service_id})
                ON CREATE SET 
                    svc.port = $port,
                    svc.protocol = $protocol,
                    svc.first_seen = datetime($timestamp)
                ON MATCH SET 
                    svc.last_seen = datetime($timestamp)
            """, service_id=f"{dst_ip}:{dst_port}", port=dst_port, protocol=protocol, timestamp=timestamp)
            
            # Connect destination host to service
            tx.run("""
                MATCH (dst:Host {ip: $dst_ip})
                MATCH (svc:Service {service_id: $service_id})
                MERGE (dst)-[r:HOSTS_SERVICE]->(svc)
                ON CREATE SET r.first_seen = datetime($timestamp)
                ON MATCH SET r.last_seen = datetime($timestamp)
            """, dst_ip=dst_ip, service_id=f"{dst_ip}:{dst_port}", timestamp=timestamp)
        
        # Create connection relationship
        tx.run("""
            MATCH (src:Host {ip: $src_ip})
            MATCH (dst:Host {ip: $dst_ip})
            MERGE (src)-[r:CONNECTS_TO {protocol: $protocol, port: $port}]->(dst)
            ON CREATE SET 
                r.first_seen = datetime($timestamp),
                r.packet_count = 1,
                r.byte_count = $length,
                r.suspicious = false
            ON MATCH SET 
                r.last_seen = datetime($timestamp),
                r.packet_count = r.packet_count + 1,
                r.byte_count = r.byte_count + $length
        """, src_ip=src_ip, dst_ip=dst_ip, protocol=protocol, port=dst_port, 
             timestamp=timestamp, length=length)
    
    def detect_beaconing_patterns(self, time_window_hours: int = 24) -> List[Dict[str, Any]]:
        """Detect beaconing patterns using Neo4j graph queries."""
        if not self.connected:
            return []
        
        query = """
        MATCH (src:Host)-[r:CONNECTS_TO]->(dst:Host)
        WHERE r.last_seen >= datetime() - duration({hours: $hours})
        AND r.packet_count >= 10
        WITH src, dst, r, 
             r.packet_count as connections,
             duration.between(r.first_seen, r.last_seen).seconds as duration_seconds
        WHERE duration_seconds > 0 AND connections/duration_seconds < 0.1  // Regular intervals
        RETURN src.ip as source_ip, 
               dst.ip as target_ip,
               r.protocol as protocol,
               r.port as port,
               connections,
               duration_seconds,
               r.first_seen as first_seen,
               r.last_seen as last_seen
        ORDER BY connections DESC
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, hours=time_window_hours)
                return [dict(record) for record in result]
        except Exception as e:
            self.logger.error(f"Failed to detect beaconing patterns: {e}")
            return []
    
    def detect_lateral_movement(self, threshold: int = 5) -> List[Dict[str, Any]]:
        """Detect lateral movement patterns."""
        if not self.connected:
            return []
        
        query = """
        MATCH (src:Host {node_type: 'internal'})-[r:CONNECTS_TO]->(dst:Host {node_type: 'internal'})
        WHERE r.port IN [22, 23, 135, 139, 445, 3389, 5985, 5986]  // Admin ports
        WITH src, count(DISTINCT dst) as target_count, collect(DISTINCT dst.ip) as targets
        WHERE target_count >= $threshold
        RETURN src.ip as source_ip,
               target_count,
               targets,
               'LATERAL_MOVEMENT' as pattern_type
        ORDER BY target_count DESC
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, threshold=threshold)
                return [dict(record) for record in result]
        except Exception as e:
            self.logger.error(f"Failed to detect lateral movement: {e}")
            return []
    
    def detect_data_exfiltration(self, byte_threshold: int = 10485760) -> List[Dict[str, Any]]:
        """Detect potential data exfiltration (large outbound transfers)."""
        if not self.connected:
            return []
        
        query = """
        MATCH (src:Host {node_type: 'internal'})-[r:CONNECTS_TO]->(dst:Host {node_type: 'external'})
        WHERE r.byte_count >= $threshold
        RETURN src.ip as source_ip,
               dst.ip as target_ip,
               r.byte_count as bytes_transferred,
               r.packet_count as packet_count,
               r.protocol as protocol,
               r.port as port,
               r.first_seen as first_seen,
               r.last_seen as last_seen,
               'DATA_EXFILTRATION' as pattern_type
        ORDER BY r.byte_count DESC
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, threshold=byte_threshold)
                return [dict(record) for record in result]
        except Exception as e:
            self.logger.error(f"Failed to detect data exfiltration: {e}")
            return []
    
    def detect_port_scanning(self, port_threshold: int = 20) -> List[Dict[str, Any]]:
        """Detect port scanning activities."""
        if not self.connected:
            return []
        
        query = """
        MATCH (src:Host)-[r:CONNECTS_TO]->(dst:Host)
        WITH src, dst, count(DISTINCT r.port) as unique_ports, collect(DISTINCT r.port) as ports
        WHERE unique_ports >= $threshold
        RETURN src.ip as source_ip,
               dst.ip as target_ip,
               unique_ports,
               ports[0..10] as sample_ports,  // First 10 ports
               'PORT_SCANNING' as pattern_type
        ORDER BY unique_ports DESC
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, threshold=port_threshold)
                return [dict(record) for record in result]
        except Exception as e:
            self.logger.error(f"Failed to detect port scanning: {e}")
            return []
    
    def get_network_topology(self, limit: int = 100) -> Dict[str, Any]:
        """Get network topology for visualization."""
        if not self.connected:
            return {"nodes": [], "relationships": []}
        
        # Get nodes
        nodes_query = """
        MATCH (h:Host)
        RETURN h.ip as ip, 
               h.node_type as type,
               h.packet_count as packet_count,
               h.byte_count as byte_count,
               h.first_seen as first_seen,
               h.last_seen as last_seen
        LIMIT $limit
        """
        
        # Get relationships
        relationships_query = """
        MATCH (src:Host)-[r:CONNECTS_TO]->(dst:Host)
        RETURN src.ip as source,
               dst.ip as target,
               r.protocol as protocol,
               r.port as port,
               r.packet_count as packet_count,
               r.byte_count as byte_count
        LIMIT $limit
        """
        
        try:
            with self.driver.session() as session:
                nodes_result = session.run(nodes_query, limit=limit)
                relationships_result = session.run(relationships_query, limit=limit)
                
                return {
                    "nodes": [dict(record) for record in nodes_result],
                    "relationships": [dict(record) for record in relationships_result]
                }
        except Exception as e:
            self.logger.error(f"Failed to get network topology: {e}")
            return {"nodes": [], "relationships": []}
    
    def get_host_behavior_profile(self, ip: str) -> Dict[str, Any]:
        """Get detailed behavioral profile for a specific host."""
        if not self.connected:
            return {}
        
        query = """
        MATCH (h:Host {ip: $ip})
        OPTIONAL MATCH (h)-[out:CONNECTS_TO]->(dst:Host)
        OPTIONAL MATCH (src:Host)-[in:CONNECTS_TO]->(h)
        OPTIONAL MATCH (h)-[:HOSTS_SERVICE]->(svc:Service)
        
        RETURN h.ip as ip,
               h.node_type as node_type,
               h.packet_count as total_packets,
               h.byte_count as total_bytes,
               h.first_seen as first_seen,
               h.last_seen as last_seen,
               count(DISTINCT dst) as outbound_connections,
               count(DISTINCT src) as inbound_connections,
               collect(DISTINCT out.protocol) as protocols_used,
               collect(DISTINCT out.port) as ports_accessed,
               collect(DISTINCT svc.port) as services_hosted
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, ip=ip)
                record = result.single()
                return dict(record) if record else {}
        except Exception as e:
            self.logger.error(f"Failed to get host profile for {ip}: {e}")
            return {}
    
    def mark_suspicious_activity(self, source_ip: str, target_ip: str, 
                               activity_type: str, severity: str = "MEDIUM"):
        """Mark suspicious activity in the graph."""
        if not self.connected:
            return
        
        query = """
        MATCH (src:Host {ip: $src_ip})-[r:CONNECTS_TO]->(dst:Host {ip: $dst_ip})
        SET r.suspicious = true,
            r.activity_type = $activity_type,
            r.severity = $severity,
            r.flagged_at = datetime()
        """
        
        try:
            with self.driver.session() as session:
                session.run(query, src_ip=source_ip, dst_ip=target_ip, 
                           activity_type=activity_type, severity=severity)
        except Exception as e:
            self.logger.error(f"Failed to mark suspicious activity: {e}")
    
    def get_connection_status(self) -> Dict[str, Any]:
        """Get Neo4j connection status and basic statistics."""
        if not self.connected:
            return {
                "connected": False,
                "uri": self.uri,
                "error": "Not connected to Neo4j"
            }
        
        try:
            with self.driver.session() as session:
                # Get basic statistics
                stats_result = session.run("""
                    MATCH (h:Host) 
                    WITH count(h) as host_count
                    MATCH ()-[r:CONNECTS_TO]->()
                    RETURN host_count, count(r) as connection_count
                """)
                
                stats = stats_result.single()
                
                return {
                    "connected": True,
                    "uri": self.uri,
                    "host_count": stats["host_count"] if stats else 0,
                    "connection_count": stats["connection_count"] if stats else 0
                }
                
        except Exception as e:
            self.logger.error(f"Failed to get connection status: {e}")
            return {
                "connected": False,
                "uri": self.uri,
                "error": str(e)
            }
    
    def clear_old_data(self, days_to_keep: int = 7):
        """Clear old network data to manage database size."""
        if not self.connected:
            return
        
        query = """
        MATCH (h:Host)
        WHERE h.last_seen < datetime() - duration({days: $days})
        DETACH DELETE h
        """
        
        try:
            with self.driver.session() as session:
                session.run(query, days=days_to_keep)
                self.logger.info(f"Cleared old network data (older than {days_to_keep} days)")
        except Exception as e:
            self.logger.error(f"Failed to clear old data: {e}")


# Global instance for easy access
_neo4j_analyzer: Optional[Neo4jNetworkAnalyzer] = None


def get_neo4j_analyzer(uri: str = "bolt://127.0.0.1:7687", 
                      username: str = "neo4j", 
                      password: str = "VNPS6437") -> Neo4jNetworkAnalyzer:
    """Get or create Neo4j network analyzer instance."""
    global _neo4j_analyzer
    
    if _neo4j_analyzer is None:
        _neo4j_analyzer = Neo4jNetworkAnalyzer(uri, username, password)
    
    return _neo4j_analyzer


def close_neo4j_analyzer():
    """Close Neo4j analyzer connection."""
    global _neo4j_analyzer
    
    if _neo4j_analyzer:
        _neo4j_analyzer.disconnect()
        _neo4j_analyzer = None
