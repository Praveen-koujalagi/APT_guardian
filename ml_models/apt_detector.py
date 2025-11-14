"""Advanced APT Detection Module with Behavioral Analysis.

This module implements sophisticated APT detection techniques including:
- Behavioral pattern analysis
- Command & Control (C2) detection
- Data exfiltration detection
- Lateral movement detection
- Persistence mechanism detection
"""

from __future__ import annotations
from typing import Dict, List, Any, Optional, Tuple, Set
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
import ipaddress
import re
import math
import statistics
from dataclasses import dataclass, field
import json

# Neo4j integration
try:
    from utils.neo4j_network_analyzer import get_neo4j_analyzer, Neo4jNetworkAnalyzer
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False

# Blockchain integration
try:
    from blockchain.blockchain_utils import log_event_to_blockchain
    BLOCKCHAIN_AVAILABLE = True
except ImportError:
    BLOCKCHAIN_AVAILABLE = False
    def log_event_to_blockchain(*args, **kwargs):
        """Fallback function when blockchain is not available."""
        return False


@dataclass
class APTIndicator:
    """Represents an APT indicator with severity and context."""
    indicator_type: str
    severity: str  # HIGH, MEDIUM, LOW
    confidence: float  # 0.0 to 1.0
    description: str
    evidence: Dict[str, Any]
    timestamp: datetime
    source_ip: str
    target_ip: str
    related_packets: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class HostProfile:
    """Profile of a host's network behavior."""
    ip: str
    first_seen: datetime
    last_seen: datetime
    total_connections: int = 0
    unique_destinations: Set[str] = field(default_factory=set)
    protocols_used: Set[str] = field(default_factory=set)
    ports_accessed: Set[int] = field(default_factory=set)
    data_volume_in: int = 0
    data_volume_out: int = 0
    suspicious_activities: List[str] = field(default_factory=list)
    connection_patterns: Dict[str, Any] = field(default_factory=dict)


class APTDetector:
    """Advanced APT detection engine with behavioral analysis."""
    
    def __init__(self, time_window: int = 3600, enable_neo4j: bool = True):  # 1 hour window
        self.time_window = time_window
        self.host_profiles: Dict[str, HostProfile] = {}
        self.apt_indicators: List[APTIndicator] = []
        self.c2_domains: Set[str] = self._load_c2_domains()
        self.suspicious_tlds: Set[str] = {'.tk', '.ml', '.ga', '.cf', '.bit', '.onion'}
        
        # Neo4j integration
        self.enable_neo4j = enable_neo4j and NEO4J_AVAILABLE
        self.neo4j_analyzer: Optional[Neo4jNetworkAnalyzer] = None
        
        if self.enable_neo4j:
            try:
                self.neo4j_analyzer = get_neo4j_analyzer()
                print(f"✅ Neo4j analyzer initialized successfully")
                print(f"🔗 Neo4j connection status: {self.neo4j_analyzer.connected}")
            except Exception as e:
                print(f"❌ Failed to initialize Neo4j analyzer: {e}")
                self.enable_neo4j = False
        
        # Behavioral thresholds
        self.thresholds = {
            'beacon_variance_threshold': 0.1,  # Low variance indicates beaconing
            'beacon_min_connections': 5,
            'data_exfil_threshold': 10 * 1024 * 1024,  # 10MB
            'lateral_movement_threshold': 5,  # unique internal IPs
            'port_scan_threshold': 20,  # unique ports
            'dns_tunnel_entropy_threshold': 4.0,
            'dns_query_threshold': 15,
            'dns_time_window': 300,  # seconds
            'brute_force_attempt_threshold': 12,
            'brute_force_connection_threshold': 5,
            'unusual_port_threshold': 0.95,  # percentile
        }
        
        # Temporal analysis windows
        self.connection_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.dns_queries: Dict[str, List[Dict]] = defaultdict(list)
        self.file_transfers: Dict[str, List[Dict]] = defaultdict(list)
        self.last_dns_alerts: Dict[str, datetime] = {}
        self.last_brute_force_alerts: Dict[tuple, datetime] = {}
        
    def _load_c2_domains(self) -> Set[str]:
        """Load known C2 domains from threat intelligence."""
        # In production, this would load from threat intel feeds
        return {
            'pastebin.com', 'hastebin.com', 'ghostbin.com',
            'telegram.org', 'discord.com',
            # Add more known C2 domains
        }
    
    def analyze_packet_batch(self, packets: List[Dict[str, Any]]) -> List[APTIndicator]:
        """Analyze a batch of packets for APT indicators."""
        indicators = []
        
        # Update host profiles
        for packet in packets:
            self._update_host_profile(packet)
        
        # Ingest packets into Neo4j for graph analysis
        if self.enable_neo4j and self.neo4j_analyzer:
            try:
                print(f"🔄 Ingesting {len(packets)} packets into Neo4j...")
                success = self.neo4j_analyzer.ingest_packet_batch(packets)
                if success:
                    print(f"✅ Successfully ingested {len(packets)} packets into Neo4j")
                else:
                    print(f"❌ Failed to ingest packets into Neo4j")
            except Exception as e:
                print(f"❌ Neo4j ingestion error: {e}")
                import traceback
                traceback.print_exc()
        
        # Run traditional APT detection algorithms
        indicators.extend(self._detect_c2_communication(packets))
        indicators.extend(self._detect_data_exfiltration(packets))
        indicators.extend(self._detect_lateral_movement(packets))
        indicators.extend(self._detect_persistence_mechanisms(packets))
        indicators.extend(self._detect_reconnaissance(packets))
        indicators.extend(self._detect_dns_tunneling(packets))
        indicators.extend(self._detect_brute_force_attacks())
        indicators.extend(self._detect_beaconing_behavior())
        
        # Run Neo4j-powered detection algorithms
        if self.enable_neo4j and self.neo4j_analyzer:
            indicators.extend(self._detect_neo4j_patterns())
        
        # Store indicators
        self.apt_indicators.extend(indicators)
        
        return indicators
    
    def _update_host_profile(self, packet: Dict[str, Any]):
        """Update host behavioral profile."""
        src_ip = packet.get('src_ip')
        dst_ip = packet.get('dst_ip')
        
        if not src_ip or not dst_ip:
            return
        
        timestamp_str = packet.get('timestamp', '')
        try:
            # Handle different timestamp formats
            if timestamp_str.endswith('Z'):
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
            else:
                timestamp = datetime.fromisoformat(timestamp_str)
        except ValueError:
            # Fallback to current time if timestamp parsing fails
            timestamp = datetime.now()
        
        # Normalize timestamp to naive UTC for consistent comparisons
        if timestamp.tzinfo is not None:
            timestamp = timestamp.astimezone(timezone.utc).replace(tzinfo=None)
        
        # Update source host profile
        if src_ip not in self.host_profiles:
            self.host_profiles[src_ip] = HostProfile(
                ip=src_ip,
                first_seen=timestamp,
                last_seen=timestamp
            )
        
        profile = self.host_profiles[src_ip]
        profile.last_seen = timestamp
        profile.total_connections += 1
        profile.unique_destinations.add(dst_ip)
        
        if 'protocol' in packet:
            profile.protocols_used.add(packet['protocol'])
        
        if 'dst_port' in packet:
            profile.ports_accessed.add(packet['dst_port'])
        
        if 'length' in packet:
            profile.data_volume_out += packet['length']
        
        # Store connection for temporal analysis
        self.connection_history[src_ip].append({
            'timestamp': timestamp,
            'dst_ip': dst_ip,
            'dst_port': packet.get('dst_port'),
            'protocol': packet.get('protocol'),
            'length': packet.get('length', 0),
            'packet_count': packet.get('packet_count', 1),
            'packet': packet
        })
        
        # Track DNS queries for tunneling detection
        dst_port = packet.get('dst_port')
        src_port = packet.get('src_port')
        if dst_port == 53 or src_port == 53:
            dns_entry = {
                'timestamp': timestamp,
                'packet': packet
            }
            self.dns_queries[src_ip].append(dns_entry)
            
            # Remove old entries beyond the configured window
            dns_window = self.thresholds.get('dns_time_window', self.time_window)
            cutoff_time = datetime.utcnow() - timedelta(seconds=dns_window)
            self.dns_queries[src_ip] = [
                entry for entry in self.dns_queries[src_ip]
                if entry['timestamp'] >= cutoff_time
            ]
    
    def _detect_c2_communication(self, packets: List[Dict[str, Any]]) -> List[APTIndicator]:
        """Detect Command & Control communication patterns."""
        indicators = []
        
        for packet in packets:
            dst_ip = packet.get('dst_ip')
            src_ip = packet.get('src_ip')
            
            if not dst_ip or not src_ip:
                continue
            
            # Check for known C2 domains (if DNS resolution available)
            if self._is_suspicious_domain(dst_ip):
                indicators.append(APTIndicator(
                    indicator_type="C2_COMMUNICATION",
                    severity="HIGH",
                    confidence=0.8,
                    description=f"Communication with known C2 domain: {dst_ip}",
                    evidence={"c2_domain": dst_ip, "packet": packet},
                    timestamp=datetime.now(timezone.utc),
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    related_packets=[packet]
                ))
            
            # Check for suspicious ports commonly used by APTs
            dst_port = packet.get('dst_port')
            if dst_port in {4444, 5555, 8080, 9999, 31337, 1337}:
                indicators.append(APTIndicator(
                    indicator_type="SUSPICIOUS_PORT_C2",
                    severity="MEDIUM",
                    confidence=0.6,
                    description=f"Communication on suspicious port {dst_port}",
                    evidence={"suspicious_port": dst_port, "packet": packet},
                    timestamp=datetime.now(timezone.utc),
                    source_ip=src_ip,
                    target_ip=dst_ip,
                    related_packets=[packet]
                ))
        
        return indicators
    
    def _detect_beaconing_behavior(self) -> List[APTIndicator]:
        """Detect beaconing patterns characteristic of APT C2."""
        indicators = []
        
        for src_ip, connections in self.connection_history.items():
            if len(connections) < self.thresholds['beacon_min_connections']:
                continue
            
            # Group connections by destination
            dest_groups = defaultdict(list)
            for conn in connections:
                dest_groups[conn['dst_ip']].append(conn)
            
            for dst_ip, dest_connections in dest_groups.items():
                if len(dest_connections) < self.thresholds['beacon_min_connections']:
                    continue
                
                # Calculate time intervals between connections
                timestamps = [conn['timestamp'] for conn in dest_connections]
                timestamps.sort()
                
                intervals = []
                for i in range(1, len(timestamps)):
                    interval = (timestamps[i] - timestamps[i-1]).total_seconds()
                    intervals.append(interval)
                
                if len(intervals) < 3:
                    continue
                
                # Check for regular intervals (low variance)
                mean_interval = statistics.mean(intervals)
                variance = statistics.variance(intervals) if len(intervals) > 1 else 0
                coefficient_of_variation = (variance ** 0.5) / mean_interval if mean_interval > 0 else 1
                
                if coefficient_of_variation < self.thresholds['beacon_variance_threshold']:
                    confidence = 1.0 - coefficient_of_variation
                    indicators.append(APTIndicator(
                        indicator_type="BEACONING_BEHAVIOR",
                        severity="HIGH",
                        confidence=min(confidence, 0.95),
                        description=f"Regular beaconing detected to {dst_ip} (interval: {mean_interval:.1f}s)",
                        evidence={
                            "mean_interval": mean_interval,
                            "coefficient_of_variation": coefficient_of_variation,
                            "connection_count": len(dest_connections)
                        },
                        timestamp=datetime.now(timezone.utc),
                        source_ip=src_ip,
                        target_ip=dst_ip,
                        related_packets=dest_connections
                    ))
        
        return indicators
    
    def _detect_data_exfiltration(self, packets: List[Dict[str, Any]]) -> List[APTIndicator]:
        """Detect potential data exfiltration patterns."""
        indicators = []
        
        # Track data volumes per source IP
        data_volumes = defaultdict(int)
        for packet in packets:
            src_ip = packet.get('src_ip')
            length = packet.get('length', 0)
            if src_ip and length:
                data_volumes[src_ip] += length
        
        # Check for unusual data volumes
        for src_ip, volume in data_volumes.items():
            if volume > self.thresholds['data_exfil_threshold']:
                indicators.append(APTIndicator(
                    indicator_type="DATA_EXFILTRATION",
                    severity="HIGH",
                    confidence=0.7,
                    description=f"Large data transfer detected: {volume / (1024*1024):.1f}MB",
                    evidence={"data_volume": volume, "src_ip": src_ip},
                    timestamp=datetime.now(timezone.utc),
                    source_ip=src_ip,
                    target_ip="multiple",
                    related_packets=[p for p in packets if p.get('src_ip') == src_ip]
                ))
        
        return indicators
    
    def _detect_lateral_movement(self, packets: List[Dict[str, Any]]) -> List[APTIndicator]:
        """Detect lateral movement patterns."""
        indicators = []
        
        # Track internal network connections
        internal_connections = defaultdict(set)
        
        for packet in packets:
            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            dst_port = packet.get('dst_port')
            
            if not src_ip or not dst_ip:
                continue
            
            # Check if both IPs are internal (RFC 1918)
            if self._is_internal_ip(src_ip) and self._is_internal_ip(dst_ip):
                # Common lateral movement ports
                if dst_port in {22, 23, 135, 139, 445, 3389, 5985, 5986}:
                    internal_connections[src_ip].add(dst_ip)
        
        # Check for excessive internal connections
        for src_ip, destinations in internal_connections.items():
            if len(destinations) > self.thresholds['lateral_movement_threshold']:
                indicators.append(APTIndicator(
                    indicator_type="LATERAL_MOVEMENT",
                    severity="HIGH",
                    confidence=0.8,
                    description=f"Potential lateral movement: {len(destinations)} internal targets",
                    evidence={
                        "target_count": len(destinations),
                        "targets": list(destinations)
                    },
                    timestamp=datetime.now(timezone.utc),
                    source_ip=src_ip,
                    target_ip="multiple_internal",
                    related_packets=[p for p in packets if p.get('src_ip') == src_ip]
                ))
        
        return indicators
    
    def _detect_reconnaissance(self, packets: List[Dict[str, Any]]) -> List[APTIndicator]:
        """Detect reconnaissance activities."""
        indicators = []
        
        # Track port scanning behavior
        port_scans = defaultdict(set)
        
        for packet in packets:
            src_ip = packet.get('src_ip')
            dst_port = packet.get('dst_port')
            
            if src_ip and dst_port:
                port_scans[src_ip].add(dst_port)
        
        # Check for port scanning
        for src_ip, ports in port_scans.items():
            if len(ports) > self.thresholds['port_scan_threshold']:
                indicators.append(APTIndicator(
                    indicator_type="RECONNAISSANCE",
                    severity="MEDIUM",
                    confidence=0.7,
                    description=f"Port scanning detected: {len(ports)} unique ports",
                    evidence={"port_count": len(ports), "ports": list(ports)},
                    timestamp=datetime.now(timezone.utc),
                    source_ip=src_ip,
                    target_ip="multiple",
                    related_packets=[p for p in packets if p.get('src_ip') == src_ip]
                ))
        
        return indicators
    
    def _detect_persistence_mechanisms(self, packets: List[Dict[str, Any]]) -> List[APTIndicator]:
        """Detect persistence establishment attempts."""
        indicators = []
        
        # Look for connections to common persistence-related services
        persistence_ports = {
            135: "RPC Endpoint Mapper",
            445: "SMB (potential scheduled tasks)",
            3389: "RDP (potential backdoor)",
            5985: "WinRM (potential backdoor)",
            1433: "SQL Server (potential backdoor)"
        }
        
        for packet in packets:
            dst_port = packet.get('dst_port')
            src_ip = packet.get('src_ip')
            dst_ip = packet.get('dst_ip')
            
            if dst_port in persistence_ports:
                indicators.append(APTIndicator(
                    indicator_type="PERSISTENCE_ATTEMPT",
                    severity="MEDIUM",
                    confidence=0.5,
                    description=f"Connection to {persistence_ports[dst_port]} service",
                    evidence={"service": persistence_ports[dst_port], "port": dst_port},
                    timestamp=datetime.now(timezone.utc),
                    source_ip=src_ip or "unknown",
                    target_ip=dst_ip or "unknown",
                    related_packets=[packet]
                ))
        
        return indicators
    
    def _detect_dns_tunneling(self, packets: List[Dict[str, Any]]) -> List[APTIndicator]:
        """Detect DNS tunneling attempts."""
        indicators = []
        
        dns_threshold = self.thresholds.get('dns_query_threshold', 15)
        dns_window = self.thresholds.get('dns_time_window', 300)
        now = datetime.utcnow()
        
        for src_ip, query_entries in list(self.dns_queries.items()):
            # Keep only recent entries within the window
            recent_entries = [
                entry for entry in query_entries
                if (now - entry['timestamp']).total_seconds() <= dns_window
            ]
            
            if len(recent_entries) != len(query_entries):
                self.dns_queries[src_ip] = recent_entries
            
            if not recent_entries:
                continue
            
            total_queries = sum(entry['packet'].get('packet_count', 1) for entry in recent_entries)
            average_size = (
                sum(entry['packet'].get('length', 0) for entry in recent_entries) /
                max(total_queries, 1)
            )
            unique_dns_servers = {entry['packet'].get('dst_ip') for entry in recent_entries}
            
            if total_queries >= dns_threshold or average_size >= 200:
                last_alert = self.last_dns_alerts.get(src_ip)
                if last_alert and (now - last_alert).total_seconds() < dns_window / 2:
                    continue
                
                severity = "HIGH" if total_queries >= dns_threshold * 2 else "MEDIUM"
                confidence = min(0.95, 0.4 + total_queries / 40)
                
                indicators.append(APTIndicator(
                    indicator_type="DNS_TUNNELING",
                    severity=severity,
                    confidence=confidence,
                    description=f"Potential DNS tunneling: {total_queries} queries in {dns_window}s window",
                    evidence={
                        "query_count": total_queries,
                        "average_query_size": average_size,
                        "dns_servers": list(unique_dns_servers),
                        "time_window_seconds": dns_window
                    },
                    timestamp=datetime.now(timezone.utc),
                    source_ip=src_ip,
                    target_ip="dns_servers",
                    related_packets=[entry['packet'] for entry in recent_entries[:20]]
                ))
                
                self.last_dns_alerts[src_ip] = now
        
        return indicators
    
    def _detect_brute_force_attacks(self) -> List[APTIndicator]:
        """Detect brute force authentication attempts."""
        indicators = []
        brute_ports = {22, 23, 3389, 445, 1433, 3306, 5432}
        attempt_threshold = self.thresholds.get('brute_force_attempt_threshold', 12)
        connection_threshold = self.thresholds.get('brute_force_connection_threshold', 5)
        window_seconds = min(self.time_window, 600)
        now = datetime.utcnow()
        
        for src_ip, history in self.connection_history.items():
            attempts: Dict[Tuple[str, int], Dict[str, Any]] = defaultdict(lambda: {
                'attempts': 0,
                'connections': 0,
                'packets': []
            })
            
            for entry in history:
                dst_ip = entry.get('dst_ip')
                dst_port = entry.get('dst_port')
                timestamp = entry.get('timestamp')
                
                if not dst_ip or dst_port not in brute_ports:
                    continue
                
                if not timestamp or (now - timestamp).total_seconds() > window_seconds:
                    continue
                
                key = (dst_ip, dst_port)
                attempts[key]['attempts'] += entry.get('packet_count', 1)
                attempts[key]['connections'] += 1
                if entry.get('packet'):
                    attempts[key]['packets'].append(entry['packet'])
            
            for (dst_ip, dst_port), data in attempts.items():
                if data['attempts'] >= attempt_threshold or data['connections'] >= connection_threshold:
                    alert_key = (src_ip, dst_ip, dst_port)
                    last_alert = self.last_brute_force_alerts.get(alert_key)
                    if last_alert and (now - last_alert).total_seconds() < window_seconds / 2:
                        continue
                    
                    severity = "HIGH" if data['attempts'] >= attempt_threshold * 2 else "MEDIUM"
                    confidence = min(0.95, 0.5 + data['attempts'] / 30)
                    
                    indicators.append(APTIndicator(
                        indicator_type="BRUTE_FORCE_ATTACK",
                        severity=severity,
                        confidence=confidence,
                        description=f"Brute force attempts detected against {dst_ip}:{dst_port}",
                        evidence={
                            "attempts": data['attempts'],
                            "connection_count": data['connections'],
                            "time_window_seconds": window_seconds
                        },
                        timestamp=datetime.now(timezone.utc),
                        source_ip=src_ip,
                        target_ip=f"{dst_ip}:{dst_port}",
                        related_packets=data['packets'][:20]
                    ))
                    
                    self.last_brute_force_alerts[alert_key] = now
        
        return indicators
    
    def _is_internal_ip(self, ip: str) -> bool:
        """Check if IP address is in private/internal range."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except ValueError:
            return False
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain is suspicious based on various indicators."""
        if domain in self.c2_domains:
            return True
        
        # Check for suspicious TLDs
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                return True
        
        # Check for domain generation algorithm patterns
        if self._is_dga_domain(domain):
            return True
        
        return False
    
    def _is_dga_domain(self, domain: str) -> bool:
        """Detect domain generation algorithm (DGA) domains."""
        # Simple heuristics for DGA detection
        if len(domain) > 20:  # Very long domains
            return True
        
        # Check for high entropy (randomness)
        entropy = self._calculate_entropy(domain)
        if entropy > 4.5:
            return True
        
        # Check for excessive consonants or vowels
        vowels = sum(1 for c in domain.lower() if c in 'aeiou')
        consonants = sum(1 for c in domain.lower() if c.isalpha() and c not in 'aeiou')
        
        if consonants > 0 and vowels / consonants < 0.2:  # Too few vowels
            return True
        
        return False
    
    def _calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not string:
            return 0
        
        # Count character frequencies
        char_counts = defaultdict(int)
        for char in string:
            char_counts[char] += 1
        
        # Calculate entropy
        entropy = 0
        length = len(string)
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def get_apt_summary(self) -> Dict[str, Any]:
        """Get summary of APT detection results."""
        if not self.apt_indicators:
            return {"total_indicators": 0, "severity_breakdown": {}, "indicator_types": {}}
        
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)
        
        for indicator in self.apt_indicators:
            severity_counts[indicator.severity] += 1
            type_counts[indicator.indicator_type] += 1
        
        return {
            "total_indicators": len(self.apt_indicators),
            "severity_breakdown": dict(severity_counts),
            "indicator_types": dict(type_counts),
            "high_confidence_indicators": len([i for i in self.apt_indicators if i.confidence > 0.8]),
            "recent_indicators": len([i for i in self.apt_indicators 
                                   if (datetime.now(timezone.utc) - i.timestamp).seconds < 3600])
        }
    
    def get_host_risk_scores(self) -> Dict[str, float]:
        """Calculate risk scores for monitored hosts."""
        risk_scores = {}
        
        for ip, profile in self.host_profiles.items():
            score = 0.0
            
            # Factor in suspicious activities
            score += len(profile.suspicious_activities) * 0.2
            
            # Factor in connection diversity (too many destinations = suspicious)
            if len(profile.unique_destinations) > 100:
                score += 0.3
            
            # Factor in protocol diversity
            if len(profile.protocols_used) > 5:
                score += 0.1
            
            # Factor in port access patterns
            if len(profile.ports_accessed) > 50:
                score += 0.2
            
            # Factor in data volume
            total_data = profile.data_volume_in + profile.data_volume_out
            if total_data > 100 * 1024 * 1024:  # 100MB
                score += 0.2
            
            # Factor in APT indicators for this host
            host_indicators = [i for i in self.apt_indicators if i.source_ip == ip]
            score += len(host_indicators) * 0.1
            
            risk_scores[ip] = min(score, 1.0)  # Cap at 1.0
        
        return risk_scores
    
    def _detect_neo4j_patterns(self) -> List[APTIndicator]:
        """Detect APT patterns using Neo4j graph analysis."""
        indicators = []
        
        if not self.neo4j_analyzer or not self.neo4j_analyzer.connected:
            return indicators
        
        try:
            # Detect beaconing patterns
            beaconing_patterns = self.neo4j_analyzer.detect_beaconing_patterns()
            for pattern in beaconing_patterns:
                indicators.append(APTIndicator(
                    indicator_type="NEO4J_BEACONING",
                    severity="HIGH",
                    confidence=0.9,
                    description=f"Graph-detected beaconing: {pattern['connections']} connections over {pattern['duration_seconds']}s",
                    evidence=pattern,
                    timestamp=datetime.now(timezone.utc),
                    source_ip=pattern['source_ip'],
                    target_ip=pattern['target_ip'],
                    related_packets=[]
                ))
            
            # Detect lateral movement
            lateral_patterns = self.neo4j_analyzer.detect_lateral_movement()
            for pattern in lateral_patterns:
                indicators.append(APTIndicator(
                    indicator_type="NEO4J_LATERAL_MOVEMENT",
                    severity="HIGH",
                    confidence=0.85,
                    description=f"Graph-detected lateral movement: {pattern['target_count']} internal targets",
                    evidence=pattern,
                    timestamp=datetime.now(timezone.utc),
                    source_ip=pattern['source_ip'],
                    target_ip="multiple_internal",
                    related_packets=[]
                ))
            
            # Detect data exfiltration
            exfil_patterns = self.neo4j_analyzer.detect_data_exfiltration()
            for pattern in exfil_patterns:
                bytes_mb = pattern['bytes_transferred'] / (1024 * 1024)
                indicators.append(APTIndicator(
                    indicator_type="NEO4J_DATA_EXFILTRATION",
                    severity="HIGH",
                    confidence=0.8,
                    description=f"Graph-detected data exfiltration: {bytes_mb:.1f}MB transferred",
                    evidence=pattern,
                    timestamp=datetime.now(timezone.utc),
                    source_ip=pattern['source_ip'],
                    target_ip=pattern['target_ip'],
                    related_packets=[]
                ))
            
            # Detect port scanning
            scan_patterns = self.neo4j_analyzer.detect_port_scanning()
            for pattern in scan_patterns:
                indicators.append(APTIndicator(
                    indicator_type="NEO4J_PORT_SCANNING",
                    severity="MEDIUM",
                    confidence=0.75,
                    description=f"Graph-detected port scanning: {pattern['unique_ports']} ports scanned",
                    evidence=pattern,
                    timestamp=datetime.now(timezone.utc),
                    source_ip=pattern['source_ip'],
                    target_ip=pattern['target_ip'],
                    related_packets=[]
                ))
            
            # Mark suspicious activities in Neo4j
            for indicator in indicators:
                if indicator.severity == "HIGH":
                    self.neo4j_analyzer.mark_suspicious_activity(
                        indicator.source_ip,
                        indicator.target_ip,
                        indicator.indicator_type,
                        indicator.severity
                    )
        
        except Exception as e:
            print(f"Warning: Neo4j pattern detection failed: {e}")
        
        return indicators
    
    def get_neo4j_network_topology(self) -> Dict[str, Any]:
        """Get network topology from Neo4j."""
        if not self.neo4j_analyzer or not self.neo4j_analyzer.connected:
            return {"nodes": [], "relationships": []}
        
        try:
            return self.neo4j_analyzer.get_network_topology()
        except Exception as e:
            print(f"Warning: Failed to get Neo4j topology: {e}")
            return {"nodes": [], "relationships": []}
    
    def get_host_behavior_from_neo4j(self, ip: str) -> Dict[str, Any]:
        """Get detailed host behavior profile from Neo4j."""
        if not self.neo4j_analyzer or not self.neo4j_analyzer.connected:
            return {}
        
        try:
            return self.neo4j_analyzer.get_host_behavior_profile(ip)
        except Exception as e:
            print(f"Warning: Failed to get Neo4j host profile for {ip}: {e}")
            return {}
    
    def get_neo4j_connection_status(self) -> Dict[str, Any]:
        """Get Neo4j connection status."""
        if not self.neo4j_analyzer:
            return {"connected": False, "error": "Neo4j analyzer not initialized"}
        
        return self.neo4j_analyzer.get_connection_status()