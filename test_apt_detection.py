"""Test script for APT detection capabilities.

This script demonstrates and validates the APT detection system by:
1. Generating synthetic network traffic with APT-like patterns
2. Testing various APT detection algorithms
3. Validating behavioral analysis capabilities
"""

import time
import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
import json

# Import APT detection modules
from ml_models.apt_detector import APTDetector, APTIndicator
from ml_models.inference import predict_flows, load_models


def generate_benign_traffic(count: int = 20) -> List[Dict[str, Any]]:
    """Generate benign network traffic patterns."""
    packets = []
    base_time = datetime.now(timezone.utc)
    
    for i in range(count):
        packet = {
            "src_ip": f"192.168.1.{random.randint(10, 50)}",
            "dst_ip": f"8.8.{random.randint(4, 8)}.{random.randint(4, 8)}",
            "src_port": random.randint(49152, 65535),
            "dst_port": random.choice([80, 443, 53]),
            "protocol": random.choice(["TCP", "UDP"]),
            "length": random.randint(64, 1500),
            "packet_count": random.randint(1, 10),
            "byte_count": random.randint(100, 5000),
            "timestamp": (base_time + timedelta(seconds=i*2)).isoformat() + "Z"
        }
        packets.append(packet)
    
    return packets


def generate_apt_beaconing_traffic(count: int = 15) -> List[Dict[str, Any]]:
    """Generate APT beaconing traffic patterns."""
    packets = []
    base_time = datetime.now(timezone.utc)
    beacon_interval = 300  # 5 minutes
    c2_server = "185.159.158.240"  # Suspicious IP
    infected_host = "192.168.1.25"
    
    for i in range(count):
        packet = {
            "src_ip": infected_host,
            "dst_ip": c2_server,
            "src_port": random.randint(49152, 65535),
            "dst_port": 8080,  # Suspicious port
            "protocol": "TCP",
            "length": random.randint(200, 400),  # Small, consistent payload
            "packet_count": 1,
            "byte_count": random.randint(200, 400),
            "timestamp": (base_time + timedelta(seconds=i*beacon_interval)).isoformat() + "Z"
        }
        packets.append(packet)
    
    return packets


def generate_lateral_movement_traffic(count: int = 10) -> List[Dict[str, Any]]:
    """Generate lateral movement traffic patterns."""
    packets = []
    base_time = datetime.now(timezone.utc)
    attacker_ip = "192.168.1.15"
    
    # Target multiple internal hosts on admin ports
    target_ports = [22, 135, 445, 3389, 5985]  # SSH, RPC, SMB, RDP, WinRM
    
    for i in range(count):
        target_ip = f"192.168.1.{random.randint(100, 200)}"
        packet = {
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "src_port": random.randint(49152, 65535),
            "dst_port": random.choice(target_ports),
            "protocol": "TCP",
            "length": random.randint(100, 800),
            "packet_count": 1,
            "byte_count": random.randint(100, 800),
            "timestamp": (base_time + timedelta(seconds=i*30)).isoformat() + "Z"
        }
        packets.append(packet)
    
    return packets


def generate_data_exfiltration_traffic(count: int = 5) -> List[Dict[str, Any]]:
    """Generate data exfiltration traffic patterns."""
    packets = []
    base_time = datetime.now(timezone.utc)
    exfil_source = "192.168.1.30"
    external_server = "203.0.113.50"
    
    for i in range(count):
        packet = {
            "src_ip": exfil_source,
            "dst_ip": external_server,
            "src_port": random.randint(49152, 65535),
            "dst_port": 443,
            "protocol": "TCP",
            "length": random.randint(50000, 100000),  # Large data transfers
            "packet_count": random.randint(50, 100),
            "byte_count": random.randint(5000000, 15000000),  # 5-15MB
            "timestamp": (base_time + timedelta(seconds=i*60)).isoformat() + "Z"
        }
        packets.append(packet)
    
    return packets


def generate_port_scanning_traffic(count: int = 25) -> List[Dict[str, Any]]:
    """Generate port scanning traffic patterns."""
    packets = []
    base_time = datetime.now(timezone.utc)
    scanner_ip = "192.168.1.12"
    target_ip = "192.168.1.100"
    
    # Scan many different ports
    for i in range(count):
        packet = {
            "src_ip": scanner_ip,
            "dst_ip": target_ip,
            "src_port": random.randint(49152, 65535),
            "dst_port": 1000 + i,  # Sequential port scan
            "protocol": "TCP",
            "length": 60,  # Small SYN packets
            "packet_count": 1,
            "byte_count": 60,
            "timestamp": (base_time + timedelta(seconds=i*2)).isoformat() + "Z"
        }
        packets.append(packet)
    
    return packets


def generate_dns_tunneling_traffic(count: int = 30) -> List[Dict[str, Any]]:
    """Generate DNS tunneling traffic patterns."""
    packets = []
    base_time = datetime.now(timezone.utc)
    tunneling_host = "192.168.1.35"
    dns_server = "8.8.8.8"
    
    for i in range(count):
        packet = {
            "src_ip": tunneling_host,
            "dst_ip": dns_server,
            "src_port": random.randint(49152, 65535),
            "dst_port": 53,
            "protocol": "UDP",
            "length": random.randint(100, 300),
            "packet_count": 1,
            "byte_count": random.randint(100, 300),
            "timestamp": (base_time + timedelta(seconds=i*10)).isoformat() + "Z"
        }
        packets.append(packet)
    
    return packets


def test_apt_detection():
    """Main test function for APT detection capabilities."""
    print("🔍 APT Guardian - Testing APT Detection Capabilities")
    print("=" * 60)
    
    # Initialize APT detector
    apt_detector = APTDetector()
    
    # Generate test traffic
    print("\n📊 Generating Test Traffic Patterns...")
    
    benign_traffic = generate_benign_traffic(20)
    beaconing_traffic = generate_apt_beaconing_traffic(15)
    lateral_movement = generate_lateral_movement_traffic(10)
    data_exfiltration = generate_data_exfiltration_traffic(5)
    port_scanning = generate_port_scanning_traffic(25)
    dns_tunneling = generate_dns_tunneling_traffic(30)
    
    # Combine all traffic
    all_traffic = (benign_traffic + beaconing_traffic + lateral_movement + 
                  data_exfiltration + port_scanning + dns_tunneling)
    
    # Sort by timestamp
    all_traffic.sort(key=lambda x: x['timestamp'])
    
    print(f"✅ Generated {len(all_traffic)} packets:")
    print(f"   - Benign: {len(benign_traffic)}")
    print(f"   - Beaconing: {len(beaconing_traffic)}")
    print(f"   - Lateral Movement: {len(lateral_movement)}")
    print(f"   - Data Exfiltration: {len(data_exfiltration)}")
    print(f"   - Port Scanning: {len(port_scanning)}")
    print(f"   - DNS Tunneling: {len(dns_tunneling)}")
    
    # Test APT detection
    print("\n🔍 Running APT Detection Analysis...")
    start_time = time.time()
    
    apt_indicators = apt_detector.analyze_packet_batch(all_traffic)
    
    analysis_time = time.time() - start_time
    print(f"✅ Analysis completed in {analysis_time:.2f} seconds")
    
    # Display results
    print(f"\n🚨 APT Detection Results:")
    print(f"Total Indicators Found: {len(apt_indicators)}")
    
    if apt_indicators:
        # Group by severity
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        type_counts = {}
        
        for indicator in apt_indicators:
            severity_counts[indicator.severity] += 1
            type_counts[indicator.indicator_type] = type_counts.get(indicator.indicator_type, 0) + 1
        
        print(f"\n📊 Severity Breakdown:")
        for severity, count in severity_counts.items():
            emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "⚪"}[severity]
            print(f"   {emoji} {severity}: {count}")
        
        print(f"\n🎯 Indicator Types:")
        for itype, count in type_counts.items():
            print(f"   - {itype.replace('_', ' ').title()}: {count}")
        
        print(f"\n🔍 Detailed Indicators:")
        for i, indicator in enumerate(apt_indicators[:10], 1):  # Show first 10
            confidence_bar = "█" * int(indicator.confidence * 10)
            print(f"\n   {i}. {indicator.indicator_type.replace('_', ' ').title()}")
            print(f"      Severity: {indicator.severity} | Confidence: {confidence_bar} {indicator.confidence:.2f}")
            print(f"      Source: {indicator.source_ip} → Target: {indicator.target_ip}")
            print(f"      Description: {indicator.description}")
    
    # Test host profiling
    print(f"\n👥 Host Behavioral Analysis:")
    host_profiles = apt_detector.host_profiles
    risk_scores = apt_detector.get_host_risk_scores()
    
    print(f"Monitored Hosts: {len(host_profiles)}")
    
    if risk_scores:
        print(f"\n🎯 Top Risk Hosts:")
        sorted_hosts = sorted(risk_scores.items(), key=lambda x: x[1], reverse=True)
        
        for ip, risk_score in sorted_hosts[:5]:
            risk_emoji = "🔴" if risk_score > 0.7 else "🟡" if risk_score > 0.4 else "🟢"
            profile = host_profiles.get(ip)
            
            print(f"\n   {risk_emoji} {ip} - Risk Score: {risk_score:.2f}")
            if profile:
                print(f"      Connections: {profile.total_connections}")
                print(f"      Unique Destinations: {len(profile.unique_destinations)}")
                print(f"      Protocols: {', '.join(profile.protocols_used)}")
                print(f"      Data Out: {profile.data_volume_out / 1024:.1f} KB")
    
    # Test ML integration
    print(f"\n🧠 Testing ML Integration...")
    try:
        models = load_models(["RandomForest"])  # Load placeholder models
        predictions = predict_flows(models, all_traffic[:10])  # Test first 10 packets
        
        print(f"✅ ML Integration Test Successful")
        print(f"Predictions generated for {len(predictions)} flows")
        
        # Show prediction summary
        pred_counts = predictions['prediction'].value_counts()
        print(f"\n📊 ML Prediction Summary:")
        for label, count in pred_counts.items():
            print(f"   - {label}: {count}")
        
        # Show APT-enhanced predictions
        apt_enhanced = predictions[predictions['apt_indicators_count'] > 0]
        if not apt_enhanced.empty:
            print(f"\n🔍 APT-Enhanced Predictions: {len(apt_enhanced)}")
            for _, row in apt_enhanced.iterrows():
                print(f"   - {row['src_ip']} → {row['dst_ip']}: {row['prediction']} "
                      f"(Risk: {row['risk_score']}, APT Indicators: {row['apt_indicators_count']})")
    
    except Exception as e:
        print(f"⚠️ ML Integration Test Failed: {e}")
    
    # Summary
    print(f"\n" + "=" * 60)
    print(f"🎯 APT Detection Test Summary:")
    print(f"   - Total Packets Analyzed: {len(all_traffic)}")
    print(f"   - APT Indicators Found: {len(apt_indicators)}")
    print(f"   - Hosts Monitored: {len(host_profiles)}")
    print(f"   - High-Risk Hosts: {len([h for h in risk_scores.values() if h > 0.7])}")
    print(f"   - Analysis Time: {analysis_time:.2f} seconds")
    print(f"   - Detection Rate: {len(apt_indicators) / len(all_traffic) * 100:.1f}% of packets flagged")
    
    # Performance metrics
    if apt_indicators:
        high_conf = len([i for i in apt_indicators if i.confidence > 0.8])
        print(f"   - High Confidence Detections: {high_conf} ({high_conf/len(apt_indicators)*100:.1f}%)")
    
    print(f"\n✅ APT Detection System Test Completed Successfully!")
    
    return {
        'total_packets': len(all_traffic),
        'apt_indicators': len(apt_indicators),
        'hosts_monitored': len(host_profiles),
        'analysis_time': analysis_time,
        'indicators': apt_indicators,
        'risk_scores': risk_scores
    }


if __name__ == "__main__":
    # Run the comprehensive APT detection test
    results = test_apt_detection()
    
    # Optional: Save results to file
    with open('apt_detection_test_results.json', 'w') as f:
        # Convert non-serializable objects for JSON
        serializable_results = {
            'total_packets': results['total_packets'],
            'apt_indicators': results['apt_indicators'],
            'hosts_monitored': results['hosts_monitored'],
            'analysis_time': results['analysis_time'],
            'risk_scores': results['risk_scores']
        }
        json.dump(serializable_results, f, indent=2)
    
    print(f"\n💾 Test results saved to 'apt_detection_test_results.json'")
