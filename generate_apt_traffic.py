"""Generate APT-like traffic patterns to test detection capabilities."""

import time
import random
from datetime import datetime, timedelta

# Import your packet capture system
try:
    from utils.windows_packet_capture import WindowsPacketCapture
except ImportError:
    from utils.packet_capture import LivePacketCapture as WindowsPacketCapture


def inject_apt_patterns(pc: WindowsPacketCapture):
    """Inject APT-like patterns into the packet capture system."""
    print("🔍 Injecting APT patterns for testing...")
    
    # 1. Beaconing Pattern - Regular C2 communication
    print("📡 Generating beaconing pattern...")
    beacon_host = "192.168.1.100"
    c2_server = "185.159.158.240"  # Suspicious external IP
    
    for i in range(15):  # 15 regular beacons
        packet = {
            "src_ip": beacon_host,
            "dst_ip": c2_server,
            "src_port": random.randint(49152, 65535),
            "dst_port": 8080,  # Suspicious port
            "protocol": "TCP",
            "length": 250,  # Small, consistent payload
            "packet_count": 1,
            "byte_count": 250,
            "timestamp": (datetime.now() + timedelta(seconds=i*5)).isoformat() + "Z"
        }
        pc._process_packet_info(packet)
        time.sleep(0.1)  # Small delay
    
    # 2. Lateral Movement Pattern
    print("🔄 Generating lateral movement pattern...")
    attacker_ip = "192.168.1.50"
    admin_ports = [22, 135, 445, 3389, 5985]  # SSH, RPC, SMB, RDP, WinRM
    
    for i in range(12):  # Multiple internal targets
        target_ip = f"192.168.1.{100 + i}"
        packet = {
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "src_port": random.randint(49152, 65535),
            "dst_port": random.choice(admin_ports),
            "protocol": "TCP",
            "length": random.randint(100, 500),
            "packet_count": 1,
            "byte_count": random.randint(100, 500),
            "timestamp": (datetime.now() + timedelta(seconds=i*2)).isoformat() + "Z"
        }
        pc._process_packet_info(packet)
        time.sleep(0.1)
    
    # 3. Data Exfiltration Pattern
    print("📤 Generating data exfiltration pattern...")
    exfil_host = "192.168.1.75"
    external_server = "203.0.113.50"
    
    for i in range(8):  # Large data transfers
        packet = {
            "src_ip": exfil_host,
            "dst_ip": external_server,
            "src_port": random.randint(49152, 65535),
            "dst_port": 443,
            "protocol": "TCP",
            "length": random.randint(80000, 120000),  # Large packets
            "packet_count": random.randint(80, 120),
            "byte_count": random.randint(8000000, 12000000),  # 8-12MB
            "timestamp": (datetime.now() + timedelta(seconds=i*3)).isoformat() + "Z"
        }
        pc._process_packet_info(packet)
        time.sleep(0.1)
    
    # 4. Port Scanning Pattern
    print("🔍 Generating port scanning pattern...")
    scanner_ip = "192.168.1.25"
    target_ip = "192.168.1.200"
    
    for port in range(1000, 1030):  # Scan 30 ports
        packet = {
            "src_ip": scanner_ip,
            "dst_ip": target_ip,
            "src_port": random.randint(49152, 65535),
            "dst_port": port,
            "protocol": "TCP",
            "length": 60,  # Small SYN packets
            "packet_count": 1,
            "byte_count": 60,
            "timestamp": (datetime.now() + timedelta(seconds=(port-1000)*0.5)).isoformat() + "Z"
        }
        pc._process_packet_info(packet)
        time.sleep(0.05)
    
    # 5. DNS Tunneling Pattern
    print("🌐 Generating DNS tunneling pattern...")
    tunneling_host = "192.168.1.60"
    dns_server = "8.8.8.8"
    
    for i in range(40):  # Excessive DNS queries
        packet = {
            "src_ip": tunneling_host,
            "dst_ip": dns_server,
            "src_port": random.randint(49152, 65535),
            "dst_port": 53,
            "protocol": "UDP",
            "length": random.randint(150, 300),
            "packet_count": 1,
            "byte_count": random.randint(150, 300),
            "timestamp": (datetime.now() + timedelta(seconds=i*1)).isoformat() + "Z"
        }
        pc._process_packet_info(packet)
        time.sleep(0.05)
    
    print("✅ APT patterns injected! Check your APT Analysis tab.")


def test_apt_detection_live():
    """Test APT detection with live packet capture system."""
    print("🚀 Testing APT Detection with Live System")
    print("=" * 50)
    
    # Initialize packet capture
    pc = WindowsPacketCapture()
    
    # Inject APT patterns
    inject_apt_patterns(pc)
    
    # Wait a moment for processing
    time.sleep(2)
    
    # Check results
    apt_indicators = pc.get_apt_indicators()
    traffic_summary = pc.get_traffic_summary()
    
    print(f"\n📊 Results:")
    print(f"Total Packets: {traffic_summary.get('total_packets', 0)}")
    print(f"APT Indicators: {len(apt_indicators)}")
    print(f"Attack Logs: {traffic_summary.get('attack_count', 0)}")
    
    if apt_indicators:
        print(f"\n🚨 APT Indicators Found:")
        for i, indicator in enumerate(apt_indicators[:5], 1):
            print(f"  {i}. {indicator['type'].replace('_', ' ').title()}")
            print(f"     Severity: {indicator['severity']} | Confidence: {indicator['confidence']:.2f}")
            print(f"     {indicator['description']}")
            print()
    
    # Show host profiles
    host_profiles = pc.get_host_profiles()
    if host_profiles:
        print(f"🎯 Host Profiles: {len(host_profiles)} hosts monitored")
        
        # Show risk scores
        risk_scores = traffic_summary.get('host_risk_scores', {})
        if risk_scores:
            print(f"\n📈 Top Risk Hosts:")
            sorted_hosts = sorted(risk_scores.items(), key=lambda x: x[1], reverse=True)
            for ip, risk in sorted_hosts[:3]:
                print(f"  {ip}: {risk:.2f}")
    
    return pc


if __name__ == "__main__":
    pc = test_apt_detection_live()
    
    print(f"\n💡 Tips:")
    print(f"1. Run this script while your Streamlit app is running")
    print(f"2. Check the 'APT Analysis' tab to see the indicators")
    print(f"3. The patterns are designed to trigger multiple APT detection algorithms")
    print(f"4. Refresh your Streamlit app to see updated results")
