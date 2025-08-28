#!/usr/bin/env python3
"""
Simple packet capture test script to diagnose issues
"""
import time
import sys
import os

def test_basic_imports():
    """Test if all required modules can be imported."""
    print("🔍 Testing imports...")
    
    try:
        import scapy
        print(f"✅ Scapy imported successfully (version: {scapy.__version__})")
    except ImportError as e:
        print(f"❌ Scapy import failed: {e}")
        return False
    
    try:
        from scapy.all import get_if_list, sniff, IP
        print("✅ Scapy functions imported successfully")
    except ImportError as e:
        print(f"❌ Scapy functions import failed: {e}")
        return False
    
    try:
        import pyshark
        print("✅ PyShark imported successfully")
    except ImportError as e:
        print(f"⚠️ PyShark import failed: {e}")
    
    return True

def test_interface_detection():
    """Test if network interfaces can be detected."""
    print("\n🔍 Testing interface detection...")
    
    try:
        from scapy.all import get_if_list
        interfaces = get_if_list()
        print(f"✅ Found {len(interfaces)} network interfaces:")
        for i, iface in enumerate(interfaces):
            print(f"   {i+1}. {iface}")
        return interfaces
    except Exception as e:
        print(f"❌ Interface detection failed: {e}")
        return []

def test_simple_capture(interface, duration=5):
    """Test simple packet capture."""
    print(f"\n🔍 Testing packet capture on {interface} for {duration} seconds...")
    
    try:
        from scapy.all import sniff, IP
        
        # Simple capture test
        packets = sniff(iface=interface, timeout=duration, store=1)
        print(f"✅ Captured {len(packets)} packets")
        
        if packets:
            print("Sample packet details:")
            for i, pkt in enumerate(packets[:3]):  # Show first 3 packets
                if IP in pkt:
                    print(f"   Packet {i+1}: {pkt[IP].src} -> {pkt[IP].dst}")
                else:
                    print(f"   Packet {i+1}: Non-IP packet")
        
        return len(packets)
        
    except Exception as e:
        print(f"❌ Packet capture failed: {e}")
        return 0

def test_admin_privileges():
    """Test if we have admin privileges."""
    print("\n🔍 Testing admin privileges...")
    
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if is_admin:
            print("✅ Running with administrator privileges")
        else:
            print("❌ NOT running with administrator privileges")
            print("   Packet capture requires admin rights on Windows")
        return is_admin
    except Exception as e:
        print(f"⚠️ Could not determine admin status: {e}")
        return False

def test_windows_packet_capture():
    """Test the Windows packet capture class."""
    print("\n🔍 Testing Windows packet capture class...")
    
    try:
        from utils.windows_packet_capture import WindowsPacketCapture
        
        pc = WindowsPacketCapture()
        print(f"✅ Created packet capture object")
        print(f"   Interface: {pc.interface}")
        print(f"   Available interfaces: {len(pc.available_interfaces)}")
        
        # Try to start capture
        if pc.start():
            print("✅ Started packet capture")
            time.sleep(3)  # Wait for some packets
            
            summary = pc.get_traffic_summary()
            print(f"   Traffic summary: {summary}")
            
            packets = pc.get_recent_packets(5)
            print(f"   Recent packets: {len(packets)}")
            
            pc.stop()
            print("✅ Stopped packet capture")
            return True
        else:
            print("❌ Failed to start packet capture")
            return False
            
    except Exception as e:
        print(f"❌ Windows packet capture test failed: {e}")
        return False

def main():
    """Main test function."""
    print("🚀 APT Guardian Packet Capture Diagnostic Tool")
    print("=" * 50)
    
    # Check admin privileges first
    is_admin = test_admin_privileges()
    
    # Test imports
    if not test_basic_imports():
        print("\n❌ Critical imports failed. Please install required packages:")
        print("   pip install scapy pyshark")
        return
    
    # Test interface detection
    interfaces = test_interface_detection()
    if not interfaces:
        print("\n❌ No network interfaces detected")
        return
    
    # Test simple capture on first non-loopback interface
    test_interface = None
    for iface in interfaces:
        if 'loopback' not in iface.lower():
            test_interface = iface
            break
    
    if test_interface:
        packet_count = test_simple_capture(test_interface, 5)
        if packet_count == 0 and not is_admin:
            print("\n⚠️ No packets captured. This is likely due to:")
            print("   1. Missing administrator privileges")
            print("   2. Windows Defender/firewall blocking capture")
            print("   3. Interface not having active traffic")
    else:
        print("\n❌ No suitable test interface found")
    
    # Test the Windows packet capture class
    test_windows_packet_capture()
    
    print("\n" + "=" * 50)
    print("📋 Summary:")
    if is_admin:
        print("✅ Administrator privileges: OK")
    else:
        print("❌ Administrator privileges: REQUIRED")
        print("   Run this script as Administrator")
    
    if interfaces:
        print(f"✅ Network interfaces: {len(interfaces)} found")
    else:
        print("❌ Network interfaces: None detected")
    
    print("\n💡 To fix packet capture issues:")
    print("   1. Run as Administrator")
    print("   2. Check Windows Defender settings")
    print("   3. Ensure network interface is active")
    print("   4. Try different network interfaces")

if __name__ == "__main__":
    main()

