#!/usr/bin/env python3
"""Test improved timestamp handling"""
import time
from utils.windows_packet_capture import WindowsPacketCapture

def test_improved_timestamps():
    print("🔍 Testing improved timestamp handling...")
    print("=" * 50)
    
    pc = WindowsPacketCapture()
    print(f"✅ Created packet capture object")
    print(f"   Interface: {pc.interface}")
    
    # Start capture
    if pc.start():
        print("✅ Started packet capture")
        print("   Waiting 5 seconds for packets...")
        time.sleep(5)
        
        # Get recent packets
        packets = pc.get_recent_packets(5)
        print(f"   Captured {len(packets)} packets")
        print()
        
        # Show timestamps
        for i, pkt in enumerate(packets):
            print(f"Packet {i+1}:")
            print(f"  Timestamp: {pkt['timestamp']}")
            print(f"  Source: {pkt['src_ip']} -> {pkt['dst_ip']}")
            print(f"  Protocol: {pkt['protocol']}")
            print()
        
        # Stop capture
        pc.stop()
        print("✅ Stopped packet capture")
        
        # Check if timestamps are different
        if len(packets) > 1:
            timestamps = [pkt['timestamp'] for pkt in packets]
            unique_timestamps = set(timestamps)
            print(f"📊 Timestamp Analysis:")
            print(f"   Total packets: {len(packets)}")
            print(f"   Unique timestamps: {len(unique_timestamps)}")
            print(f"   All same timestamp: {len(unique_timestamps) == 1}")
            
            if len(unique_timestamps) > 1:
                print("✅ SUCCESS: Packets have different timestamps!")
            else:
                print("⚠️  All packets still have the same timestamp")
        else:
            print("⚠️  Not enough packets to analyze timestamps")
            
    else:
        print("❌ Failed to start packet capture")

if __name__ == "__main__":
    test_improved_timestamps()
