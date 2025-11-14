#!/usr/bin/env python3
"""Comprehensive timestamp test including simulated traffic"""
import time
from utils.windows_packet_capture import WindowsPacketCapture

def test_comprehensive_timestamps():
    print("🔍 Comprehensive Timestamp Test")
    print("=" * 50)
    
    pc = WindowsPacketCapture()
    print(f"✅ Created packet capture object")
    print(f"   Interface: {pc.interface}")
    
    # Start capture
    if pc.start():
        print("✅ Started packet capture")
        
        # Wait for real packets
        print("   Waiting 3 seconds for real packets...")
        time.sleep(3)
        
        # Generate some simulated traffic to test timestamp handling
        print("   Generating simulated traffic...")
        pc._generate_simulated_traffic()
        
        # Wait a bit more
        time.sleep(2)
        
        # Get all packets
        packets = pc.get_recent_packets(20)
        print(f"   Total packets: {len(packets)}")
        print()
        
        if packets:
            # Show first few packets with timestamps
            print("📦 Packet Timestamps:")
            for i, pkt in enumerate(packets[:5]):
                print(f"Packet {i+1}:")
                print(f"  Timestamp: {pkt['timestamp']}")
                print(f"  Source: {pkt['src_ip']} -> {pkt['dst_ip']}")
                print(f"  Protocol: {pkt['protocol']}")
                print()
            
            # Analyze timestamp diversity
            timestamps = [pkt['timestamp'] for pkt in packets]
            unique_timestamps = set(timestamps)
            
            print(f"📊 Timestamp Analysis:")
            print(f"   Total packets: {len(packets)}")
            print(f"   Unique timestamps: {len(unique_timestamps)}")
            print(f"   All same timestamp: {len(unique_timestamps) == 1}")
            
            if len(unique_timestamps) > 1:
                print("✅ SUCCESS: Packets have different timestamps!")
                
                # Show timestamp differences
                print("\n🕐 Timestamp Details:")
                sorted_timestamps = sorted(unique_timestamps)
                for i, ts in enumerate(sorted_timestamps[:5]):
                    print(f"   {i+1}. {ts}")
                
                # Check if timestamps are realistic (not all the same)
                if len(unique_timestamps) >= 3:
                    print("\n🎯 Timestamp Quality: EXCELLENT")
                elif len(unique_timestamps) >= 2:
                    print("\n🎯 Timestamp Quality: GOOD")
                else:
                    print("\n🎯 Timestamp Quality: POOR")
                    
            else:
                print("⚠️  All packets still have the same timestamp")
                print("   This indicates the timestamp fix didn't work")
                
        else:
            print("⚠️  No packets captured")
            
        # Stop capture
        pc.stop()
        print("✅ Stopped packet capture")
        
    else:
        print("❌ Failed to start packet capture")

if __name__ == "__main__":
    test_comprehensive_timestamps()




