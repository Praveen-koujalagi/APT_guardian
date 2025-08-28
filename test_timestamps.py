#!/usr/bin/env python3
"""Test script to check packet timestamps"""
from scapy.all import sniff, IP
import time
from datetime import datetime, timezone

def test_packet_timestamps():
    print("🔍 Testing packet timestamps...")
    print("=" * 40)
    
    # Capture a few packets
    print("Capturing 3 packets...")
    packets = sniff(count=3, timeout=10, store=1)
    
    print(f"Captured {len(packets)} packets")
    print()
    
    for i, pkt in enumerate(packets):
        print(f"Packet {i+1}:")
        
        # Check if packet has time attribute
        if hasattr(pkt, 'time'):
            print(f"  Scapy time: {pkt.time}")
            print(f"  Scapy time type: {type(pkt.time)}")
            
            # Convert to datetime if it's a float
            if isinstance(pkt.time, float):
                dt = datetime.fromtimestamp(pkt.time, tz=timezone.utc)
                print(f"  Converted: {dt.isoformat()}")
        else:
            print("  No time attribute")
        
        # Current time when processing
        current_time = datetime.now(timezone.utc)
        print(f"  Current time: {current_time.isoformat()}")
        
        # Check if IP layer exists
        if IP in pkt:
            print(f"  IP: {pkt[IP].src} -> {pkt[IP].dst}")
        
        print()

if __name__ == "__main__":
    test_packet_timestamps()
