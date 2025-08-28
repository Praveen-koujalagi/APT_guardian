#!/usr/bin/env python3
"""
Network Attack Simulation Script
Use this to test your APT Guardian detection capabilities!
WARNING: This is for testing purposes only. Do not use on production networks.
"""

import time
import socket
import threading
import random
from datetime import datetime

def simulate_port_scan(target_ip="127.0.0.1", ports=None):
    """Simulate a port scan attack."""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5900, 8080]
    
    print(f"🔍 Simulating port scan on {target_ip}...")
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f"   ✅ Port {port} is open")
            sock.close()
            time.sleep(0.05)  # Small delay
        except Exception as e:
            pass
    
    print("✅ Port scan simulation complete!")

def simulate_ddos(target_ip="127.0.0.1", duration=10):
    """Simulate a DDoS attack with rapid connections."""
    print(f"💥 Simulating DDoS attack on {target_ip} for {duration} seconds...")
    
    def send_packets():
        start_time = time.time()
        packet_count = 0
        
        while time.time() - start_time < duration:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect((target_ip, 80))
                sock.close()
                packet_count += 1
                
                if packet_count % 10 == 0:
                    print(f"   📦 Sent {packet_count} packets...")
                
                time.sleep(0.01)  # Very rapid sending
            except:
                pass
        
        print(f"✅ DDoS simulation complete! Sent {packet_count} packets.")
    
    # Run in thread to avoid blocking
    thread = threading.Thread(target=send_packets)
    thread.daemon = True
    thread.start()
    thread.join()

def simulate_suspicious_activity(target_ip="127.0.0.1"):
    """Simulate suspicious network activity."""
    print(f"⚠️ Simulating suspicious activity on {target_ip}...")
    
    # Try to connect to suspicious ports
    suspicious_ports = [22, 23, 3389, 5900, 4444, 31337]
    
    for port in suspicious_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect((target_ip, port))
            print(f"   🔓 Connected to suspicious port {port}")
            sock.close()
            time.sleep(0.1)
        except:
            pass
    
    print("✅ Suspicious activity simulation complete!")

def simulate_normal_traffic(target_ip="127.0.0.1"):
    """Simulate normal network traffic."""
    print(f"🌐 Simulating normal traffic to {target_ip}...")
    
    normal_ports = [80, 443, 8080]
    
    for _ in range(5):
        for port in normal_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect((target_ip, port))
                sock.close()
                time.sleep(0.2)
            except:
                pass
    
    print("✅ Normal traffic simulation complete!")

def main():
    """Main simulation function."""
    print("🚀 APT Guardian Attack Simulation Tool")
    print("=" * 50)
    print("⚠️  WARNING: This tool simulates network attacks for testing purposes.")
    print("    Only use on your own network or authorized testing environments.")
    print("=" * 50)
    
    # Get target IP
    target_ip = input("Enter target IP (default: 127.0.0.1): ").strip()
    if not target_ip:
        target_ip = "127.0.0.1"
    
    print(f"\n🎯 Target: {target_ip}")
    print("\nAvailable simulations:")
    print("1. Port Scan Attack")
    print("2. DDoS Attack")
    print("3. Suspicious Activity")
    print("4. Normal Traffic")
    print("5. Run All Simulations")
    print("6. Exit")
    
    while True:
        choice = input("\nSelect simulation (1-6): ").strip()
        
        if choice == "1":
            simulate_port_scan(target_ip)
        elif choice == "2":
            duration = input("Enter duration in seconds (default: 10): ").strip()
            duration = int(duration) if duration.isdigit() else 10
            simulate_ddos(target_ip, duration)
        elif choice == "3":
            simulate_suspicious_activity(target_ip)
        elif choice == "4":
            simulate_normal_traffic(target_ip)
        elif choice == "5":
            print("\n🔄 Running all simulations...")
            simulate_port_scan(target_ip)
            time.sleep(2)
            simulate_ddos(target_ip, 5)
            time.sleep(2)
            simulate_suspicious_activity(target_ip)
            time.sleep(2)
            simulate_normal_traffic(target_ip)
            print("\n✅ All simulations complete!")
        elif choice == "6":
            print("👋 Goodbye!")
            break
        else:
            print("❌ Invalid choice. Please select 1-6.")
        
        print("\n" + "="*50)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⏹️ Simulation stopped by user.")
    except Exception as e:
        print(f"\n❌ Error during simulation: {e}")
        print("💡 Make sure you have proper permissions and the target is reachable.")

