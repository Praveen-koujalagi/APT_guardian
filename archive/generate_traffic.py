#!/usr/bin/env python3
"""
Generate Real Network Traffic for APT Guardian Testing
This script creates actual network connections that will be captured.
"""

import socket
import time
import requests
def ping_hosts():
    """Ping multiple hosts to generate ICMP traffic."""
    hosts = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]  # Google, Cloudflare, OpenDNS
    
    print("🏓 Pinging hosts to generate ICMP traffic...")
    for host in hosts:
        try:
            # Use socket to create connection (simulates ping)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, 80))
            sock.close()
            if result == 0:
                print(f"   ✅ Connected to {host}")
            else:
                print(f"   ❌ Failed to connect to {host}")

def browse_websites():
    """Visit websites to generate HTTP/HTTPS traffic."""
    websites = [
        "http://httpbin.org/get",
        "https://api.github.com",
        "http://jsonplaceholder.typicode.com/posts/1"
    ]
    
    print("🌐 Browsing websites to generate HTTP traffic...")
    for url in websites:
        try:
            response = requests.get(url, timeout=5)
            print(f"   ✅ {url} - Status: {response.status_code}")
        except Exception as e:
            print(f"   ❌ {url} - Error: {e}")

def port_scan_local():
    """Scan local ports to generate TCP traffic."""
    print("🔍 Scanning local ports to generate TCP traffic...")
    
    # Common ports to test
    ports = [80, 443, 22, 23, 3389, 5900, 8080, 8443]
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex(("127.0.0.1", port))
            if result == 0:
                print(f"   🔓 Port {port} is open")
            sock.close()
        except:
            pass

def generate_continuous_traffic(duration=30):
    """Generate continuous network traffic for specified duration."""
    print(f"🔄 Generating continuous traffic for {duration} seconds...")
    
    start_time = time.time()
    while time.time() - start_time < duration:
        try:
            # Make a quick request every 2 seconds
            response = requests.get("http://httpbin.org/delay/1", timeout=2)
            print(f"   📡 Request {int(time.time() - start_time)}s - Status: {response.status_code}")
        except:
            pass
        
        time.sleep(2)

def main():
    """Main function to generate various types of network traffic."""
    print("🚀 APT Guardian Network Traffic Generator")
    print("=" * 50)
    print("This will generate real network traffic for testing packet capture.")
    print("=" * 50)
    
    try:
        # Generate different types of traffic
        ping_hosts()
        time.sleep(1)
        
        browse_websites()
        time.sleep(1)
        
        port_scan_local()
        time.sleep(1)
        
        # Ask user if they want continuous traffic
        choice = input("\nGenerate continuous traffic for 30 seconds? (y/n): ").lower()
        if choice == 'y':
            generate_continuous_traffic(30)
        
        print("\n✅ Traffic generation complete!")
        print("💡 Check your APT Guardian dashboard for captured packets!")
        
    except KeyboardInterrupt:
        print("\n⏹️ Traffic generation stopped by user.")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    main()





