"""Live packet capture abstraction (placeholder)."""
from __future__ import annotations
from typing import Optional


class LivePacketCapture:
    def __init__(self, interface: Optional[str] = None):
        self.interface = interface or "default"

    def start(self):  # placeholder
        return True

    def stop(self):  # placeholder
        return True


# --- Live Capture Demo ---
if __name__ == "__main__":
    from scapy.all import sniff, IP
    from utils.logger import log_security_event

    def process_packet(packet):
        if packet.haslayer(IP):
            src = packet[IP].src
            dst = packet[IP].dst
            # Example: log all packets as 'Low' severity (customize as needed)
            log_security_event(src, dst, "Low", "Live capture: packet detected")

    print("[INFO] Starting live capture mode (press Ctrl+C to stop)...")
    try:
        sniff(prn=process_packet, count=5)  # Capture 5 packets for demo
    except KeyboardInterrupt:
        print("[INFO] Live capture stopped by user.")
