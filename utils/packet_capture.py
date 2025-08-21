"""Live packet capture abstraction.

Provides a thin wrapper around scapy's sniff for assembling flows in-memory.
If scapy or required permissions are unavailable (e.g., CI / restricted
environment) it degrades to a synthetic packet generator so the rest of the
pipeline can still exercise logic.
"""
from __future__ import annotations
from typing import Optional, List, Dict, Any
import time
import threading
import random

try:  # pragma: no cover - optional in CI
    from scapy.all import sniff, IP, TCP, UDP  # type: ignore
    _HAS_SCAPY = True
except Exception:  # pragma: no cover
    _HAS_SCAPY = False


class LivePacketCapture:
    def __init__(self, interface: Optional[str] = None, flow_timeout: int = 60):
        self.interface = interface
        self.flow_timeout = flow_timeout
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._synthetic_mode = False
        # Flow table keyed by 5-tuple (src,dst,sport,dport,proto)
        self._flows: Dict[tuple, Dict[str, Any]] = {}

    # ----------------------------------------------------------------------------------
    # Public API
    # ----------------------------------------------------------------------------------
    def start(self):
        if self._running:
            return
        self._running = True
        if _HAS_SCAPY and not self._synthetic_mode:
            self._thread = threading.Thread(target=self._sniff_loop, daemon=True)
        else:
            self._synthetic_mode = True
            self._thread = threading.Thread(target=self._synthetic_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)

    def get_recent_flows(self, limit: int = 50) -> List[Dict[str, Any]]:
        now = time.time()
        # Purge stale flows
        for key, data in list(self._flows.items()):
            if now - data['last_seen'] > self.flow_timeout:
                self._flows.pop(key, None)
        flows = list(self._flows.values())
        flows.sort(key=lambda x: x['last_seen'], reverse=True)
        return flows[:limit]

    # ----------------------------------------------------------------------------------
    # Internal collection loops
    # ----------------------------------------------------------------------------------
    def _sniff_loop(self):  # pragma: no cover
        """Attempt real sniffing; on any runtime failure fallback to synthetic mode."""
        try:
            def _handle(pkt):
                try:
                    if IP in pkt:
                        proto = 'TCP' if TCP in pkt else ('UDP' if UDP in pkt else 'IP')
                        src = pkt[IP].src
                        dst = pkt[IP].dst
                        sport = int(pkt[TCP].sport) if TCP in pkt else (int(pkt[UDP].sport) if UDP in pkt else 0)
                        dport = int(pkt[TCP].dport) if TCP in pkt else (int(pkt[UDP].dport) if UDP in pkt else 0)
                        key = (src, dst, sport, dport, proto)
                        entry = self._flows.get(key)
                        if not entry:
                            entry = {
                                'src_ip': src,
                                'dst_ip': dst,
                                'src_port': sport,
                                'dst_port': dport,
                                'protocol': proto,
                                'packet_count': 0,
                                'byte_count': 0,
                                'first_seen': time.time(),
                                'last_seen': time.time(),
                            }
                            self._flows[key] = entry
                        entry['packet_count'] += 1
                        entry['byte_count'] += len(pkt)
                        entry['last_seen'] = time.time()
                except Exception:
                    pass
            sniff(prn=_handle, store=False, iface=self.interface, stop_filter=lambda x: not self._running)
        except Exception:
            # Fallback exactly once
            if self._running and not self._synthetic_mode:
                self._synthetic_mode = True
                self._synthetic_loop()

    def _synthetic_loop(self):
        while self._running:
            # Generate a few synthetic flows each second
            for _ in range(5):
                src = f"10.0.0.{random.randint(1,10)}"
                dst = f"192.168.1.{random.randint(1,10)}"
                sport = random.randint(1024, 65535)
                dport = random.choice([80, 443, 22, 3389])
                proto = random.choice(['TCP', 'UDP'])
                key = (src, dst, sport, dport, proto)
                entry = self._flows.get(key)
                if not entry:
                    entry = {
                        'src_ip': src,
                        'dst_ip': dst,
                        'src_port': sport,
                        'dst_port': dport,
                        'protocol': proto,
                        'packet_count': 0,
                        'byte_count': 0,
                        'first_seen': time.time(),
                        'last_seen': time.time(),
                    }
                    self._flows[key] = entry
                entry['packet_count'] += 1
                entry['byte_count'] += random.randint(40, 1500)
                entry['last_seen'] = time.time()
            time.sleep(1)
