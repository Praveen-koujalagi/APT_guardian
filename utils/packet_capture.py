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
