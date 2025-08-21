"""Security & adversarial input sanity checks.

Functions here attempt to detect obviously malformed or adversarial feature
vectors prior to model inference. They are intentionally conservative to
avoid excessive false positives while still rejecting egregious cases.
"""
from __future__ import annotations
from typing import Dict, Any, List
import math

# Upper bounds (post-scaling original counts may be standardized – these run pre-scaling)
_RAW_LIMITS = {
    'packet_count': 10_000_000,
    'byte_count': 10_000_000_000,  # 10 GB in a single flow unrealistic
    'src_port': 65535,
    'dst_port': 65535,
}


def sanitize_flow(flow: Dict[str, Any]) -> Dict[str, Any]:
    clean = dict(flow)
    to_drop: List[str] = []
    for k, v in clean.items():
        if isinstance(v, (int, float)):
            if math.isinf(v) or math.isnan(v):
                clean[k] = 0
            # Negative values where not expected
            if k in _RAW_LIMITS and v < 0:
                clean[k] = 0
            # Extreme upper bounds
            if k in _RAW_LIMITS and v > _RAW_LIMITS[k]:
                clean[k] = _RAW_LIMITS[k]
        # Overly long strings (truncate)
        if isinstance(v, str) and len(v) > 200:
            clean[k] = v[:200]
    # Remove keys with suspicious script tags
    for k, v in list(clean.items()):
        if isinstance(v, str) and ('<script' in v.lower() or 'javascript:' in v.lower()):
            to_drop.append(k)
    for k in to_drop:
        clean.pop(k, None)
    return clean


def batch_sanitize(flows: List[Dict[str, Any]]):
    return [sanitize_flow(f) for f in flows]
