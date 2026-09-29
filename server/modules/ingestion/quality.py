"""Capture quality scoring for ingestion events."""
from __future__ import annotations

from typing import Any, Dict


def compute_quality(event: Dict[str, Any]) -> float:
    """Return 0.0-1.0 quality score based on field completeness."""
    total = 6
    score = 0
    req = event.get("request") or {}
    resp = event.get("response") or {}
    if req.get("method"):
        score += 1
    if req.get("path"):
        score += 1
    if req.get("host"):
        score += 1
    if resp.get("status_code") is not None:
        score += 1
    if event.get("observed_at"):
        score += 1
    if event.get("source_ip"):
        score += 1
    return score / total
