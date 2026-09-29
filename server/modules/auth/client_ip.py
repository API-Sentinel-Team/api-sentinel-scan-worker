"""Trusted client IP extraction behind nginx / ingress.

Never trust the leftmost X-Forwarded-For value alone — clients can spoof it.
Our SPA nginx overwrites X-Forwarded-For with $remote_addr (after real_ip),
and sets X-Real-IP to the same. Prefer those; fall back to the peer address.
"""
from __future__ import annotations

import ipaddress

from fastapi import Request


def _valid_ip(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return candidate


def get_client_ip(request: Request) -> str:
    """Return the connecting client IP for rate limiting and audit."""
    # nginx: proxy_set_header X-Real-IP $remote_addr (post–real_ip)
    real_ip = _valid_ip(request.headers.get("x-real-ip"))
    if real_ip:
        return real_ip

    # If a single XFF hop was set by our proxy (overwrite, not append), use it.
    xff = request.headers.get("x-forwarded-for")
    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        # Prefer the rightmost hop (added by the nearest trusted proxy).
        for part in reversed(parts):
            ip = _valid_ip(part)
            if ip:
                return ip

    if request.client and request.client.host:
        return request.client.host
    return "unknown"
