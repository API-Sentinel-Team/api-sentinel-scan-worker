import asyncio
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from server.config import settings
from server.modules.cache.redis_cache import get_int, incr


@dataclass
class QuotaStatus:
    allowed: bool
    remaining: int
    reset_at: int


_lock = asyncio.Lock()
_memory_counters: Dict[str, Tuple[int, int]] = {}


def _window_key(account_id: int, window_start: int, kind: str = "ingest") -> str:
    return f"quota:{kind}:{account_id}:{window_start}"


async def check_ingest_quota(account_id: int, cost: int = 1) -> QuotaStatus:
    return await _check_quota(
        account_id,
        cost=cost,
        rpm=settings.INGESTION_RATE_LIMIT_RPM,
        kind="ingest",
    )


async def check_cicd_gate_quota(account_id: int, cost: int = 1) -> QuotaStatus:
    return await _check_quota(
        account_id,
        cost=cost,
        rpm=settings.CICD_GATE_RATE_LIMIT_RPM,
        kind="cicd_gate",
    )


async def _check_quota(account_id: int, *, cost: int, rpm: int, kind: str) -> QuotaStatus:
    now = int(time.time())
    window_start = now - (now % 60)
    reset_at = window_start + 60
    key = _window_key(account_id, window_start, kind)

    # Prefer Redis when available
    try:
        current = await get_int(key)
        if current is not None:
            new_val = current
            for _ in range(max(1, cost)):
                new_val = await incr(key, ttl_seconds=70)
            allowed = new_val <= rpm
            remaining = max(0, rpm - new_val)
            return QuotaStatus(allowed=allowed, remaining=remaining, reset_at=reset_at)
    except Exception:
        pass # Fallback to in-memory

    # In-memory fallback
    async with _lock:
        current_val, expires_at = _memory_counters.get(key, (0, reset_at))
        if now >= expires_at:
            current_val = 0
            expires_at = reset_at
        
        new_val = current_val + cost
        _memory_counters[key] = (new_val, expires_at)
        
        # Cleanup old keys sporadically
        if len(_memory_counters) > 100:
            for k in list(_memory_counters.keys()):
                _, exp = _memory_counters[k]
                if now > exp + 60:
                    del _memory_counters[k]

        allowed = new_val <= rpm
        remaining = max(0, rpm - new_val)
        return QuotaStatus(allowed=allowed, remaining=remaining, reset_at=reset_at)


async def peek_ingest_quota(account_id: int) -> QuotaStatus:
    return await _peek_quota(
        account_id,
        rpm=settings.INGESTION_RATE_LIMIT_RPM,
        kind="ingest",
    )


async def peek_cicd_gate_quota(account_id: int) -> QuotaStatus:
    return await _peek_quota(
        account_id,
        rpm=settings.CICD_GATE_RATE_LIMIT_RPM,
        kind="cicd_gate",
    )


async def _peek_quota(account_id: int, *, rpm: int, kind: str) -> QuotaStatus:
    now = int(time.time())
    window_start = now - (now % 60)
    reset_at = window_start + 60
    key = _window_key(account_id, window_start, kind)

    try:
        current = await get_int(key)
        if current is not None:
            remaining = max(0, rpm - current)
            return QuotaStatus(allowed=remaining > 0, remaining=remaining, reset_at=reset_at)
    except Exception:
        pass

    async with _lock:
        current_val, expires_at = _memory_counters.get(key, (0, reset_at))
        if now >= expires_at:
            current_val = 0
        remaining = max(0, rpm - current_val)
        return QuotaStatus(allowed=remaining > 0, remaining=remaining, reset_at=reset_at)
