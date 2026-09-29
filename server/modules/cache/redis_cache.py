import json
import logging
from typing import Any, Optional

try:
    import redis.asyncio as redis
except ImportError:
    redis = None

from server.config import settings

logger = logging.getLogger(__name__)

if redis is not None:
    RedisClientType = redis.Redis
else:
    RedisClientType = Any

_client: Optional[RedisClientType] = None
_disabled_until: float = 0.0


async def _get_client() -> Optional[RedisClientType]:
    global _client
    global _disabled_until
    if redis is None:
        return None
    if _disabled_until and _disabled_until > __import__("time").time():
        return None
    if _client is not None:
        return _client
    if not settings.REDIS_URL:
        return None
    try:
        _client = redis.from_url(settings.REDIS_URL, decode_responses=True)
    except Exception as exc:
        logger.warning("redis_unavailable", extra={"error": str(exc)})
        _disabled_until = __import__("time").time() + 30
        _client = None
    return _client


async def get_json(key: str) -> Optional[Any]:
    client = await _get_client()
    if client is None:
        return None
    try:
        raw = await client.get(key)
        return json.loads(raw) if raw else None
    except Exception as exc:
        logger.warning("redis_get_failed", extra={"error": str(exc), "key": key})
        _disable_temporarily()
        return None


async def set_json(key: str, value: Any, ttl_seconds: int) -> None:
    client = await _get_client()
    if client is None:
        return
    try:
        await client.set(key, json.dumps(value), ex=ttl_seconds)
    except Exception as exc:
        logger.warning("redis_set_failed", extra={"error": str(exc), "key": key})
        _disable_temporarily()


async def incr(key: str, ttl_seconds: int) -> int:
    client = await _get_client()
    if client is None:
        return 0
    try:
        value = await client.incr(key)
        if value == 1:
            await client.expire(key, ttl_seconds)
        return int(value)
    except Exception as exc:
        logger.warning("redis_incr_failed", extra={"error": str(exc), "key": key})
        _disable_temporarily()
        return 0


async def get_int(key: str) -> Optional[int]:
    client = await _get_client()
    if client is None:
        return None
    try:
        raw = await client.get(key)
        return int(raw) if raw is not None else None
    except Exception as exc:
        logger.warning("redis_get_int_failed", extra={"error": str(exc), "key": key})
        _disable_temporarily()
        return None


async def delete(key: str) -> None:
    client = await _get_client()
    if client is None:
        return
    try:
        await client.delete(key)
    except Exception as exc:
        logger.warning("redis_delete_failed", extra={"error": str(exc), "key": key})
        _disable_temporarily()


async def get_cache_version(account_id: int) -> int:
    key = f"cache:version:{account_id}"
    val = await get_int(key)
    return val if val is not None else 0


async def bump_cache_version(account_id: int) -> int:
    key = f"cache:version:{account_id}"
    # use a long ttl so it doesn't grow unbounded
    val = await incr(key, ttl_seconds=60 * 60 * 24 * 30)
    return val


def _disable_temporarily() -> None:
    global _disabled_until
    _disabled_until = __import__("time").time() + 30
