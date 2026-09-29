"""
Enhanced authentication rate limiter with brute-force protection.
Tracks failed login attempts per IP address and applies exponential backoff.
"""
import time
from datetime import datetime, timedelta, timezone
from server.modules.cache.redis_cache import set_json, get_json, delete
from server.config import settings
import logging

logger = logging.getLogger(__name__)

class AuthRateLimiter:
    """
    Protects /login endpoint from brute-force attacks using Redis.

    Strategy:
    - Track failed attempts per IP (key: f"auth:failed:{ip}")
    - After 3rd failed attempt: exponential backoff (5s, 10s, 20s, etc.)
    - After 10 consecutive failures: auto-add to blocklist for 1 hour
    - Return 429 with Retry-After header (no timing attacks)
    """

    FAILED_ATTEMPTS_KEY_PREFIX = "auth:failed"
    BLOCKLIST_KEY_PREFIX = "auth:blocklist"
    SUCCESS_WINDOW_KEY_PREFIX = "auth:success_window"

    @staticmethod
    async def check_rate_limit(client_ip: str) -> tuple[bool, dict]:
        """
        Check if a client IP is allowed to attempt login.
        Returns: (is_allowed: bool, context: dict with retry_after, attempts, reason)
        """
        if not client_ip:
            client_ip = "unknown"

        # Check blocklist first (1-hour blocks after 10 failures)
        blocklist_key = f"{AuthRateLimiter.BLOCKLIST_KEY_PREFIX}:{client_ip}"
        is_blocked = await get_json(blocklist_key)
        if is_blocked:
            retry_after = 3600  # 1 hour
            return False, {
                "reason": "ip_blocklisted",
                "retry_after": retry_after,
                "message": "Too many failed login attempts. Please try again in 1 hour."
            }

        # Get failed attempts for this IP
        failed_key = f"{AuthRateLimiter.FAILED_ATTEMPTS_KEY_PREFIX}:{client_ip}"
        failed_data = await get_json(failed_key)

        if not failed_data:
            return True, {"attempts": 0, "reason": "none"}

        attempts = failed_data.get("count", 0)
        last_failed_at = failed_data.get("last_failed_at")

        # Exponential backoff: after 3rd attempt, enforce increasing delays
        if attempts >= 3:
            # Calculate backoff delay: 5s * 2^(attempts-3)
            backoff_seconds = 5 * (2 ** (attempts - 3))
            backoff_seconds = min(backoff_seconds, 300)  # Cap at 5 minutes

            # Check if enough time has passed since last failure
            last_failed = datetime.fromisoformat(last_failed_at) if last_failed_at else None
            if last_failed:
                time_since_failure = (datetime.now(timezone.utc) - last_failed).total_seconds()
                if time_since_failure < backoff_seconds:
                    remaining = int(backoff_seconds - time_since_failure)
                    return False, {
                        "reason": "exponential_backoff",
                        "attempts": attempts,
                        "retry_after": remaining,
                        "message": f"Too many failed attempts. Please try again in {remaining} seconds."
                    }

        return True, {"attempts": attempts, "reason": "none"}

    @staticmethod
    async def record_failed_attempt(client_ip: str) -> None:
        """Record a failed login attempt for an IP address."""
        if not client_ip:
            client_ip = "unknown"

        failed_key = f"{AuthRateLimiter.FAILED_ATTEMPTS_KEY_PREFIX}:{client_ip}"
        blocklist_key = f"{AuthRateLimiter.BLOCKLIST_KEY_PREFIX}:{client_ip}"

        # Get current failed attempts
        failed_data = await get_json(failed_key)
        attempts = (failed_data.get("count", 0) if failed_data else 0) + 1

        # Update failed attempts (TTL: 1 hour)
        await set_json(
            failed_key,
            {
                "count": attempts,
                "last_failed_at": datetime.now(timezone.utc).isoformat(),
                "first_failed_at": (failed_data.get("first_failed_at") if failed_data else datetime.now(timezone.utc).isoformat())
            },
            ttl_seconds=3600
        )

        # After 10 consecutive failures, add to blocklist (1 hour)
        if attempts >= 10:
            await set_json(
                blocklist_key,
                {
                    "blocked_at": datetime.now(timezone.utc).isoformat(),
                    "reason": "10_failed_attempts",
                    "attempts": attempts
                },
                ttl_seconds=3600
            )
            logger.warning(
                "auth_brute_force_blocklist",
                extra={"client_ip": client_ip, "attempts": attempts}
            )

    @staticmethod
    async def record_success(client_ip: str) -> None:
        """Record a successful login for an IP (clears failed attempts)."""
        if not client_ip:
            return

        failed_key = f"{AuthRateLimiter.FAILED_ATTEMPTS_KEY_PREFIX}:{client_ip}"
        await delete(failed_key)

        logger.info("auth_success_clear_attempts", extra={"client_ip": client_ip})

    @staticmethod
    def get_retry_after_header(context: dict) -> int:
        """Get the Retry-After value (in seconds) from rate limit context."""
        return context.get("retry_after", 60)
