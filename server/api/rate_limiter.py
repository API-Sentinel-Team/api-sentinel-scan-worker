import logging

from slowapi import Limiter
from fastapi import Request
import jwt

from server.config import settings
from server.modules.auth.client_ip import get_client_ip

logger = logging.getLogger(__name__)


def get_rate_limit_key(request: Request) -> str:
    """
    Rate limit key: IP + account_id when we can resolve tenant safely.

    Uses JWT Bearer first (per-request, no cross-tenant leakage). Falls back to
    request.state.account_id only if middleware set it. Never uses app.state
    (process-global and unsafe for multi-tenant limits).
    """
    client_ip = get_client_ip(request)
    account_id = None

    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        try:
            token = auth_header[7:]
            payload = jwt.decode(
                token,
                settings.JWT_SECRET,
                algorithms=[settings.JWT_ALGORITHM],
                options={"verify_exp": True},
            )
            account_id = payload.get("account_id")
        except Exception as e:
            logger.debug("rate_limit_key_jwt_decode_failed: %s", e)

    if account_id is None:
        account_id = getattr(request.state, "account_id", None)

    if account_id is not None:
        return f"{client_ip}:{account_id}"
    return client_ip


limiter = Limiter(key_func=get_rate_limit_key)
