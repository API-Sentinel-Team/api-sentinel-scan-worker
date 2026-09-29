"""
AuthRotator: fetches and applies auth tokens from TestAccount records.
Used by ExecutionEngine to perform BOLA/BFLA cross-role replays.
"""
import copy
from sqlalchemy import select
from server.models.core import TestAccount
from server.modules.identity.role_keys import authorization_role_key
from server.modules.identity.test_account_secrets import TestAccountSecretCodec


AUTH_HEADERS = ["authorization", "x-api-key", "x-auth-token", "cookie", "token", "x-access-token"]


class AuthRotator:

    async def get_auth_headers(self, role: str = "ATTACKER", account_id: int | None = None, db=None) -> dict:
        """Return auth headers dict for the given role from TestAccount table."""
        if db is None or account_id is None:
            return {}
        try:
            requested_role = authorization_role_key({"role": role})
            if not requested_role:
                return {}
            result = await db.execute(
                select(TestAccount).where(
                    TestAccount.account_id == account_id,
                )
            )
            for acct in result.scalars().all():
                if authorization_role_key(acct) != requested_role:
                    continue
                auth_headers = TestAccountSecretCodec.auth_headers(acct)
                if auth_headers:
                    return auth_headers
                auth_token = TestAccountSecretCodec.auth_token(acct)
                if auth_token:
                    token = str(auth_token)
                    if token.lower().startswith(("bearer ", "basic ")):
                        return {"Authorization": token}
                    return {"Authorization": f"Bearer {token}"}
        except Exception:
            pass
        return {}

    def apply_auth(self, request: dict, auth_headers: dict) -> dict:
        """Replace existing auth headers on the request with the given ones."""
        if not auth_headers:
            return request
        mutated = copy.deepcopy(request)
        existing = mutated.setdefault("headers", {})
        # Remove old auth headers
        cleaned = {k: v for k, v in existing.items() if k.lower() not in AUTH_HEADERS}
        cleaned.update(auth_headers)
        mutated["headers"] = cleaned
        return mutated
