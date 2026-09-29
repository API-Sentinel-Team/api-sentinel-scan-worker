"""
Builds the roles_access_context used by BFLA templates.

Akto BFLA templates reference ${roles_access_context.MEMBER} and
${roles_access_context.ADMIN} to inject role-specific auth tokens.

This module resolves those substitutions from configured test accounts.
"""

from server.modules.identity.role_keys import authorization_role_key
from server.modules.identity.test_account_secrets import TestAccountSecretCodec


_ANONYMOUS_ROLE_KEYS = {"ANONYMOUS", "UNAUTHENTICATED", "PUBLIC", "GUEST"}


class RolesContextBuilder:
    """
    Builds the roles_access_context dict from a list of TestAccount objects.

    roles_access_context = {
        "ADMIN":  "Bearer <admin_token>",
        "MEMBER": "Bearer <member_token>",
    }
    """

    def build(self, test_accounts: list) -> dict:
        """
        test_accounts: list of TestAccount ORM objects or dicts with
                       {role: str, auth_headers: {header_key: value}}
        """
        context = {}
        for account in test_accounts:
            role = authorization_role_key(account)
            auth_headers = self._auth_headers(account)
            if role in _ANONYMOUS_ROLE_KEYS:
                context[role] = ""
                continue
            if role and auth_headers:
                # Store the full header value for the first auth header found
                token_value = next(iter(auth_headers.values()), "")
                context[role] = token_value
        return context

    def flatten(self, roles_context: dict) -> dict:
        """
        Flatten to template variable names:
        {"roles_access_context.ADMIN": "Bearer ...", "roles_access_context.MEMBER": "Bearer ..."}
        """
        return {f"roles_access_context.{k}": v for k, v in roles_context.items()}

    def _get_field(self, obj, field: str):
        if isinstance(obj, dict):
            return obj.get(field)
        return getattr(obj, field, None)

    def _auth_headers(self, obj) -> dict:
        if isinstance(obj, dict):
            return TestAccountSecretCodec.decrypt_headers(obj.get("auth_headers") or {})
        return TestAccountSecretCodec.auth_headers(obj)

    def get_attacker_token(self, roles_context: dict, attacker_role: str = "MEMBER") -> str:
        """Return the attacker's auth token for BOLA tests."""
        role_key = authorization_role_key({"role": attacker_role})
        return roles_context.get(role_key or "", "")

    def get_victim_token(self, roles_context: dict, victim_role: str = "ADMIN") -> str:
        """Return the victim's auth token."""
        role_key = authorization_role_key({"role": victim_role})
        return roles_context.get(role_key or "", "")
