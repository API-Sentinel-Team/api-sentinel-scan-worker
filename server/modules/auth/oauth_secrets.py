from __future__ import annotations

from typing import Any

from server.models.core import OAuthProvider
from server.modules.auth.encryption import Encryption


class OAuthProviderSecretCodec:
    """Encrypts OAuth provider client secrets while supporting legacy plaintext rows."""

    PREFIX = "enc:v1:"

    @classmethod
    def encrypt_secret(cls, value: Any) -> Any:
        if value is None or value == "":
            return value
        if not isinstance(value, str):
            return value
        if value.startswith(cls.PREFIX):
            return value
        return f"{cls.PREFIX}{Encryption.encrypt(value)}"

    @classmethod
    def decrypt_secret(cls, value: Any) -> Any:
        if not isinstance(value, str) or not value.startswith(cls.PREFIX):
            return value
        return Encryption.decrypt(value[len(cls.PREFIX):])

    @classmethod
    def client_secret(cls, provider: OAuthProvider) -> str:
        secret = cls.decrypt_secret(getattr(provider, "client_secret_enc", None))
        return str(secret or "")
