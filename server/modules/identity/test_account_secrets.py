from __future__ import annotations

from typing import Any

from server.models.core import TestAccount
from server.modules.auth.encryption import Encryption


class TestAccountSecretCodec:
    """Encrypts BOLA/BFLA test-account auth material while supporting legacy plaintext rows."""

    PREFIX = "enc:v1:"

    @classmethod
    def encrypt_payload(cls, payload: dict[str, Any]) -> dict[str, Any]:
        encrypted = dict(payload)
        encrypted["auth_token"] = cls.encrypt_value(encrypted.get("auth_token"))
        encrypted["auth_headers"] = cls.encrypt_headers(encrypted.get("auth_headers") or {})
        return encrypted

    @classmethod
    def encrypt_value(cls, value: Any) -> Any:
        if value is None or value == "":
            return value
        if isinstance(value, str) and value.startswith(cls.PREFIX):
            return value
        return f"{cls.PREFIX}{Encryption.encrypt(str(value))}"

    @classmethod
    def decrypt_value(cls, value: Any) -> Any:
        if not isinstance(value, str) or not value.startswith(cls.PREFIX):
            return value
        return Encryption.decrypt(value[len(cls.PREFIX):])

    @classmethod
    def encrypt_headers(cls, headers: dict[str, Any] | None) -> dict[str, Any]:
        return {str(key): cls.encrypt_value(value) for key, value in (headers or {}).items()}

    @classmethod
    def decrypt_headers(cls, headers: dict[str, Any] | None) -> dict[str, str]:
        return {str(key): str(cls.decrypt_value(value)) for key, value in (headers or {}).items()}

    @classmethod
    def auth_token(cls, account: TestAccount) -> str | None:
        token = cls.decrypt_value(getattr(account, "auth_token", None))
        return str(token) if token else None

    @classmethod
    def auth_headers(cls, account: TestAccount) -> dict[str, str]:
        return cls.decrypt_headers(getattr(account, "auth_headers", None) or {})

    @classmethod
    def has_secret(cls, account: TestAccount) -> bool:
        return bool(getattr(account, "auth_headers", None) or getattr(account, "auth_token", None))
