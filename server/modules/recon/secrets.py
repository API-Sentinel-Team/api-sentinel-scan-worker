from __future__ import annotations

from typing import Any

from server.models.core import ReconSourceConfig
from server.modules.auth.encryption import Encryption
from server.modules.utils.redactor import Redactor


class ReconSourceSecretCodec:
    """Encrypts external recon source config while supporting legacy plaintext rows."""

    PREFIX = "enc:v1:"

    @classmethod
    def encrypt_config(cls, config: dict[str, Any] | None) -> dict[str, Any]:
        return cls._encrypt(config or {})

    @classmethod
    def decrypt_config(cls, config: dict[str, Any] | None) -> dict[str, Any]:
        return cls._decrypt(config or {})

    @classmethod
    def runtime_config(cls, source: ReconSourceConfig) -> dict[str, Any]:
        return cls.decrypt_config(getattr(source, "config", None) or {})

    @classmethod
    def redacted_config(cls, source: ReconSourceConfig) -> dict[str, Any]:
        return Redactor.redact_json(cls.runtime_config(source))

    @classmethod
    def _encrypt(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(key): cls._encrypt(item) for key, item in value.items()}
        if isinstance(value, list):
            return [cls._encrypt(item) for item in value]
        if value is None or value == "":
            return value
        if not isinstance(value, str):
            return value
        if value.startswith(cls.PREFIX):
            return value
        return f"{cls.PREFIX}{Encryption.encrypt(value)}"

    @classmethod
    def _decrypt(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(key): cls._decrypt(item) for key, item in value.items()}
        if isinstance(value, list):
            return [cls._decrypt(item) for item in value]
        if not isinstance(value, str) or not value.startswith(cls.PREFIX):
            return value
        return Encryption.decrypt(value[len(cls.PREFIX):])
