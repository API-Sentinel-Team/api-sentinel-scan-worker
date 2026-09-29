from __future__ import annotations

from typing import Any

from server.modules.integrations.secrets import IntegrationSecretCodec
from server.modules.utils.redactor import Redactor


SENSITIVE_ACTION_FIELDS = {
    "url",
    "secret",
    "token",
    "token_jti",
    "api_token",
    "personal_access_token",
    "password",
    "webhook_url",
    "headers",
    "config",
    "credentials_json",
}


class PlaybookActionSecretCodec:
    """Encrypts sensitive response playbook action fields while preserving routing fields."""

    @classmethod
    def encrypt_actions(cls, actions: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
        return [cls.encrypt_action(action) for action in (actions or [])]

    @classmethod
    def decrypt_actions(cls, actions: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
        return [cls.decrypt_action(action) for action in (actions or [])]

    @classmethod
    def redact_actions(cls, actions: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
        return [cls.redact_action(action) for action in (actions or [])]

    @classmethod
    def encrypt_action(cls, action: dict[str, Any]) -> dict[str, Any]:
        encrypted = dict(action or {})
        for field in SENSITIVE_ACTION_FIELDS:
            if field in encrypted:
                encrypted[field] = IntegrationSecretCodec.encrypt_config({"value": encrypted[field]})["value"]
        return encrypted

    @classmethod
    def decrypt_action(cls, action: dict[str, Any]) -> dict[str, Any]:
        decrypted = dict(action or {})
        for field in SENSITIVE_ACTION_FIELDS:
            if field in decrypted:
                decrypted[field] = IntegrationSecretCodec.decrypt_config({"value": decrypted[field]})["value"]
        return decrypted

    @classmethod
    def redact_action(cls, action: dict[str, Any]) -> dict[str, Any]:
        redacted = Redactor.redact_json(dict(action or {}))
        if not isinstance(redacted, dict):
            return {}
        for field in SENSITIVE_ACTION_FIELDS:
            if field in redacted:
                redacted[field] = cls._redacted_shape(action.get(field))
        return redacted

    @classmethod
    def _redacted_shape(cls, value: Any) -> Any:
        if isinstance(value, dict):
            return {str(key): cls._redacted_shape(item) for key, item in value.items()}
        if isinstance(value, list):
            return [cls._redacted_shape(item) for item in value]
        if value is None or value == "":
            return value
        return Redactor.REDACT_VALUE
