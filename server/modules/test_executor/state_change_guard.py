from __future__ import annotations

import re

from server.modules.utils.redactor import Redactor


class StateChangeBlocked(ValueError):
    """Raised when a scan request would change server-side state in safe mode."""


class StateChangeGuard:
    """Prevents active pentest traffic from mutating APIs unless explicitly allowed."""

    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
    DESTRUCTIVE_METHODS = {"DELETE", "PATCH", "POST", "PUT"}
    METHOD_OVERRIDE_HEADERS = {
        "x-http-method",
        "x-http-method-override",
        "x-method-override",
    }

    def __init__(
        self,
        *,
        allow_state_change: bool = False,
        allow_destructive_methods: bool = False,
    ):
        self.allow_state_change = bool(allow_state_change)
        self.allow_destructive_methods = bool(allow_destructive_methods)

    @classmethod
    def is_safe_method(cls, method: str | None) -> bool:
        return (method or "GET").upper() in cls.SAFE_METHODS

    @classmethod
    def is_destructive_method(cls, method: str | None) -> bool:
        return (method or "GET").upper() in cls.DESTRUCTIVE_METHODS

    @classmethod
    def normalize_method_tokens(cls, method: str | None) -> list[str]:
        text = str(method or "GET").strip().upper()
        tokens = [token for token in re.split(r"[\s,]+", text) if token]
        return tokens or ["GET"]

    @classmethod
    def effective_methods(cls, request: dict) -> list[str]:
        methods = cls.normalize_method_tokens(request.get("method") or "GET")
        headers = request.get("headers") or {}
        if not isinstance(headers, dict):
            return methods

        for key, value in headers.items():
            if str(key).lower() in cls.METHOD_OVERRIDE_HEADERS and value:
                methods.extend(cls.normalize_method_tokens(str(value)))
        return methods

    @classmethod
    def has_composite_method_override(cls, request: dict) -> bool:
        headers = request.get("headers") or {}
        if not isinstance(headers, dict):
            return False

        return any(
            len(cls.normalize_method_tokens(str(value))) > 1
            for key, value in headers.items()
            if str(key).lower() in cls.METHOD_OVERRIDE_HEADERS and value
        )

    @classmethod
    def effective_state_change_method(cls, request: dict) -> str:
        methods = cls.effective_methods(request)
        for method in reversed(methods):
            if cls.is_destructive_method(method):
                return method
        for method in methods:
            if not cls.is_safe_method(method):
                return method
        return methods[-1] if methods else "GET"

    def validate_method(self, method: str | None) -> None:
        self._validate_normalized_methods(self.normalize_method_tokens(method))

    def validate_request(self, request: dict) -> None:
        self._validate_normalized_methods(self.effective_methods(request))

    def _validate_normalized_methods(self, methods: list[str]) -> None:
        for method in methods:
            if not self.allow_state_change and not self.is_safe_method(method):
                raise StateChangeBlocked(
                    f"state_change_blocked: {method} requires pentest profile allow_state_change=true"
                )
        for method in reversed(methods):
            if self.is_destructive_method(method) and not self.allow_destructive_methods:
                raise StateChangeBlocked(
                    "destructive_method_blocked: "
                    f"{method} requires execute.allow_destructive_methods=true and "
                    "pentest profile allow_state_change=true"
                )


def state_change_policy_for_request(
    request: dict,
    guard: StateChangeGuard,
    *,
    reason: str | None = None,
    blocked: bool = True,
) -> dict[str, object]:
    method = str(request.get("method") or "GET").upper()
    effective_method = StateChangeGuard.effective_state_change_method(request)
    destructive_method = StateChangeGuard.is_destructive_method(effective_method)
    policy: dict[str, object] = {
        "policy": "state_change_guard",
        "blocked": bool(blocked),
        "method": method,
        "effective_method": effective_method,
        "safe_method": StateChangeGuard.is_safe_method(effective_method),
        "destructive_method": destructive_method,
        "allow_state_change": bool(guard.allow_state_change),
        "allow_destructive_methods": bool(guard.allow_destructive_methods),
    }
    if reason is not None:
        policy["reason"] = Redactor.redact_text(reason)
    if StateChangeGuard.has_composite_method_override(request):
        policy["effective_methods"] = StateChangeGuard.effective_methods(request)
    return policy
