import re


# Common auth header patterns
AUTH_PATTERNS = {
    "BEARER": re.compile(r"^bearer\s+", re.IGNORECASE),
    "BASIC":  re.compile(r"^basic\s+", re.IGNORECASE),
    "API_KEY": re.compile(r"^[a-zA-Z0-9\-_]{20,}$"),
}

AUTH_HEADER_NAMES = [
    "authorization", "x-api-key", "x-auth-token",
    "x-access-token", "token", "api-key",
]


class AuthMechanismManager:
    """
    Detects which header carries the auth token and manipulates it.
    Mirrors Akto's auth_mechanisms collection logic.
    """

    def detect_auth_header(self, headers: dict) -> tuple[str, str]:
        """
        Returns (header_name, token_type) for the first auth header found.
        e.g. ("Authorization", "BEARER")
        """
        lower = {k.lower(): (k, v) for k, v in headers.items()}
        for name in AUTH_HEADER_NAMES:
            if name in lower:
                original_key, value = lower[name]
                token_type = self._detect_type(value)
                return original_key, token_type
        return "Authorization", "UNKNOWN"

    def remove_auth(self, headers: dict) -> dict:
        """Strip all known auth headers from the request."""
        return {
            k: v for k, v in headers.items()
            if k.lower() not in AUTH_HEADER_NAMES
        }

    def replace_auth(self, headers: dict, attacker_token: str, header_name: str = None) -> dict:
        """
        Remove existing auth headers and inject the attacker's token.
        header_name: override detected header key (e.g. 'Authorization')
        """
        clean = self.remove_auth(headers)
        key = header_name or self.detect_auth_header(headers)[0]
        clean[key] = attacker_token
        return clean

    def _detect_type(self, value: str) -> str:
        for name, pattern in AUTH_PATTERNS.items():
            if pattern.match(value):
                return name
        return "UNKNOWN"

    @staticmethod
    def from_config(config: dict) -> "AuthMechanismConfig":
        """Build from a stored auth_mechanisms DB record."""
        return AuthMechanismConfig(
            header_key=config.get("header_key", "Authorization"),
            prefix=config.get("prefix", "Bearer "),
            token_type=config.get("token_type", "BEARER"),
        )


class AuthMechanismConfig:
    def __init__(self, header_key: str, prefix: str, token_type: str):
        self.header_key = header_key
        self.prefix = prefix
        self.token_type = token_type

    def format_token(self, raw_token: str) -> str:
        if not raw_token.lower().startswith(self.prefix.lower()):
            return f"{self.prefix}{raw_token}"
        return raw_token
