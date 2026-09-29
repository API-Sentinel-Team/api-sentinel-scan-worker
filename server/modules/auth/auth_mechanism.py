"""
Authentication mechanism detection and management.
Used for BOLA/BFLA test templates to identify and manipulate auth headers.
"""
import re
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, asdict


@dataclass
class AuthMechanism:
    """Represents an authentication mechanism discovered on an endpoint."""
    name: str
    header_key: str = "Authorization"
    prefix: str = "Bearer "
    token_type: str = "BEARER"
    extract_regex: Optional[str] = None
    refreshable: bool = False
    scopes: List[str] = None

    def __post_init__(self):
        if self.scopes is None:
            self.scopes = []

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AuthMechanismDetector:
    """
    Detects authentication mechanisms from HTTP headers and request patterns.
    Supports: Bearer tokens, API keys, Basic auth, OAuth2, Custom headers.
    """

    # Known auth header patterns
    AUTH_PATTERNS = [
        (r'^Bearer\s+(.+)$', 'Bearer', 'Authorization', 'BEARER'),
        (r'^(.+)$', 'Token', 'Authorization', 'TOKEN'),
        (r'^Basic\s+(.+)$', 'Basic', 'Authorization', 'BASIC'),
        (r'^(X-API-Key|API-Key|X-API-KEY)\s*:\s*(.+)$', 'API Key', 'X-API-Key', 'API_KEY'),
        (r'^(X-Auth-Token|X-Auth-Token)\s*:\s*(.+)$', 'Auth Token', 'X-Auth-Token', 'AUTH_TOKEN'),
        (r'^(X-JWT|X-JWT-TOKEN)\s*:\s*(.+)$', 'JWT', 'X-JWT', 'JWT'),
    ]

    @classmethod
    def detect_from_headers(cls, headers: Dict[str, str]) -> List[AuthMechanism]:
        """
        Detect authentication mechanisms from HTTP headers.
        Returns list of detected mechanisms.
        """
        mechanisms = []
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            if header_lower in ['authorization', 'x-api-key', 'x-auth-token', 'x-jwt', 'api-key']:
                for pattern, name, header_key, token_type in cls.AUTH_PATTERNS:
                    if re.match(pattern, header_value, re.IGNORECASE):
                        mechanisms.append(AuthMechanism(
                            name=name,
                            header_key=header_name,
                            prefix=cls._get_prefix(header_value, pattern),
                            token_type=token_type
                        ))
                        break
        return mechanisms

    @classmethod
    def _get_prefix(cls, header_value: str, pattern: str) -> str:
        """Extract the prefix from the header value."""
        match = re.match(pattern, header_value, re.IGNORECASE)
        if match:
            return header_value[:match.start(1)]
        return "Bearer "

    @classmethod
    def get_auth_header(cls, token: str, mechanism: Optional[AuthMechanism] = None) -> Dict[str, str]:
        """
        Generate an auth header dict for the given token.
        """
        if mechanism:
            return {mechanism.header_key: f"{mechanism.prefix}{token}"}
        return {"Authorization": f"Bearer {token}"}


class AuthMechanismManager:
    """
    Manages authentication mechanisms for test accounts.
    Used in BOLA/BFLA testing to switch between different auth contexts.
    """

    def __init__(self):
        self._mechanisms: Dict[str, AuthMechanism] = {}

    def register_mechanism(self, name: str, mechanism: AuthMechanism):
        """Register a named authentication mechanism."""
        self._mechanisms[name] = mechanism

    def get_mechanism(self, name: str) -> Optional[AuthMechanism]:
        """Get a registered mechanism by name."""
        return self._mechanisms.get(name)

    def get_all_mechanisms(self) -> Dict[str, AuthMechanism]:
        """Get all registered mechanisms."""
        return self._mechanisms.copy()

    @classmethod
    def create_default_mechanisms(cls) -> 'AuthMechanismManager':
        """Create a manager with default authentication mechanisms."""
        manager = AuthMechanismManager()
        
        # Bearer Token (most common)
        manager.register_mechanism("bearer", AuthMechanism(
            name="Bearer Token",
            header_key="Authorization",
            prefix="Bearer ",
            token_type="BEARER"
        ))
        
        # API Key
        manager.register_mechanism("api_key", AuthMechanism(
            name="API Key",
            header_key="X-API-Key",
            prefix="",
            token_type="API_KEY"
        ))
        
        # JWT
        manager.register_mechanism("jwt", AuthMechanism(
            name="JWT",
            header_key="Authorization",
            prefix="Bearer ",
            token_type="JWT",
            refreshable=True
        ))
        
        # Basic Auth
        manager.register_mechanism("basic", AuthMechanism(
            name="Basic Auth",
            header_key="Authorization",
            prefix="Basic ",
            token_type="BASIC"
        ))
        
        return manager
