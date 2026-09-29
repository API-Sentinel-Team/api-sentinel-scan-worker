"""
Comprehensive input validation for security hardening.

Implements:
- Max length enforcement
- Path traversal prevention
- XSS sanitization (HTML entity encoding)
- Email validation
- UUID validation
- Integer range validation
"""

import re
import logging
from typing import Any, Optional
from urllib.parse import unquote

logger = logging.getLogger(__name__)

# Security constraints
MAX_STRING_LENGTH = 4096  # Default max length for strings
MAX_PATH_LENGTH = 2048
MAX_EMAIL_LENGTH = 254  # RFC 5321
MAX_PASSWORD_LENGTH = 72  # Bcrypt limit
MAX_COLLECTION_SIZE = 10000

# Dangerous path patterns
DANGEROUS_PATH_PATTERNS = [
    r"\.\.",  # Directory traversal
    r"//+",  # Multiple slashes
    r"\\",  # Backslash
    r"(?i)^(con|prn|aux|nul|com\d|lpt\d)$",  # Windows reserved names
]

# XSS dangerous patterns
XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",  # Script tags
    r"javascript:",  # JavaScript protocol
    r"on\w+\s*=",  # Event handlers (onclick, onload, etc)
    r"<iframe[^>]*>",  # Iframe tags
    r"<object[^>]*>",  # Object tags
    r"<embed[^>]*>",  # Embed tags
]

# SQL injection signatures (kept narrow to avoid false positives on normal text)
SQLI_PATTERNS = [
    r"(?i)'\s*or\s*'[^']+'\s*=\s*'[^']+'",  # ' OR '1'='1
    r'(?i)"\s*or\s*"[^"]+"\s*=\s*"[^"]+"',  # " OR "1"="1
    r"(?i)'\s*or\s*'?\d+'?\s*=\s*'?\d+'?",  # ' OR '1'='1 or ' OR 1=1
    r"(?i)\bunion\s+select\b",
    r"(?i)\bdrop\s+table\b",
    r"(?i)--\s*$",
]

# Email regex (simplified RFC 5322)
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

# UUID regex
UUID_REGEX = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE
)


class ValidationError(Exception):
    """Raised when validation fails."""
    pass


class InputValidator:
    """Central validation service for all user inputs."""

    @staticmethod
    def validate_string(
        value: str,
        field_name: str,
        max_length: int = MAX_STRING_LENGTH,
        allow_empty: bool = False,
        pattern: Optional[str] = None
    ) -> str:
        """
        Validate a string input.

        Args:
            value: String to validate
            field_name: Name of the field (for error messages)
            max_length: Maximum allowed length
            allow_empty: Whether empty strings are allowed
            pattern: Optional regex pattern to match

        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(value, str):
            raise ValidationError(f"{field_name}: Must be a string")

        if not allow_empty and not value.strip():
            raise ValidationError(f"{field_name}: Cannot be empty")

        if len(value) > max_length:
            raise ValidationError(f"{field_name}: Exceeds max length of {max_length}")

        for sqli_pattern in SQLI_PATTERNS:
            if re.search(sqli_pattern, value):
                logger.warning(f"sqli_attempt: {field_name}={value[:100]}")
                raise ValidationError(f"{field_name}: Contains potentially dangerous content")

        if pattern:
            if not re.match(pattern, value):
                raise ValidationError(f"{field_name}: Invalid format")

        return value.strip()

    @staticmethod
    def validate_path(path: str, field_name: str = "path") -> str:
        """
        Validate file paths to prevent directory traversal attacks.

        Rejects:
        - ".." sequences
        - Multiple consecutive slashes
        - Backslashes
        - Windows reserved names
        """
        if not isinstance(path, str):
            raise ValidationError(f"{field_name}: Must be a string")

        # Decode URL-encoded paths
        decoded_path = unquote(path)

        # Check against dangerous patterns
        for pattern in DANGEROUS_PATH_PATTERNS:
            if re.search(pattern, decoded_path):
                logger.warning(f"path_traversal_attempt: {field_name}={path}")
                raise ValidationError(f"{field_name}: Invalid path format (potential traversal)")

        if len(decoded_path) > MAX_PATH_LENGTH:
            raise ValidationError(f"{field_name}: Path exceeds max length")

        return decoded_path

    @staticmethod
    def validate_email(email: str) -> str:
        """
        Validate email address format.

        Enforces RFC 5321 length limits and basic format validation.
        """
        if not isinstance(email, str):
            raise ValidationError("email: Must be a string")

        email = email.strip().lower()

        if not email or len(email) > MAX_EMAIL_LENGTH:
            raise ValidationError(f"email: Invalid length (max {MAX_EMAIL_LENGTH} chars)")

        if not EMAIL_REGEX.match(email):
            raise ValidationError("email: Invalid email format")

        return email

    @staticmethod
    def validate_uuid(value: str, field_name: str = "id") -> str:
        """Validate UUID format (v4)."""
        if not isinstance(value, str):
            raise ValidationError(f"{field_name}: Must be a string")

        value = value.strip()

        if not UUID_REGEX.match(value):
            raise ValidationError(f"{field_name}: Invalid UUID format")

        return value.lower()

    @staticmethod
    def validate_integer(
        value: Any,
        field_name: str,
        min_value: Optional[int] = None,
        max_value: Optional[int] = None
    ) -> int:
        """
        Validate integer input with optional range constraints.
        """
        try:
            if isinstance(value, str):
                value = int(value)
            elif not isinstance(value, int):
                raise ValueError()

            if min_value is not None and value < min_value:
                raise ValidationError(f"{field_name}: Must be >= {min_value}")

            if max_value is not None and value > max_value:
                raise ValidationError(f"{field_name}: Must be <= {max_value}")

            return value
        except (ValueError, TypeError):
            raise ValidationError(f"{field_name}: Must be a valid integer")

    @staticmethod
    def sanitize_html(text: str, field_name: str = "text") -> str:
        """
        Sanitize HTML input by encoding dangerous characters.

        Encodes &, <, >, ", ' to prevent XSS attacks.
        Also checks for dangerous JavaScript patterns.
        """
        if not isinstance(text, str):
            raise ValidationError(f"{field_name}: Must be a string")

        # Check for dangerous XSS patterns
        for pattern in XSS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                logger.warning(f"xss_attempt: {field_name}={text[:100]}")
                raise ValidationError(f"{field_name}: Contains potentially dangerous content")

        # HTML entity encoding
        text = (
            text
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#x27;")
        )

        return text

    @staticmethod
    def validate_password(password: str) -> str:
        """
        Validate password meets security requirements.

        Requirements:
        - Minimum 12 characters
        - Maximum 72 characters (bcrypt limit)
        - At least one digit
        - At least one letter
        - At least one special character
        """
        if not isinstance(password, str):
            raise ValidationError("password: Must be a string")

        if len(password) < 12:
            raise ValidationError("password: Must be at least 12 characters")

        if len(password) > MAX_PASSWORD_LENGTH:
            raise ValidationError(f"password: Cannot exceed {MAX_PASSWORD_LENGTH} characters")

        if not any(c.isdigit() for c in password):
            raise ValidationError("password: Must contain at least one digit")

        if not any(c.isalpha() for c in password):
            raise ValidationError("password: Must contain at least one letter")

        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            raise ValidationError("password: Must contain at least one special character")

        return password

    @staticmethod
    def validate_collection_size(
        collection: list,
        field_name: str,
        max_size: int = MAX_COLLECTION_SIZE
    ) -> list:
        """Validate collection size to prevent DoS attacks."""
        if not isinstance(collection, (list, tuple)):
            raise ValidationError(f"{field_name}: Must be a list")

        if len(collection) > max_size:
            raise ValidationError(f"{field_name}: Exceeds max size of {max_size}")

        return collection

    @staticmethod
    def validate_json_depth(obj: Any, max_depth: int = 20, current_depth: int = 0) -> bool:
        """
        Validate JSON object depth to prevent stack overflow attacks.
        """
        if current_depth > max_depth:
            return False

        if isinstance(obj, dict):
            for v in obj.values():
                if not InputValidator.validate_json_depth(v, max_depth, current_depth + 1):
                    return False
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                if not InputValidator.validate_json_depth(item, max_depth, current_depth + 1):
                    return False

        return True
