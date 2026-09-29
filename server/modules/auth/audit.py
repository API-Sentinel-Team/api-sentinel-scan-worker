from sqlalchemy.ext.asyncio import AsyncSession
from server.models.core import AuditLog
from server.modules.auth.encryption import Encryption
from typing import Optional, Dict, Any
import json

SENSITIVE_KEYS = {"password", "token", "secret", "api_key", "authorization", "bearer", "credential"}
QUERYABLE_AUTH_POSTURE_KEYS = {
    "auth_required",
    "auth_profile_id",
    "auth_profile_present",
    "auth_mode",
    "has_runtime_credentials",
}
QUERYABLE_CONTROL_PLANE_VALUES = {
    "auth_context",
    "auth_context_ready",
    "authorization_replay",
    "bfla_replay_testable",
    "body_key",
    "bola_replay_testable",
    "business_logic",
    "llm_api",
    "nuclei_secret_file",
    "passive_findings",
    "path_hint",
    "private_identifier",
    "private_identifier_context_ready",
    "prompt_context_ready",
    "role_context",
    "role_context_ready",
    "schemathesis",
    "schemathesis_execution",
    "state_change_context_ready",
    "state_changing_method",
    "templates_execution",
    "tool_abuse_testable",
    "tool_context",
    "tool_context_ready",
    "workflow_abuse_testable",
    "workflow_context_ready",
    "workflow_path",
    "zap_execution",
    "zap_plan",
}
QUERYABLE_COVERAGE_TARGET_KEYS = {"authorization", "business_logic", "llm_api"}

def _contains_sensitive_data(data: Any) -> bool:
    """Check if data contains potentially sensitive information."""
    if isinstance(data, dict):
        for key, value in data.items():
            key_text = str(key).lower()
            if key_text in QUERYABLE_AUTH_POSTURE_KEYS:
                continue
            if _is_queryable_coverage_target_key(key_text, value):
                if _contains_sensitive_data(value):
                    return True
                continue
            if key_text in QUERYABLE_CONTROL_PLANE_VALUES and isinstance(value, (bool, int, float, type(None))):
                continue
            if any(sensitive in key_text for sensitive in SENSITIVE_KEYS):
                return True
            if _contains_sensitive_data(value):
                return True
        return False
    if isinstance(data, list):
        return any(_contains_sensitive_data(item) for item in data)
    if isinstance(data, str):
        data_text = data.lower()
        if data_text in QUERYABLE_CONTROL_PLANE_VALUES:
            return False
        return any(sensitive in data_text for sensitive in SENSITIVE_KEYS)
    return False


def _is_queryable_coverage_target_key(key_text: str, value: Any) -> bool:
    return (
        key_text in QUERYABLE_COVERAGE_TARGET_KEYS
        and isinstance(value, dict)
        and "template_requested" in value
        and "status" in value
    )

async def log_action(
    db: AsyncSession,
    account_id: int,
    action: str,
    user_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    ip_address: Optional[str] = None
):
    """Immutable trail of user/system actions for security & compliance.
    Sensitive fields are encrypted."""
    details_encrypted = None
    ip_encrypted = None
    
    if details and _contains_sensitive_data(details):
        details_encrypted = Encryption.encrypt(json.dumps(details))
        details = None
    
    if ip_address:
        ip_encrypted = Encryption.encrypt(ip_address)
    
    log = AuditLog(
        account_id=account_id,
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        details=details,
        details_encrypted=details_encrypted,
        ip_address=ip_address if not ip_encrypted else None,
        ip_address_encrypted=ip_encrypted
    )
    db.add(log)
    await db.flush()
