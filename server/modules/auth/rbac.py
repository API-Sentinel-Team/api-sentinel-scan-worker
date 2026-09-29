"""
Production-grade RBAC — role hierarchy with granular resource permissions.
Roles: ADMIN > SECURITY_ENGINEER > DEVELOPER > MEMBER > AUDITOR > VIEWER
"""
from typing import List, Callable, Optional, Set
from fastapi import HTTPException, Depends, Security, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from .jwt_issuer import JWTIssuer, TokenRevokedError
from server.modules.tenancy.context import set_current_account_id
import logging

logger = logging.getLogger(__name__)
auth_scheme = HTTPBearer(auto_error=False)


class Permission:
    ENDPOINTS_READ    = "endpoints:read"
    ENDPOINTS_WRITE   = "endpoints:write"
    ENDPOINTS_DELETE  = "endpoints:delete"
    TESTS_READ        = "tests:read"
    TESTS_RUN         = "tests:run"
    TESTS_MANAGE      = "tests:manage"
    VULNS_READ        = "vulnerabilities:read"
    VULNS_MANAGE      = "vulnerabilities:manage"
    COMPLIANCE_READ   = "compliance:read"
    COMPLIANCE_EXPORT = "compliance:export"
    TRAFFIC_READ      = "traffic:read"
    TRAFFIC_MANAGE    = "traffic:manage"
    INTEGRATIONS_READ = "integrations:read"
    INTEGRATIONS_WRITE= "integrations:write"
    SOURCE_CODE_READ  = "source_code:read"
    SOURCE_CODE_SCAN  = "source_code:scan"
    CICD_READ         = "cicd:read"
    CICD_TRIGGER      = "cicd:trigger"
    BILLING_READ      = "billing:read"
    BILLING_MANAGE    = "billing:manage"
    USERS_MANAGE      = "users:manage"
    ACCOUNTS_MANAGE   = "accounts:manage"
    AUDIT_READ        = "audit:read"
    AGENT_GUARD_READ  = "agent_guard:read"
    AGENT_GUARD_INSPECT="agent_guard:inspect"
    MCP_SHIELD_MANAGE = "mcp_shield:manage"
    NUCLEI_RUN        = "nuclei:run"
    NUCLEI_READ       = "nuclei:read"
    WORKFLOWS_READ    = "workflows:read"
    WORKFLOWS_MANAGE  = "workflows:manage"
    WORKFLOWS_EXECUTE = "workflows:execute"


_ALL = {v for k, v in vars(Permission).items() if not k.startswith("_") and isinstance(v, str)}

ROLE_PERMISSIONS: dict[str, Set[str]] = {
    "VIEWER": {
        Permission.ENDPOINTS_READ, Permission.TESTS_READ, Permission.VULNS_READ,
        Permission.COMPLIANCE_READ, Permission.TRAFFIC_READ,
        Permission.NUCLEI_READ, Permission.WORKFLOWS_READ, Permission.AGENT_GUARD_READ,
    },
    "AUDITOR": {
        Permission.ENDPOINTS_READ, Permission.TESTS_READ, Permission.VULNS_READ,
        Permission.COMPLIANCE_READ, Permission.COMPLIANCE_EXPORT,
        Permission.TRAFFIC_READ, Permission.AUDIT_READ, Permission.INTEGRATIONS_READ,
        Permission.NUCLEI_READ, Permission.SOURCE_CODE_READ,
        Permission.CICD_READ, Permission.WORKFLOWS_READ, Permission.AGENT_GUARD_READ,
        Permission.BILLING_READ,
    },
    "MEMBER": {
        Permission.ENDPOINTS_READ, Permission.ENDPOINTS_WRITE,
        Permission.TESTS_READ, Permission.TESTS_RUN,
        Permission.VULNS_READ, Permission.COMPLIANCE_READ,
        Permission.TRAFFIC_READ, Permission.INTEGRATIONS_READ,
        Permission.SOURCE_CODE_READ, Permission.WORKFLOWS_READ,
        Permission.NUCLEI_READ, Permission.AGENT_GUARD_READ,
    },
    "DEVELOPER": {
        Permission.ENDPOINTS_READ, Permission.ENDPOINTS_WRITE,
        Permission.TESTS_READ, Permission.TESTS_RUN,
        Permission.VULNS_READ, Permission.COMPLIANCE_READ,
        Permission.TRAFFIC_READ, Permission.TRAFFIC_MANAGE,
        Permission.INTEGRATIONS_READ, Permission.SOURCE_CODE_READ, Permission.SOURCE_CODE_SCAN,
        Permission.CICD_READ, Permission.CICD_TRIGGER,
        Permission.NUCLEI_READ, Permission.NUCLEI_RUN,
        Permission.WORKFLOWS_READ, Permission.WORKFLOWS_EXECUTE,
        Permission.AGENT_GUARD_READ, Permission.AGENT_GUARD_INSPECT,
    },
    "SECURITY_ENGINEER": {
        Permission.ENDPOINTS_READ, Permission.ENDPOINTS_WRITE, Permission.ENDPOINTS_DELETE,
        Permission.TESTS_READ, Permission.TESTS_RUN, Permission.TESTS_MANAGE,
        Permission.VULNS_READ, Permission.VULNS_MANAGE,
        Permission.COMPLIANCE_READ, Permission.COMPLIANCE_EXPORT,
        Permission.TRAFFIC_READ, Permission.TRAFFIC_MANAGE,
        Permission.INTEGRATIONS_READ, Permission.INTEGRATIONS_WRITE,
        Permission.SOURCE_CODE_READ, Permission.SOURCE_CODE_SCAN,
        Permission.CICD_READ, Permission.CICD_TRIGGER,
        Permission.NUCLEI_READ, Permission.NUCLEI_RUN,
        Permission.WORKFLOWS_READ, Permission.WORKFLOWS_MANAGE, Permission.WORKFLOWS_EXECUTE,
        Permission.AGENT_GUARD_READ, Permission.AGENT_GUARD_INSPECT, Permission.MCP_SHIELD_MANAGE,
        Permission.AUDIT_READ, Permission.BILLING_READ,
    },
    "ADMIN": _ALL,
    # Cross-tenant oversight role for the platform operator. Same permission
    # surface as ADMIN but additionally authorized to read across accounts
    # (e.g. /organization list). Tenant scoping in routers still applies.
    "PLATFORM_ADMIN": _ALL,
}


def get_role_permissions(role: str) -> Set[str]:
    return ROLE_PERMISSIONS.get(role.upper(), ROLE_PERMISSIONS["VIEWER"])


class RBAC:
    @staticmethod
    async def require_auth(request: Request, token: Optional[HTTPAuthorizationCredentials] = Security(auth_scheme)) -> dict:
        token_str = None
        if token and hasattr(token, "credentials"):
            token_str = token.credentials
        elif request.headers.get("authorization", "").lower().startswith("bearer "):
            token_str = request.headers.get("authorization", "").split(" ", 1)[1].strip()
        elif "access_token" in request.cookies:
            token_str = request.cookies["access_token"]
            
        if not token_str:
            raise HTTPException(401, "Authorization header or cookie missing")
            
        try:
            payload = await JWTIssuer.verify_token(token_str)
        except TokenRevokedError:
            raise HTTPException(401, "Token has been revoked. Please log in again.")
        except Exception as e:
            raise HTTPException(401, f"Invalid or expired token: {str(e)}")
            
        if not payload.get("user_id") and payload.get("sub"):
            payload["user_id"] = payload.get("sub")
        payload["_permissions"] = get_role_permissions(payload.get("role", "VIEWER"))
        set_current_account_id(payload.get("account_id"))
        return payload

    @staticmethod
    def require_role(roles: List[str]) -> Callable:
        async def dependency(payload: dict = Depends(RBAC.require_auth)):
            user_role = payload.get("role", "VIEWER").upper()
            if user_role == "ADMIN":
                return payload
            if user_role not in {r.upper() for r in roles}:
                raise HTTPException(403, f"Role '{user_role}' not authorized. Required: {roles}")
            return payload
        return dependency

    @staticmethod
    def require_permission(permission: str) -> Callable:
        async def dependency(payload: dict = Depends(RBAC.require_auth)):
            if permission not in get_role_permissions(payload.get("role", "VIEWER")):
                raise HTTPException(403, f"Permission '{permission}' required")
            return payload
        return dependency


# Shortcuts
require_admin             = RBAC.require_role(["ADMIN"])
require_security_engineer = RBAC.require_role(["ADMIN", "SECURITY_ENGINEER"])
require_developer         = RBAC.require_role(["ADMIN", "SECURITY_ENGINEER", "DEVELOPER", "MEMBER"])
require_auditor           = RBAC.require_role(["ADMIN", "SECURITY_ENGINEER", "DEVELOPER", "AUDITOR", "MEMBER"])
require_member            = RBAC.require_role(["ADMIN", "SECURITY_ENGINEER", "DEVELOPER", "MEMBER"])
can_run_tests             = RBAC.require_permission(Permission.TESTS_RUN)
can_manage_vulns          = RBAC.require_permission(Permission.VULNS_MANAGE)
can_run_nuclei            = RBAC.require_permission(Permission.NUCLEI_RUN)
can_trigger_cicd          = RBAC.require_permission(Permission.CICD_TRIGGER)
can_manage_billing        = RBAC.require_permission(Permission.BILLING_MANAGE)
