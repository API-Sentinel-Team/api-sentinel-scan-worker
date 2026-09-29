"""
Role-based access control context for BFLA (Broken Function Level Authorization) testing.
Used to track which roles have access to which endpoints and test authorization bypasses.
"""
from typing import Dict, List, Optional, Set, Any
from dataclasses import dataclass, field, asdict
from enum import Enum


class RoleType(Enum):
    """Standard role types for multi-tenant applications."""
    ADMIN = "ADMIN"
    SECURITY_ENGINEER = "SECURITY_ENGINEER"
    DEVELOPER = "DEVELOPER"
    MEMBER = "MEMBER"
    AUDITOR = "AUDITOR"
    VIEWER = "VIEWER"
    ANONYMOUS = "ANONYMOUS"
    ATTACKER = "ATTACKER"


@dataclass
class RolePermission:
    """Represents a permission granted to a role."""
    resource: str  # e.g., "endpoints", "users", "reports"
    action: str    # e.g., "read", "write", "delete", "manage"
    condition: Optional[Dict[str, Any]] = None  # Optional conditions

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class RoleContext:
    """Context for a role including permissions and metadata."""
    name: str
    description: str = ""
    permissions: List[RolePermission] = field(default_factory=list)
    hierarchy_level: int = 0  # For role inheritance (higher = more privileged)
    is_system_role: bool = False

    def has_permission(self, resource: str, action: str) -> bool:
        """Check if this role has a specific permission."""
        return any(
            p.resource == resource and p.action == action
            for p in self.permissions
        )

    def get_permissions_for_resource(self, resource: str) -> List[str]:
        """Get all actions allowed for a resource."""
        return [p.action for p in self.permissions if p.resource == resource]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "permissions": [p.to_dict() for p in self.permissions],
            "hierarchy_level": self.hierarchy_level,
            "is_system_role": self.is_system_role,
        }


class RolesContextManager:
    """
    Manages role definitions and context for BFLA testing.
    Allows checking access patterns and testing authorization bypasses.
    """

    def __init__(self):
        self._roles: Dict[str, RoleContext] = {}
        self._default_roles()

    def _default_roles(self):
        """Initialize default role definitions."""
        # Admin - full access
        admin_role = RoleContext(
            name=RoleType.ADMIN.value,
            description="Full system access",
            hierarchy_level=100,
            is_system_role=True,
            permissions=[
                RolePermission("*", "*"),  # Wildcard - all resources, all actions
            ]
        )
        self._roles[RoleType.ADMIN.value] = admin_role

        # Security Engineer - security-focused access
        sec_eng_role = RoleContext(
            name=RoleType.SECURITY_ENGINEER.value,
            description="Security testing and monitoring",
            hierarchy_level=75,
            permissions=[
                RolePermission("endpoints", "*"),
                RolePermission("tests", "*"),
                RolePermission("vulnerabilities", "*"),
                RolePermission("threat_actors", "*"),
                RolePermission("audit_logs", "read"),
            ]
        )
        self._roles[RoleType.SECURITY_ENGINEER.value] = sec_eng_role

        # Developer - code deployment and testing
        dev_role = RoleContext(
            name=RoleType.DEVELOPER.value,
            description="Application development",
            hierarchy_level=50,
            permissions=[
                RolePermission("endpoints", "read"),
                RolePermission("endpoints", "write"),
                RolePermission("tests", "read"),
                RolePermission("tests", "run"),
                RolePermission("source_code", "*"),
            ]
        )
        self._roles[RoleType.DEVELOPER.value] = dev_role

        # Member - basic user access
        member_role = RoleContext(
            name=RoleType.MEMBER.value,
            description="Basic user access",
            hierarchy_level=25,
            permissions=[
                RolePermission("endpoints", "read"),
                RolePermission("tests", "read"),
                RolePermission("vulnerabilities", "read"),
            ]
        )
        self._roles[RoleType.MEMBER.value] = member_role

        # Auditor - read-only access to compliance data
        auditor_role = RoleContext(
            name=RoleType.AUDITOR.value,
            description="Compliance and audit access",
            hierarchy_level=20,
            permissions=[
                RolePermission("audit_logs", "read"),
                RolePermission("compliance", "read"),
                RolePermission("vulnerabilities", "read"),
            ]
        )
        self._roles[RoleType.AUDITOR.value] = auditor_role

        # Viewer - read-only access
        viewer_role = RoleContext(
            name=RoleType.VIEWER.value,
            description="Read-only access",
            hierarchy_level=10,
            permissions=[
                RolePermission("endpoints", "read"),
                RolePermission("tests", "read"),
            ]
        )
        self._roles[RoleType.VIEWER.value] = viewer_role

        # Anonymous - no authentication
        anonymous_role = RoleContext(
            name=RoleType.ANONYMOUS.value,
            description="Unauthenticated access",
            hierarchy_level=0,
            permissions=[
                RolePermission("public_endpoints", "read"),
            ]
        )
        self._roles[RoleType.ANONYMOUS.value] = anonymous_role

        # Attacker - used for BOLA/BFLA testing
        attacker_role = RoleContext(
            name=RoleType.ATTACKER.value,
            description="Test account for security testing",
            hierarchy_level=0,
            permissions=[],
            is_system_role=True
        )
        self._roles[RoleType.ATTACKER.value] = attacker_role

    def get_role(self, role_name: str) -> Optional[RoleContext]:
        """Get a role by name."""
        return self._roles.get(role_name.upper())

    def has_access(self, role_name: str, resource: str, action: str) -> bool:
        """
        Check if a role has access to a specific resource/action.
        Used in BFLA testing to verify authorization.
        """
        role = self.get_role(role_name)
        if not role:
            return False
        return role.has_permission(resource, action)

    def get_accessible_resources(self, role_name: str) -> List[Dict[str, Any]]:
        """
        Get all resources and actions accessible by a role.
        Useful for BFLA testing to identify potential targets.
        """
        role = self.get_role(role_name)
        if not role:
            return []
        
        resources = {}
        for perm in role.permissions:
            if perm.resource not in resources:
                resources[perm.resource] = []
            if perm.action not in resources[perm.resource]:
                resources[perm.resource].append(perm.action)
        
        return [{"resource": r, "actions": a} for r, a in resources.items()]

    def check_bfla_vulnerability(self, user_role: str, target_role: str, resource: str, action: str) -> bool:
        """
        Check if a user could potentially access another user's resources (BFLA check).
        Returns True if vulnerability exists (access bypass possible).
        """
        user_access = self.has_access(user_role, resource, action)
        target_access = self.has_access(target_role, resource, action)
        
        # If user has access and target doesn't, could be a BFLA bypass
        return user_access and not target_access

    def add_custom_role(self, role: RoleContext):
        """Add a custom role definition."""
        self._roles[role.name.upper()] = role

    def get_all_roles(self) -> Dict[str, RoleContext]:
        """Get all defined roles."""
        return self._roles.copy()

    def get_role_hierarchy(self) -> List[Dict[str, Any]]:
        """Get role hierarchy for visualization."""
        roles = sorted(self._roles.values(), key=lambda r: r.hierarchy_level, reverse=True)
        return [r.to_dict() for r in roles]
