"""Role×Function BFLA matrix for privilege-boundary pair selection.

A BFLA test requires selecting the right (victim, attacker) pair based on
what privilege the endpoint actually expects.  A generic "admin vs. user"
pair misses many real BFLA bugs (e.g. manager vs. viewer on a write
endpoint, or owner vs. member on a delete endpoint).

This module scores each endpoint's *expected minimum role tier* from path
and method signals, then selects the pair that crosses the most meaningful
privilege boundary without over-testing (no point sending an ADMIN to a
public endpoint — that's just spam).
"""
from __future__ import annotations

import re
from typing import Any

# ── role tier definitions ──────────────────────────────────────────────────
# Higher tier = more privilege.  Tier 0 = public/anonymous.
_ROLE_TIERS: dict[str, int] = {
    "PLATFORM_ADMIN": 4,
    "SUPERADMIN": 4,
    "SUPER_ADMIN": 4,
    "ROOT": 4,
    "ADMIN": 3,
    "OWNER": 3,
    "MANAGER": 2,
    "OPERATOR": 2,
    "USER": 1,
    "CUSTOMER": 1,
    "MEMBER": 1,
    "VIEWER": 0,
    "READONLY": 0,
    "READ_ONLY": 0,
    "GUEST": 0,
    "ATTACKER": 0,
}

# ── endpoint function-level signals ───────────────────────────────────────
_ADMIN_PATH_RE = re.compile(
    r"/(admin|management|internal|superuser|platform|ops|backoffice|system|config)(/|$)",
    re.IGNORECASE,
)
_PRIVILEGED_ACTION_RE = re.compile(
    r"/(delete|destroy|purge|reset|revoke|ban|suspend|impersonate|promote|demote)(/|$)",
    re.IGNORECASE,
)
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _endpoint_expected_tier(endpoint: dict[str, Any]) -> int:
    """Estimate the minimum role tier expected to call this endpoint."""
    path = str(endpoint.get("path") or endpoint.get("url") or "")
    method = str(endpoint.get("method") or "GET").upper()

    if _ADMIN_PATH_RE.search(path):
        return 3  # ADMIN+
    if _PRIVILEGED_ACTION_RE.search(path):
        return 2  # MANAGER+
    if method in _WRITE_METHODS:
        return 1  # USER+
    return 1  # default: at least a basic authenticated user


def _role_tier(account: Any) -> int:
    raw = str(getattr(account, "role", "") or "").strip().upper().replace("-", "_")
    return _ROLE_TIERS.get(raw, 1)


def pick_bfla_pair(
    accounts: list[Any],
    *,
    endpoint: dict[str, Any] | None = None,
) -> tuple[Any, Any] | None:
    """Select the best (victim, attacker) pair for a BFLA test.

    The victim must have a role at or above the endpoint's expected tier.
    The attacker must have a strictly lower role tier.

    When no tier context is available, falls back to the highest-tier
    account as victim and the lowest-tier as attacker (maximum boundary).
    Returns None when the account pool cannot form a privilege boundary.
    """
    if not accounts or len(accounts) < 2:
        return None

    expected_tier = _endpoint_expected_tier(endpoint or {})

    # Victims: role tier >= expected_tier
    victims = sorted(
        [a for a in accounts if _role_tier(a) >= expected_tier],
        key=lambda a: -_role_tier(a),  # highest privilege first
    )
    # Attackers: role tier < victim's tier (must be strictly lower)
    for victim in victims:
        victim_tier = _role_tier(victim)
        attackers = sorted(
            [a for a in accounts if a is not victim and _role_tier(a) < victim_tier],
            key=lambda a: -_role_tier(a),  # closest to victim first (harder boundary)
        )
        if attackers:
            return victim, attackers[0]

    # Fallback: any pair with a privilege gap
    by_tier = sorted(accounts, key=lambda a: -_role_tier(a))
    high_tier = _role_tier(by_tier[0])
    low = [a for a in by_tier[1:] if _role_tier(a) < high_tier]
    if low:
        return by_tier[0], low[0]

    return None


def bfla_endpoint_risk(endpoint: dict[str, Any]) -> dict[str, Any]:
    """Return BFLA risk metadata for an endpoint (used in scan plan coverage)."""
    path = str(endpoint.get("path") or endpoint.get("url") or "")
    method = str(endpoint.get("method") or "GET").upper()
    expected_tier = _endpoint_expected_tier(endpoint)
    return {
        "expected_minimum_role_tier": expected_tier,
        "is_admin_path": bool(_ADMIN_PATH_RE.search(path)),
        "is_privileged_action": bool(_PRIVILEGED_ACTION_RE.search(path)),
        "is_write_method": method in _WRITE_METHODS,
    }
