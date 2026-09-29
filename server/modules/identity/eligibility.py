"""Shared eligibility rules for selecting TestAccount identities for active testing.

A test account is eligible only when it is active, not expired, and carries usable
auth material — with one deliberate exception: deliberately anonymous identities
(ANONYMOUS/UNAUTHENTICATED roles) are eligible without credentials because the
authorization-replay matrix needs an unauthenticated baseline.

Every identity selection site must go through :func:`eligible_test_accounts` so
expired, disabled, or credential-less identities are never selected into scans
(shared-contract Sprint item E2.1 / COV-1).
"""

from __future__ import annotations

import datetime
from typing import Any, Iterable

from server.models.core import TestAccount
from server.modules.identity.authorization_replay import (
    _ANONYMOUS_ROLE_KEYS,
    _is_anonymous_account,
    auth_headers_for_account,
)

INELIGIBLE_ACCOUNT_STATUSES = frozenset({"EXPIRED", "DISABLED", "REVOKED", "INACTIVE"})


def account_status(account: Any) -> str:
    return str(getattr(account, "status", "") or "").strip().upper()


def account_expired(account: Any, *, now: datetime.datetime | None = None) -> bool:
    """True when the account carries an expiry that has passed."""
    expired_at = getattr(account, "expired_at", None)
    if expired_at is None:
        return False
    if expired_at.tzinfo is None:
        expired_at = expired_at.replace(tzinfo=datetime.timezone.utc)
    current = now or datetime.datetime.now(datetime.timezone.utc)
    return expired_at <= current


def account_has_auth_material(account: Any) -> bool:
    """True when the account can produce replayable auth headers.

    Anonymous roles count as material-bearing: their empty ``Authorization``
    header is the unauthenticated baseline the replay matrix requires.
    """
    return bool(auth_headers_for_account(account).keys())


def account_is_eligible(account: Any, *, now: datetime.datetime | None = None) -> bool:
    """Return True when an identity may be selected for active testing."""
    if account is None:
        return False
    if account_status(account) in INELIGIBLE_ACCOUNT_STATUSES:
        return False
    if account_expired(account, now=now):
        return False
    if _is_anonymous_account(account):
        return account_status(account) not in INELIGIBLE_ACCOUNT_STATUSES and not account_expired(account, now=now)
    return account_has_auth_material(account)


def eligible_test_accounts(
    accounts: Iterable[Any],
    *,
    now: datetime.datetime | None = None,
) -> list[Any]:
    """Filter a collection of test accounts down to eligible identities."""
    return [account for account in accounts if account_is_eligible(account, now=now)]


def eligibility_summary(
    accounts: Iterable[Any],
    *,
    now: datetime.datetime | None = None,
) -> dict[str, int]:
    """Return non-secret selection counts for preflight and audit surfaces."""
    items = list(accounts)
    eligible = eligible_test_accounts(items, now=now)
    expired = sum(1 for a in items if a is not None and account_expired(a, now=now))
    disabled = sum(1 for a in items if account_status(a) in INELIGIBLE_ACCOUNT_STATUSES)
    credential_less = sum(
        1
        for a in items
        if a is not None
        and account_status(a) not in INELIGIBLE_ACCOUNT_STATUSES
        and not account_expired(a, now=now)
        and not _is_anonymous_account(a)
        and not account_has_auth_material(a)
    )
    return {
        "total": len(items),
        "eligible": len(eligible),
        "expired_excluded": expired,
        "disabled_excluded": disabled,
        "credential_less_excluded": credential_less,
    }


__all__ = [
    "INELIGIBLE_ACCOUNT_STATUSES",
    "account_expired",
    "account_has_auth_material",
    "account_is_eligible",
    "account_status",
    "eligible_test_accounts",
    "eligibility_summary",
]

# Imported late to keep the anonymous-role key set single-sourced without a cycle.
assert _ANONYMOUS_ROLE_KEYS  # re-exported indirectly via _is_anonymous_account
