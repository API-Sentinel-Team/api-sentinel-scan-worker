"""Tenant context for enforcing row-level security."""
from __future__ import annotations

import contextvars
from typing import Optional

_current_account_id: contextvars.ContextVar[Optional[int]] = contextvars.ContextVar(
    "current_account_id", default=None
)


def set_current_account_id(account_id: Optional[int]) -> None:
    _current_account_id.set(account_id)


def get_current_account_id() -> Optional[int]:
    return _current_account_id.get()
