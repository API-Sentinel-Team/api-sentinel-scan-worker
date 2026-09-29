from __future__ import annotations

from server.config import settings

KILL_SWITCH_REASON = "pentest_kill_switch_enabled"


class PentestKillSwitchError(RuntimeError):
    """Raised when production safety has disabled all active pentest execution."""


def kill_switch_enabled() -> bool:
    return bool(getattr(settings, "PENTEST_KILL_SWITCH_ENABLED", False))


def guard_pentest_execution() -> None:
    if kill_switch_enabled():
        raise PentestKillSwitchError(KILL_SWITCH_REASON)


def ensure_pentest_not_killed() -> None:
    """Cooperative check for in-flight worker loops; raises when the switch is on."""
    guard_pentest_execution()
