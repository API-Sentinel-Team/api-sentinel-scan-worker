from __future__ import annotations

import re
from typing import Any

from server.config import settings
from server.modules.test_executor.target_guard import TargetGuard, TargetGuardError


class IntegrationDestinationError(ValueError):
    """Raised when an integration destination is unsafe for outbound delivery."""


URL_FIELDS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "slack": ("webhook_url",),
    "jira": ("base_url",),
    "splunk": ("hec_url",),
    "webhook": ("url",),
    "sentinel": ("endpoint_url",),
    "qradar": ("endpoint_url",),
    "elastic": ("endpoint_url",),
    "chronicle": ("endpoint_url",),
}

DOMAIN_RE = re.compile(r"^[a-z0-9.-]+$", re.IGNORECASE)


def integration_destination_guard() -> TargetGuard:
    return TargetGuard(
        allowlist=[],
        allow_private_targets=bool(
            getattr(settings, "INTEGRATIONS_ALLOW_PRIVATE_DESTINATIONS", False)
            or settings.DEBUG
        ),
        enforce=bool(getattr(settings, "INTEGRATIONS_ENFORCE_DESTINATION_GUARD", True)),
        resolve_hosts=bool(getattr(settings, "INTEGRATIONS_RESOLVE_DESTINATION_HOSTS", False)),
        fail_closed_on_dns_error=bool(
            getattr(settings, "INTEGRATIONS_FAIL_CLOSED_ON_DESTINATION_DNS_ERROR", True)
        ),
    )


def validate_integration_destination_config(
    integration_type: str,
    config: dict[str, Any] | None,
    *,
    guard: TargetGuard | None = None,
) -> None:
    """Block integration URLs that could route server-side requests to unsafe hosts."""
    cfg = config or {}
    active_guard = guard or integration_destination_guard()
    for field_name in URL_FIELDS_BY_TYPE.get(integration_type, ()):
        value = cfg.get(field_name)
        if not value:
            continue
        try:
            active_guard.validate_url(str(value), base_url=str(value))
        except TargetGuardError as exc:
            reason = str(exc).replace("scanner target", "integration destination")
            raise IntegrationDestinationError(f"{field_name}: {reason}") from exc

    if integration_type == "datadog":
        site = str(cfg.get("site") or "datadoghq.com").strip().lower()
        if not site or "/" in site or "@" in site or ":" in site or not DOMAIN_RE.match(site):
            raise IntegrationDestinationError("site: invalid Datadog site host")
        try:
            active_guard.validate_url(f"https://api.{site}", base_url=f"https://api.{site}")
        except TargetGuardError as exc:
            reason = str(exc).replace("scanner target", "integration destination")
            raise IntegrationDestinationError(f"site: {reason}") from exc
