from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import urlparse

from server.config import settings
from server.modules.utils.redactor import Redactor


class TargetGuardError(ValueError):
    """Raised when a scanner destination is outside the allowed target scope."""


@dataclass(frozen=True)
class _AllowedHost:
    pattern: str
    port: int | None = None


class TargetGuard:
    """Enforces scanner egress scope before active test requests are sent."""

    METADATA_HOSTS = {
        "169.254.169.254",
        "169.254.170.2",
        "metadata",
        "metadata.google.internal",
        "metadata.azure.internal",
        "instance-data",
    }
    METADATA_IPS = {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("169.254.170.2"),
    }
    PRIVATE_SUFFIXES = (".localhost", ".local", ".internal")

    def __init__(
        self,
        *,
        allowlist: list[str] | None = None,
        allow_private_targets: bool = False,
        enforce: bool = True,
        resolve_hosts: bool = False,
        fail_closed_on_dns_error: bool = True,
        resolver: Callable[[str, int], Iterable[str]] | None = None,
    ) -> None:
        self.allowlist = [self._parse_allowed_host(item) for item in (allowlist or []) if item]
        self.allow_private_targets = allow_private_targets
        self.enforce = enforce
        self.resolve_hosts = resolve_hosts
        self.fail_closed_on_dns_error = fail_closed_on_dns_error
        self.resolver = resolver or self._default_resolver
        self.allowlist_error = self._unsafe_allowlist_reason()

    @classmethod
    def from_settings(cls, settings_obj: object | None = None) -> "TargetGuard":
        source = settings_obj if settings_obj is not None else settings
        raw_allowlist = getattr(source, "PENTEST_TARGET_ALLOWLIST", "") or ""
        allowlist = [item.strip() for item in raw_allowlist.split(",") if item.strip()]
        return cls(
            allowlist=allowlist,
            # Private/loopback targets are gated only by the explicit allow flag.
            # DEBUG must not silently fail open for SSRF/private-host scans.
            allow_private_targets=bool(getattr(source, "PENTEST_ALLOW_PRIVATE_TARGETS", False)),
            enforce=bool(getattr(source, "PENTEST_ENFORCE_TARGET_GUARD", True)),
            resolve_hosts=bool(getattr(source, "PENTEST_RESOLVE_TARGET_HOSTS", False)),
            fail_closed_on_dns_error=bool(
                getattr(source, "PENTEST_FAIL_CLOSED_ON_TARGET_DNS_ERROR", True)
            ),
        )

    def validate_url(self, url: str, *, base_url: str | None = None) -> None:
        if not self.enforce:
            return
        if self.allowlist_error:
            raise TargetGuardError(self.allowlist_error)

        parsed = urlparse(url)
        if parsed.scheme.lower() not in {"http", "https"}:
            raise TargetGuardError("only http and https scanner targets are allowed")
        if parsed.username or parsed.password:
            raise TargetGuardError("scanner target URLs must not contain credentials")

        host = self._normalize_host(parsed.hostname)
        if not host:
            raise TargetGuardError("scanner target host is missing")

        if self._is_metadata_host(host):
            raise TargetGuardError("cloud metadata endpoints are blocked")

        if not self.allow_private_targets and self._is_private_host(host):
            raise TargetGuardError("private, loopback, link-local, and reserved targets are blocked")

        self._validate_resolved_addresses(host, self._effective_port(parsed))

        if self.allowlist:
            if not self._host_in_allowlist(host, self._effective_port(parsed)):
                raise TargetGuardError(f"host '{host}' is not in the pentest target allowlist")
            return

        if base_url and not self._same_origin(parsed, urlparse(base_url)):
            raise TargetGuardError("template mutation attempted to leave the selected endpoint origin")

    @classmethod
    def _parse_allowed_host(cls, item: str) -> _AllowedHost:
        value = item.strip().lower()
        if "://" in value:
            parsed = urlparse(value)
            return _AllowedHost(cls._normalize_host(parsed.hostname), cls._effective_port(parsed))

        parsed = urlparse(f"//{value}")
        if parsed.hostname:
            return _AllowedHost(cls._normalize_host(parsed.hostname), parsed.port)
        return _AllowedHost(cls._normalize_host(value), None)

    @staticmethod
    def _normalize_host(host: str | None) -> str:
        return (host or "").strip("[]").rstrip(".").lower()

    @staticmethod
    def _effective_port(parsed) -> int:
        try:
            port = parsed.port
        except ValueError as exc:
            raise TargetGuardError("scanner target port is invalid") from exc
        if port:
            return port
        return 443 if parsed.scheme.lower() == "https" else 80

    def _host_in_allowlist(self, host: str, port: int) -> bool:
        for allowed in self.allowlist:
            if allowed.port is not None and allowed.port != port:
                continue
            pattern = allowed.pattern
            if pattern == "*":
                return True
            if pattern.startswith("*.") and host.endswith(pattern[1:]):
                return True
            if host == pattern:
                return True
        return False

    def _unsafe_allowlist_reason(self) -> str | None:
        for allowed in self.allowlist:
            if allowed.pattern == "*":
                return "pentest target allowlist contains unsafe wildcard '*'"
        return None

    def _same_origin(self, target, base) -> bool:
        return (
            self._normalize_host(target.hostname) == self._normalize_host(base.hostname)
            and self._effective_port(target) == self._effective_port(base)
            and target.scheme.lower() == base.scheme.lower()
        )

    def _is_metadata_host(self, host: str) -> bool:
        address = self._host_ip_address(host)
        return host in self.METADATA_HOSTS or (
            address is not None and self._is_metadata_address(address)
        )

    def _is_private_host(self, host: str) -> bool:
        if host == "localhost" or host.endswith(self.PRIVATE_SUFFIXES):
            return True
        address = self._host_ip_address(host)
        if address is None:
            return False
        return self._is_private_address(address)

    @classmethod
    def _host_ip_address(cls, host: str) -> ipaddress._BaseAddress | None:
        try:
            return ipaddress.ip_address(host)
        except ValueError:
            return cls._legacy_ipv4_address(host)

    @classmethod
    def _legacy_ipv4_address(cls, host: str) -> ipaddress.IPv4Address | None:
        parts = host.split(".")
        if not 1 <= len(parts) <= 4 or any(part == "" for part in parts):
            return None

        numbers = [cls._parse_legacy_ipv4_part(part) for part in parts]
        if any(number is None for number in numbers):
            return None
        values = [int(number) for number in numbers]

        if len(values) == 1:
            if values[0] > 0xFFFFFFFF:
                return None
            return ipaddress.IPv4Address(values[0])

        if any(value > 0xFF for value in values[:-1]):
            return None
        last_bits = 8 * (5 - len(values))
        if values[-1] >= (1 << last_bits):
            return None

        packed = 0
        for value in values[:-1]:
            packed = (packed << 8) | value
        packed = (packed << last_bits) | values[-1]
        return ipaddress.IPv4Address(packed)

    @staticmethod
    def _parse_legacy_ipv4_part(part: str) -> int | None:
        text = part.strip().lower()
        if not text:
            return None
        if text.startswith("0x"):
            digits = text[2:]
            if not digits or any(char not in "0123456789abcdef" for char in digits):
                return None
            return int(digits, 16)
        if len(text) > 1 and text.startswith("0"):
            if any(char not in "01234567" for char in text):
                return None
            return int(text, 8)
        if not text.isdigit():
            return None
        return int(text, 10)

    def _validate_resolved_addresses(self, host: str, port: int) -> None:
        if not self.resolve_hosts:
            return

        try:
            addresses = list(self.resolver(host, port))
        except OSError as exc:
            if self.fail_closed_on_dns_error:
                raise TargetGuardError(f"target host DNS resolution failed for '{host}'") from exc
            return

        if not addresses:
            if self.fail_closed_on_dns_error:
                raise TargetGuardError(f"target host DNS resolution returned no addresses for '{host}'")
            return

        for raw_address in addresses:
            try:
                address = ipaddress.ip_address(str(raw_address).strip("[]"))
            except ValueError:
                if self.fail_closed_on_dns_error:
                    raise TargetGuardError(
                        f"target host DNS resolution returned invalid address for '{host}'"
                    )
                continue

            if self._is_metadata_address(address):
                raise TargetGuardError("resolved cloud metadata endpoints are blocked")
            if not self.allow_private_targets and self._is_private_address(address):
                raise TargetGuardError(
                    "target host resolved to private, loopback, link-local, or reserved address"
                )

    @classmethod
    def _is_metadata_address(cls, address: ipaddress._BaseAddress) -> bool:
        if address in cls.METADATA_IPS:
            return True
        return any(embedded in cls.METADATA_IPS for embedded in cls._embedded_ipv4_addresses(address))

    @classmethod
    def _is_private_address(cls, address: ipaddress._BaseAddress) -> bool:
        if any(cls._is_private_address(embedded) for embedded in cls._embedded_ipv4_addresses(address)):
            return True
        return any(
            [
                address.is_private,
                address.is_loopback,
                address.is_link_local,
                address.is_multicast,
                address.is_reserved,
                address.is_unspecified,
            ]
        )

    @staticmethod
    def _embedded_ipv4_addresses(address: ipaddress._BaseAddress) -> tuple[ipaddress.IPv4Address, ...]:
        if not isinstance(address, ipaddress.IPv6Address):
            return ()

        embedded: list[ipaddress.IPv4Address] = []
        if address.ipv4_mapped:
            embedded.append(address.ipv4_mapped)
        if address.sixtofour:
            embedded.append(address.sixtofour)
        if address.teredo:
            _server, client = address.teredo
            embedded.append(client)
        return tuple(embedded)

    @staticmethod
    def _default_resolver(host: str, port: int) -> list[str]:
        addresses: set[str] = set()
        for info in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
            sockaddr = info[4]
            if sockaddr:
                addresses.add(sockaddr[0])
        return sorted(addresses)


def endpoint_target_url(endpoint: object) -> str:
    """Build the active scanner URL for an endpoint-like model or mapping."""
    if isinstance(endpoint, dict):
        protocol = endpoint.get("protocol") or "http"
        host = endpoint.get("host") or ""
        path = endpoint.get("path") or "/"
    else:
        protocol = getattr(endpoint, "protocol", None) or "http"
        host = getattr(endpoint, "host", None) or ""
        path = getattr(endpoint, "path", None) or "/"

    path = str(path)
    if not path.startswith("/"):
        path = f"/{path}"
    return f"{protocol}://{host}{path}"


def blocked_endpoint_targets(
    endpoints: Iterable[object],
    *,
    guard: TargetGuard | None = None,
) -> list[dict[str, object]]:
    """Return redacted endpoint target-scope violations without sending network traffic."""
    from server.modules.pentest.target_policy import build_target_guard_policy

    active_guard = guard or TargetGuard.from_settings()
    blocked: list[dict[str, object]] = []
    for endpoint in endpoints:
        url = endpoint_target_url(endpoint)
        try:
            active_guard.validate_url(url, base_url=url)
        except TargetGuardError as exc:
            endpoint_id = endpoint.get("id") if isinstance(endpoint, dict) else getattr(endpoint, "id", "")
            blocked.append(
                {
                    "endpoint_id": str(endpoint_id),
                    "url": Redactor.redact_url(url),
                    "reason": Redactor.redact_text(str(exc)),
                    "target_guard_policy": build_target_guard_policy(
                        url=url,
                        base_url=url,
                        reason=str(exc),
                        guard=active_guard,
                    ),
                }
            )
    return blocked
