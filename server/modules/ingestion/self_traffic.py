"""Drop this product's own console/API traffic from sensor ingest."""

from __future__ import annotations

from urllib.parse import urlparse

from server.config import settings

# When the sensor omits Host, these paths are still this console — not a customer API.
_CONSOLE_PATH_PREFIXES = (
    "/api/",
    "/healthz",
    "/v1/events",
    "/app/",
    "/admin/",
    "/platform/",
    "/login",
    "/assets/",
)

_EMPTY_HOSTS = frozenset({"", "unknown", "localhost", "127.0.0.1"})


def normalize_host(host: str | None) -> str:
    raw = (host or "").strip().lower()
    if not raw:
        return ""
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.hostname or raw
    raw = raw.split("/")[0]
    if raw.count(":") == 1 and not raw.startswith("["):
        raw = raw.split(":", 1)[0]
    return raw


def excluded_hosts() -> set[str]:
    hosts: set[str] = set()
    for part in (settings.INGEST_EXCLUDE_HOSTS or "").split(","):
        host = normalize_host(part)
        if host:
            hosts.add(host)
    override = settings.CORS_ORIGINS_OVERRIDE or ""
    if override:
        for part in override.split(","):
            host = normalize_host(part)
            if host and host not in {"localhost", "127.0.0.1"}:
                hosts.add(host)
    return hosts


def _host_is_excluded(host: str, self_hosts: set[str]) -> bool:
    if not host or host in _EMPTY_HOSTS:
        return False
    if host in self_hosts:
        return True
    return any(host.endswith(f".{excluded}") for excluded in self_hosts)


def _is_console_path(path: str) -> bool:
    for prefix in _CONSOLE_PATH_PREFIXES:
        if prefix.endswith("/"):
            if path == prefix.rstrip("/") or path.startswith(prefix):
                return True
        elif path == prefix or path.startswith(prefix + "/"):
            return True
    return False


def is_self_traffic(
    host: str | None,
    path: str | None,
    *,
    self_hosts: set[str] | None = None,
) -> bool:
    """True when this event is API Sentinel watching itself."""
    hosts = self_hosts if self_hosts is not None else excluded_hosts()
    host_n = normalize_host(host)
    path_n = (path or "/").split("?", 1)[0] or "/"
    if not path_n.startswith("/"):
        path_n = f"/{path_n}"

    if _host_is_excluded(host_n, hosts):
        return True
    if host_n in _EMPTY_HOSTS:
        return _is_console_path(path_n)
    return False
