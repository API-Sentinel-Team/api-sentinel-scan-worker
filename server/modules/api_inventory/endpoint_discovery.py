import datetime
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import APICollection, APIEndpoint
from .path_normalizer import PathNormalizer

_DEFAULT_COLLECTION_NAME = "Default Inventory"

_OPENAPI_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"}
_UNSAFE_PATH_CHARS = ("<", ">", "'", '"', "..")


def inventory_path(path: str | None) -> str | None:
    """Return a catalogue path, or None when the raw path is attack/noise."""
    clean = (path or "/").split("?", 1)[0] or "/"
    if not clean.startswith("/"):
        clean = f"/{clean}"
    if any(token in clean for token in _UNSAFE_PATH_CHARS):
        return None
    return clean


def _utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


class EndpointDiscovery:
    """
    Handles discovery and persistence of observed API endpoints.
    """
    def __init__(self, db_session: AsyncSession):
        self.db = db_session
        self.normalizer = PathNormalizer()

    async def discover(self, entry: dict, *, commit: bool = True) -> APIEndpoint:
        """
        Takes a traffic/API-source entry and updates the database inventory.
        """
        normalized = self._normalize_entry(entry)

        query = select(APIEndpoint).where(
            APIEndpoint.account_id == normalized["account_id"],
            APIEndpoint.method == normalized["method"],
            APIEndpoint.host == normalized["host"],
            APIEndpoint.path_pattern == normalized["path_pattern"],
        )

        result = await self.db.execute(query)
        endpoint = result.scalar_one_or_none()
        tags = self._merged_tags(
            endpoint.tags if endpoint else None,
            source=normalized["source"],
            metadata=normalized["metadata"],
        )

        if endpoint:
            endpoint.last_seen = normalized["last_seen"]
            endpoint.last_response_code = normalized["status_code"]
            if normalized["query_string"] is not None:
                endpoint.last_query_string = normalized["query_string"]
            endpoint.tags = tags
            endpoint.is_sensitive = bool(endpoint.is_sensitive or normalized["is_sensitive"])
            endpoint.status = self._merged_status(endpoint.status, tags)
            if not endpoint.collection_id:
                endpoint.collection_id = await self._default_collection_id(normalized["account_id"])
        else:
            collection_id = normalized["collection_id"] or await self._default_collection_id(
                normalized["account_id"]
            )
            endpoint = APIEndpoint(
                account_id=normalized["account_id"],
                collection_id=collection_id,
                method=normalized["method"],
                host=normalized["host"],
                port=normalized["port"],
                protocol=normalized["protocol"],
                path=normalized["path"],
                path_pattern=normalized["path_pattern"],
                description=f"Auto-discovered {normalized['method']} on {normalized['host']}",
                last_seen=normalized["last_seen"],
                last_response_code=normalized["status_code"],
                last_query_string=normalized["query_string"],
                is_sensitive=normalized["is_sensitive"],
                api_type=normalized["api_type"],
                access_type=normalized["access_type"],
                auth_types_found=normalized["auth_types_found"],
                status=self._status_from_tags(tags),
                tags=tags,
            )
            self.db.add(endpoint)

        if commit:
            await self.db.commit()
        else:
            await self.db.flush()
        return endpoint

    async def _default_collection_id(self, account_id: int) -> str:
        result = await self.db.execute(
            select(APICollection).where(
                APICollection.account_id == account_id,
                APICollection.name == _DEFAULT_COLLECTION_NAME,
            )
        )
        collection = result.scalar_one_or_none()
        if collection is None:
            collection = APICollection(
                account_id=account_id,
                name=_DEFAULT_COLLECTION_NAME,
                host="all-hosts",
                type="MIRRORING",
            )
            self.db.add(collection)
            await self.db.flush()
        return collection.id

    def _normalize_entry(self, entry: dict[str, Any]) -> dict[str, Any]:
        request = entry.get("request") if isinstance(entry.get("request"), dict) else {}
        response = entry.get("response") if isinstance(entry.get("response"), dict) else {}
        raw_url = str(request.get("url") or entry.get("url") or entry.get("target_url") or "")
        parsed = urlparse(raw_url) if raw_url else None

        method = str(request.get("method") or entry.get("method") or "GET").upper()
        scheme = str(
            entry.get("scheme")
            or entry.get("protocol")
            or (parsed.scheme if parsed else "")
            or "https"
        ).lower()
        host = str(entry.get("host") or (parsed.hostname if parsed else "") or "unknown").lower()
        path = str(entry.get("path") or (parsed.path if parsed else "") or "/")
        if not path.startswith("/"):
            path = f"/{path}"
        path = path.split("?", 1)[0] or "/"
        query_string = str(
            entry.get("query_string")
            or entry.get("query")
            or (parsed.query if parsed else "")
            or ""
        ) or None

        status_code = (
            response.get("status")
            or response.get("status_code")
            or entry.get("status")
            or entry.get("status_code")
            or entry.get("last_response_code")
            or 200
        )
        sensitivity = entry.get("sensitivity")
        is_sensitive = bool(
            entry.get("is_sensitive")
            or str(sensitivity or "").lower() in {"medium", "high", "critical", "secret", "pii"}
        )

        auth_types_found = entry.get("auth_types_found") or []
        if entry.get("auth_required") is True and not auth_types_found:
            auth_types_found = ["AUTH_REQUIRED"]

        return {
            "account_id": int(entry.get("account_id") or 1000000),
            "collection_id": entry.get("collection_id"),
            "method": method,
            "host": host,
            "port": entry.get("port") or (parsed.port if parsed else None),
            "protocol": scheme,
            "path": path,
            "path_pattern": self.normalizer.normalize(path),
            "query_string": query_string,
            "status_code": int(status_code),
            "last_seen": entry.get("last_seen") or entry.get("ts") or _utc_now(),
            "source": str(entry.get("source") or "traffic").strip() or "traffic",
            "is_sensitive": is_sensitive,
            "api_type": str(entry.get("api_type") or "REST").upper(),
            "access_type": str(entry.get("access_type") or "PRIVATE").upper(),
            "auth_types_found": list(auth_types_found),
            "metadata": {
                "owner": entry.get("owner"),
                "auth_required": entry.get("auth_required"),
                "sensitivity": sensitivity,
                "version": entry.get("version"),
                "deprecated": bool(entry.get("deprecated", False)),
                "shadow": bool(entry.get("shadow", False)),
            },
        }

    @staticmethod
    def _merged_tags(
        current_tags: dict[str, Any] | None,
        *,
        source: str,
        metadata: dict[str, Any],
    ) -> dict[str, Any]:
        tags = dict(current_tags or {})
        sources = set(tags.get("sources") or [])
        sources.add(source)
        tags["source"] = source
        tags["sources"] = sorted(sources)

        for key, value in metadata.items():
            if value is None:
                continue
            if key in {"deprecated", "shadow"}:
                tags[key] = bool(tags.get(key, False) or value)
            else:
                tags[key] = value if key not in tags else tags[key]

        tags.setdefault("deprecated", False)
        tags.setdefault("shadow", False)
        return tags

    @staticmethod
    def _status_from_tags(tags: dict[str, Any]) -> str:
        if tags.get("deprecated"):
            return "DEPRECATED"
        if tags.get("shadow"):
            return "SHADOW"
        return "ACTIVE"

    @classmethod
    def _merged_status(cls, current_status: str | None, tags: dict[str, Any]) -> str:
        derived_status = cls._status_from_tags(tags)
        if derived_status != "ACTIVE":
            return derived_status
        return current_status or "ACTIVE"


def openapi_operations_to_discovery_entries(
    *,
    spec: dict[str, Any],
    target_url: str,
    account_id: int,
    source: str = "openapi",
    owner: str | None = None,
    version: str | None = None,
) -> list[dict[str, Any]]:
    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    scheme = parsed.scheme or "https"
    global_security = spec.get("security")
    entries: list[dict[str, Any]] = []

    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return entries

    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        path_security = path_item.get("security", global_security)
        for method, operation in path_item.items():
            method_upper = str(method).upper()
            if method_upper not in _OPENAPI_METHODS or not isinstance(operation, dict):
                continue

            metadata = operation.get("x-api-sentinel")
            metadata = metadata if isinstance(metadata, dict) else {}
            operation_security = operation.get("security", path_security)
            auth_required = bool(operation_security)
            sensitivity = metadata.get("sensitivity") or operation.get("x-sensitivity")
            entries.append(
                {
                    "account_id": account_id,
                    "source": source,
                    "method": method_upper,
                    "host": host,
                    "path": str(path),
                    "scheme": scheme,
                    "owner": metadata.get("owner") or owner,
                    "auth_required": auth_required,
                    "sensitivity": sensitivity,
                    "version": metadata.get("version") or version or spec.get("info", {}).get("version"),
                    "deprecated": bool(operation.get("deprecated") or metadata.get("deprecated")),
                    "shadow": bool(metadata.get("shadow", False)),
                    "api_type": "REST",
                }
            )

    return entries
