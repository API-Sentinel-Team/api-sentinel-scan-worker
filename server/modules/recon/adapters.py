"""Recon source adapters for external discovery."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple, Optional
from urllib.parse import quote

import httpx

from server.models.core import ReconSourceConfig
from server.modules.recon.secrets import ReconSourceSecretCodec


class ReconAdapterRegistry:
    async def fetch_items(self, source: ReconSourceConfig) -> Tuple[List[Dict[str, Any]], str | None]:
        provider = (source.provider or "").upper()
        cfg = ReconSourceSecretCodec.runtime_config(source)

        if provider in ("STATIC", "MANUAL"):
            items = cfg.get("items") or []
            return self._normalize_items(items), None

        if provider == "URL":
            url = cfg.get("url")
            if not url:
                return [], "url is required for URL provider"
            try:
                async with httpx.AsyncClient(timeout=20) as client:
                    resp = await client.get(url)
                    resp.raise_for_status()
                    data = resp.json()
            except Exception as exc:
                return [], f"url fetch failed: {exc}"
            items = data.get("items") if isinstance(data, dict) else data
            return self._normalize_items(items or []), None

        if provider == "SHODAN":
            return await self._fetch_shodan(cfg)

        if provider == "CENSYS":
            return await self._fetch_censys(cfg)

        if provider == "SWAGGERHUB":
            return await self._fetch_swaggerhub(cfg)

        if provider == "GITHUB":
            return await self._fetch_github(cfg)

        if provider == "GITLAB":
            return await self._fetch_gitlab(cfg)

        # Provider-specific fallbacks: allow items in config
        if cfg.get("items"):
            return self._normalize_items(cfg.get("items") or []), None

        return [], f"provider {provider} not configured"

    async def _fetch_shodan(self, cfg: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], str | None]:
        api_key = cfg.get("api_key")
        query = cfg.get("query")
        if not api_key or not query:
            return [], "shodan requires api_key and query"
        base_url = cfg.get("base_url", "https://api.shodan.io")
        limit = int(cfg.get("limit", 100))
        url = f"{base_url}/shodan/host/search"
        params = {"key": api_key, "query": query, "limit": limit}
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(url, params=params)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return [], f"shodan fetch failed: {exc}"
        matches = data.get("matches") or []
        items: List[Dict[str, Any]] = []
        for match in matches:
            host = (match.get("hostnames") or [None])[0] or match.get("ip_str")
            port = match.get("port")
            if not host:
                continue
            url = self._build_url(host, port)
            items.append({"url": url, "method": "GET", "confidence": 0.6})
        return self._normalize_items(items), None

    async def _fetch_censys(self, cfg: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], str | None]:
        api_id = cfg.get("api_id")
        api_secret = cfg.get("api_secret")
        query = cfg.get("query")
        if not api_id or not api_secret or not query:
            return [], "censys requires api_id, api_secret, and query"
        base_url = cfg.get("base_url", "https://search.censys.io")
        url = f"{base_url}/api/v2/hosts/search"
        per_page = int(cfg.get("limit", 100))
        params = {"q": query, "per_page": per_page}
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(url, params=params, auth=(api_id, api_secret))
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return [], f"censys fetch failed: {exc}"
        hits = (((data or {}).get("result") or {}).get("hits")) or []
        items: List[Dict[str, Any]] = []
        for hit in hits:
            ip = hit.get("ip")
            services = hit.get("services") or []
            if services:
                for svc in services:
                    port = svc.get("port")
                    if ip and port:
                        items.append({"url": self._build_url(ip, port), "method": "GET", "confidence": 0.6})
            elif ip:
                items.append({"url": self._build_url(ip, None), "method": "GET", "confidence": 0.5})
        return self._normalize_items(items), None

    async def _fetch_swaggerhub(self, cfg: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], str | None]:
        api_key = cfg.get("api_key")
        query = cfg.get("query")
        if not api_key or not query:
            return [], "swaggerhub requires api_key and query"
        base_url = cfg.get("base_url", "https://api.swaggerhub.com")
        url = f"{base_url}/apis"
        params = {"query": query}
        headers = {"Authorization": api_key}
        try:
            async with httpx.AsyncClient(timeout=20) as client:
                resp = await client.get(url, params=params, headers=headers)
                resp.raise_for_status()
                data = resp.json()
        except Exception as exc:
            return [], f"swaggerhub fetch failed: {exc}"
        return self._extract_items_from_response(data), None

    async def _fetch_github(self, cfg: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], str | None]:
        token = cfg.get("token")
        repo = cfg.get("repo")
        branch = cfg.get("branch", "main")
        paths = cfg.get("paths") or []
        raw_urls = cfg.get("raw_urls") or []
        items: List[Dict[str, Any]] = []

        if raw_urls:
            items.extend([{"url": u, "method": "GET", "confidence": 0.7} for u in raw_urls])

        if repo and paths:
            for path in paths:
                url = f"https://raw.githubusercontent.com/{repo}/{branch}/{path}"
                items.append({"url": url, "method": "GET", "confidence": 0.7})

        if not items:
            return [], "github requires raw_urls or repo+paths"

        # Optionally validate URLs for private repos
        if token and cfg.get("validate", False):
            headers = {"Authorization": f"Bearer {token}"}
            valid_items: List[Dict[str, Any]] = []
            async with httpx.AsyncClient(timeout=20) as client:
                for item in items:
                    try:
                        resp = await client.get(item["url"], headers=headers)
                        if resp.status_code < 400:
                            valid_items.append(item)
                    except Exception:
                        continue
            items = valid_items

        return self._normalize_items(items), None

    async def _fetch_gitlab(self, cfg: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], str | None]:
        token = cfg.get("token")
        project = cfg.get("project")
        branch = cfg.get("branch", "main")
        paths = cfg.get("paths") or []
        raw_urls = cfg.get("raw_urls") or []
        base_url = cfg.get("base_url", "https://gitlab.com")
        items: List[Dict[str, Any]] = []

        if raw_urls:
            items.extend([{"url": u, "method": "GET", "confidence": 0.7} for u in raw_urls])

        if project and paths:
            project_id = quote(project, safe="")
            for path in paths:
                file_path = quote(path, safe="")
                url = f"{base_url}/api/v4/projects/{project_id}/repository/files/{file_path}/raw?ref={branch}"
                items.append({"url": url, "method": "GET", "confidence": 0.7})

        if not items:
            return [], "gitlab requires raw_urls or project+paths"

        if token and cfg.get("validate", False):
            headers = {"PRIVATE-TOKEN": token}
            valid_items: List[Dict[str, Any]] = []
            async with httpx.AsyncClient(timeout=20) as client:
                for item in items:
                    try:
                        resp = await client.get(item["url"], headers=headers)
                        if resp.status_code < 400:
                            valid_items.append(item)
                    except Exception:
                        continue
            items = valid_items

        return self._normalize_items(items), None

    def _build_url(self, host: str, port: Optional[int]) -> str:
        if port in (443, 8443):
            scheme = "https"
        elif port in (80, 8080):
            scheme = "http"
        else:
            scheme = "https"
        if port and port not in (80, 443):
            return f"{scheme}://{host}:{port}"
        return f"{scheme}://{host}"

    def _extract_items_from_response(self, data: Any) -> List[Dict[str, Any]]:
        if isinstance(data, list):
            return self._normalize_items(self._extract_items_list(data))
        if isinstance(data, dict):
            for key in ("items", "results", "data"):
                if isinstance(data.get(key), list):
                    return self._normalize_items(self._extract_items_list(data.get(key)))
        return []

    def _extract_items_list(self, items: Iterable[Any]) -> List[Dict[str, Any]]:
        extracted: List[Dict[str, Any]] = []
        for item in items:
            if isinstance(item, dict):
                url = (
                    item.get("url")
                    or item.get("swaggerUrl")
                    or item.get("openapiUrl")
                    or item.get("apiUrl")
                    or item.get("raw_url")
                    or item.get("rawUrl")
                    or item.get("spec_url")
                    or item.get("specUrl")
                )
                if url:
                    extracted.append({"url": url, "method": item.get("method", "GET"), "confidence": 0.6})
        return extracted

    def _normalize_items(self, items: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            if not item.get("url"):
                continue
            normalized.append(
                {
                    "url": item.get("url"),
                    "method": item.get("method", "GET"),
                    "confidence": item.get("confidence", 0.5),
                }
            )
        return normalized
