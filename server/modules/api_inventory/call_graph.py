"""API call sequence graph - tracks which endpoints are called in sequence."""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)

# In-memory fallback: account_id -> {path -> {next_path -> count}}
_memory_store: dict[int, dict[str, dict[str, int]]] = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))


def _redis_client():
    try:
        from server.config import settings
        if not settings.REDIS_URL:
            return None
        import redis.asyncio as aioredis
        return aioredis.from_url(settings.REDIS_URL, decode_responses=True)
    except Exception:
        return None


def _graph_key(account_id: int) -> str:
    return f"lineage:{account_id}"


class ApiLineageGraph:
    """Tracks API call sequences as an adjacency graph per account."""

    async def record_sequence(
        self,
        account_id: int,
        session_id: str,
        endpoint_path: str,
        method: str,
        timestamp: int,
    ) -> None:
        """Record a single endpoint visit; the caller should call this in order to build edges."""
        # We store per-session last-path in memory to form edges
        session_key = f"_session_{account_id}_{session_id}"
        prev = _memory_store[account_id].get(session_key)
        if prev:
            prev_path = list(prev.keys())[0]
            _memory_store[account_id][prev_path][endpoint_path] += 1
        # Store current path marker for this session
        _memory_store[account_id][session_key] = {endpoint_path: timestamp}

        # Also persist to Redis if available
        r = _redis_client()
        if r:
            try:
                async with r:
                    if prev:
                        prev_path = list(prev.keys())[0]
                        raw = await r.get(_graph_key(account_id))
                        graph: dict[str, Any] = json.loads(raw) if raw else {}
                        edges = graph.setdefault("edges", {})
                        if prev_path not in edges:
                            edges[prev_path] = {}
                        edges[prev_path][endpoint_path] = edges[prev_path].get(endpoint_path, 0) + 1
                        await r.set(_graph_key(account_id), json.dumps(graph))
            except Exception as exc:
                logger.debug("Redis lineage write failed: %s", exc)

    async def get_graph(self, account_id: int) -> dict[str, Any]:
        """Return nodes + edges for the given account."""
        # Try Redis first
        r = _redis_client()
        if r:
            try:
                async with r:
                    raw = await r.get(_graph_key(account_id))
                    if raw:
                        stored = json.loads(raw)
                        return self._format_graph(stored.get("edges", {}))
            except Exception as exc:
                logger.debug("Redis lineage read failed: %s", exc)

        # Fall back to memory
        mem = _memory_store.get(account_id, {})
        edges: dict[str, dict[str, int]] = {}
        for src, targets in mem.items():
            if src.startswith("_session_"):
                continue
            edges[src] = {k: v for k, v in targets.items() if not k.startswith("_session_")}
        return self._format_graph(edges)

    def _format_graph(self, edges: dict[str, Any]) -> dict[str, Any]:
        node_set: set[str] = set()
        edge_list: list[dict[str, Any]] = []
        for src, targets in edges.items():
            node_set.add(src)
            for tgt, count in targets.items():
                node_set.add(tgt)
                edge_list.append({"from": src, "to": tgt, "count": count})

        nodes = [{"id": p, "label": p} for p in sorted(node_set)]
        edge_list.sort(key=lambda e: e["count"], reverse=True)
        return {"nodes": nodes, "edges": edge_list}

    async def get_top_paths(self, account_id: int, limit: int = 20) -> list[dict[str, Any]]:
        """Return the top N most-traveled edges."""
        graph = await self.get_graph(account_id)
        edges = sorted(graph["edges"], key=lambda e: e["count"], reverse=True)
        return edges[:limit]


api_lineage_graph = ApiLineageGraph()
