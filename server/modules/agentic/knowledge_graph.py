"""API knowledge graph — the attacker's mental model of an API surface.

A red team (human or agentic) does not reason endpoint-by-endpoint in isolation;
it builds a model of the whole API and chains findings across it: "endpoint A
leaked a user_id, so now try BOLA on endpoint B that takes a user_id". This
module is that model, kept deterministic and pure so it is testable and feeds the
:mod:`server.modules.agentic.strategist` as recon context.

Three node/edge concepts:

- Endpoints: method + normalized path, with auth context and the identifier
  parameters they accept or return.
- Observed identifiers: concrete id values seen in responses (e.g. a user_id
  leaked in a body), associated with the endpoint that exposed them.
- Chaining edges: "endpoint A exposes identifier of kind K; endpoint B consumes
  kind K" -> a candidate cross-object/authorization test path.

The graph accumulates across scans (merge), so coverage and chains grow over
time. Persistence is left to the caller (serialize ``as_dict`` / rebuild via
``from_dict``); this keeps the model storage-agnostic.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

# Identifier-kind hints: a parameter/field name containing one of these maps to
# that identifier kind, which is what chaining matches on.
_ID_KIND_HINTS: tuple[tuple[str, str], ...] = (
    ("user", "user_id"),
    ("account", "account_id"),
    ("tenant", "tenant_id"),
    ("org", "org_id"),
    ("customer", "customer_id"),
    ("order", "order_id"),
    ("invoice", "invoice_id"),
    ("book", "book_id"),
    ("project", "project_id"),
    ("object", "object_id"),
    ("item", "item_id"),
)


def normalize_path(path: str) -> str:
    if not path:
        return "/"
    text = path.split("?", 1)[0].split("#", 1)[0]
    if not text.startswith("/"):
        text = "/" + text
    out = []
    for seg in text.split("/"):
        if not seg:
            out.append("")
        elif seg.startswith("{") and seg.endswith("}"):
            out.append("{id}")
        elif seg.isdigit() or _UUID_RE.match(seg) or (len(seg) >= 16 and re.fullmatch(r"[0-9a-fA-F]+", seg)):
            out.append("{id}")
        else:
            out.append(seg.lower())
    norm = "/".join(out)
    if len(norm) > 1:
        norm = norm.rstrip("/")
    return norm or "/"


def identifier_kind(name: str) -> str | None:
    """Map a parameter/field name to a coarse identifier kind, else None."""
    text = str(name or "").lower()
    for hint, kind in _ID_KIND_HINTS:
        if hint in text:
            return kind
    if text in {"id", "_id"} or text.endswith("_id") or text.endswith("id"):
        return "generic_id"
    return None


@dataclass
class EndpointNode:
    endpoint_id: str
    method: str
    path: str
    host: str = ""
    protocol: str = "https"
    auth_types: set[str] = field(default_factory=set)
    # Identifier kinds this endpoint accepts (path/query/body params).
    consumes_ids: set[str] = field(default_factory=set)
    # Identifier kinds this endpoint exposes (returned in responses).
    exposes_ids: set[str] = field(default_factory=set)
    # Concrete identifier values observed coming out of this endpoint.
    observed_values: set[str] = field(default_factory=set)

    @property
    def key(self) -> tuple[str, str]:
        return (self.method.upper(), normalize_path(self.path))

    def as_dict(self) -> dict[str, Any]:
        return {
            "endpoint_id": self.endpoint_id,
            "method": self.method.upper(),
            "path": normalize_path(self.path),
            "host": self.host,
            "protocol": self.protocol,
            "auth_types": sorted(self.auth_types),
            "consumes_ids": sorted(self.consumes_ids),
            "exposes_ids": sorted(self.exposes_ids),
            "observed_value_count": len(self.observed_values),
        }


@dataclass
class ChainEdge:
    """A candidate cross-object test path between two endpoints."""

    source_endpoint_id: str
    target_endpoint_id: str
    id_kind: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "source_endpoint_id": self.source_endpoint_id,
            "target_endpoint_id": self.target_endpoint_id,
            "id_kind": self.id_kind,
            "reason": self.reason,
        }


class KnowledgeGraph:
    """Accumulating model of an API surface for one account/target."""

    def __init__(self) -> None:
        self._nodes: dict[tuple[str, str], EndpointNode] = {}

    # ── ingestion ────────────────────────────────────────────────────────────

    def add_endpoint(self, endpoint: dict[str, Any]) -> EndpointNode:
        """Add/merge an endpoint from a selection-context-style dict."""
        method = str(endpoint.get("method") or "GET").upper()
        path = str(endpoint.get("path") or endpoint.get("url") or "/")
        node = EndpointNode(
            endpoint_id=str(endpoint.get("id") or f"{method}:{normalize_path(path)}"),
            method=method,
            path=path,
            host=str(endpoint.get("host") or ""),
            protocol=str(endpoint.get("protocol") or "https"),
        )
        key = node.key
        existing = self._nodes.get(key)
        if existing is None:
            self._nodes[key] = node
            existing = node
        else:
            # Keep the first stable endpoint_id but merge the rest.
            existing.host = existing.host or node.host
            if node.protocol:
                existing.protocol = node.protocol
            node = existing

        for auth in endpoint.get("auth_types_found") or []:
            node.auth_types.add(str(auth))

        # Identifier kinds the endpoint consumes: templated path segments + params.
        for seg in normalize_path(path).split("/"):
            if seg == "{id}":
                node.consumes_ids.add("generic_id")
        for param_name in _param_names(endpoint):
            kind = identifier_kind(param_name)
            if kind:
                node.consumes_ids.add(kind)
        return node

    def observe_response_identifier(
        self, *, endpoint_id: str, field_name: str, value: str | None = None
    ) -> None:
        """Record that an endpoint exposed an identifier of a given kind/value."""
        node = self._node_by_id(endpoint_id)
        if node is None:
            return
        kind = identifier_kind(field_name)
        if kind:
            node.exposes_ids.add(kind)
        if value:
            node.observed_values.add(str(value))

    def ingest_finding(self, finding: dict[str, Any]) -> None:
        """Update exposure knowledge from a confirmed finding.

        An excessive-data-exposure or BOLA finding on an endpoint implies that
        endpoint exposes the identifiers it returns — record them so chaining can
        use them next round.
        """
        endpoint_id = str(finding.get("endpoint_id") or "")
        for field_name in finding.get("exposed_fields") or []:
            self.observe_response_identifier(endpoint_id=endpoint_id, field_name=str(field_name))

    # ── reasoning ────────────────────────────────────────────────────────────

    def chains(self) -> list[ChainEdge]:
        """Compute candidate chains: A exposes kind K, B consumes kind K."""
        edges: list[ChainEdge] = []
        exposers: dict[str, list[EndpointNode]] = {}
        for node in self._nodes.values():
            for kind in node.exposes_ids:
                exposers.setdefault(kind, []).append(node)

        for node in self._nodes.values():
            for kind in node.consumes_ids:
                for source in exposers.get(kind, []):
                    if source.endpoint_id == node.endpoint_id:
                        continue
                    edges.append(
                        ChainEdge(
                            source_endpoint_id=source.endpoint_id,
                            target_endpoint_id=node.endpoint_id,
                            id_kind=kind,
                            reason=f"{source.endpoint_id} exposes {kind}; {node.endpoint_id} consumes it",
                        )
                    )
        edges.sort(key=lambda e: (e.id_kind, e.source_endpoint_id, e.target_endpoint_id))
        return edges

    def endpoints(self) -> list[EndpointNode]:
        return list(self._nodes.values())

    def recon_context(self) -> list[dict[str, Any]]:
        """Endpoint dicts enriched with exposure/consumption for the strategist."""
        context = []
        for node in self._nodes.values():
            context.append(
                {
                    "id": node.endpoint_id,
                    "method": node.method,
                    "path": normalize_path(node.path),
                    "host": node.host,
                    "protocol": node.protocol,
                    "auth_types_found": sorted(node.auth_types),
                    "private_variable_count": len(node.consumes_ids),
                    "exposes_ids": sorted(node.exposes_ids),
                }
            )
        return context

    # ── persistence ──────────────────────────────────────────────────────────

    def merge(self, other: "KnowledgeGraph") -> "KnowledgeGraph":
        for node in other.endpoints():
            key = node.key
            existing = self._nodes.get(key)
            if existing is None:
                self._nodes[key] = node
            else:
                existing.auth_types |= node.auth_types
                existing.consumes_ids |= node.consumes_ids
                existing.exposes_ids |= node.exposes_ids
                existing.observed_values |= node.observed_values
                existing.host = existing.host or node.host
                if node.protocol:
                    existing.protocol = node.protocol
        return self

    def as_dict(self) -> dict[str, Any]:
        return {
            "endpoints": [n.as_dict() for n in self._nodes.values()],
            "chains": [c.as_dict() for c in self.chains()],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "KnowledgeGraph":
        graph = cls()
        for entry in (data or {}).get("endpoints", []):
            node = EndpointNode(
                endpoint_id=str(entry.get("endpoint_id")),
                method=str(entry.get("method", "GET")),
                path=str(entry.get("path", "/")),
                host=str(entry.get("host") or ""),
                protocol=str(entry.get("protocol") or "https"),
                auth_types=set(entry.get("auth_types") or []),
                consumes_ids=set(entry.get("consumes_ids") or []),
                exposes_ids=set(entry.get("exposes_ids") or []),
            )
            graph._nodes[node.key] = node
        return graph

    # ── internals ────────────────────────────────────────────────────────────

    def _node_by_id(self, endpoint_id: str) -> EndpointNode | None:
        for node in self._nodes.values():
            if node.endpoint_id == endpoint_id:
                return node
        return None


def build_from_endpoints(endpoints: Iterable[dict[str, Any]]) -> KnowledgeGraph:
    graph = KnowledgeGraph()
    for endpoint in endpoints:
        graph.add_endpoint(endpoint)
    return graph


def _param_names(endpoint: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for param in endpoint.get("parameters") or []:
        if isinstance(param, dict) and param.get("name"):
            names.append(str(param["name"]))
    # Some selection contexts carry a flat list of identifier names.
    for name in endpoint.get("identifier_params") or []:
        names.append(str(name))
    return names
