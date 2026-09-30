"""Tests for the API knowledge graph (agentic recon model)."""
from __future__ import annotations

import pytest

from sentinel_worker.modules.agentic.knowledge_graph import (
    KnowledgeGraph,
    build_from_endpoints,
    identifier_kind,
    normalize_path,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("/users/v1/{username}", "/users/v1/{id}"),
        ("/users/42", "/users/{id}"),
        ("/users/550e8400-e29b-41d4-a716-446655440000", "/users/{id}"),
        ("/Books/V1", "/books/v1"),
    ],
)
def test_normalize_path(raw, expected):
    assert normalize_path(raw) == expected


@pytest.mark.parametrize(
    "name,kind",
    [
        ("user_id", "user_id"),
        ("username", "user_id"),
        ("account", "account_id"),
        ("book_title", "book_id"),
        ("id", "generic_id"),
        ("order_id", "order_id"),
        ("color", None),
    ],
)
def test_identifier_kind(name, kind):
    assert identifier_kind(name) == kind


def test_add_endpoint_records_consumed_ids():
    g = KnowledgeGraph()
    node = g.add_endpoint({
        "id": "ep1", "method": "GET", "path": "/users/v1/{username}",
        "auth_types_found": ["bearer"],
    })
    assert "generic_id" in node.consumes_ids  # templated path segment
    assert node.auth_types == {"bearer"}


def test_add_endpoint_merges_duplicates():
    g = KnowledgeGraph()
    g.add_endpoint({"id": "ep1", "method": "GET", "path": "/users/1", "auth_types_found": ["bearer"]})
    g.add_endpoint({"id": "ep1b", "method": "GET", "path": "/users/2", "auth_types_found": ["cookie"]})
    # Same normalized identity -> one node, merged auth types.
    assert len(g.endpoints()) == 1
    assert g.endpoints()[0].auth_types == {"bearer", "cookie"}


def test_chaining_links_exposer_to_consumer():
    g = build_from_endpoints([
        {"id": "list_users", "method": "GET", "path": "/users", "parameters": []},
        {"id": "get_user", "method": "GET", "path": "/users/{user_id}", "parameters": [{"name": "user_id"}]},
    ])
    # list_users leaks user_id values (observed); get_user consumes user_id.
    g.observe_response_identifier(endpoint_id="list_users", field_name="user_id", value="42")
    chains = g.chains()
    assert len(chains) == 1
    assert chains[0].source_endpoint_id == "list_users"
    assert chains[0].target_endpoint_id == "get_user"
    assert chains[0].id_kind == "user_id"


def test_chaining_ignores_self_links():
    g = build_from_endpoints([
        {"id": "ep", "method": "GET", "path": "/users/{user_id}", "parameters": [{"name": "user_id"}]},
    ])
    g.observe_response_identifier(endpoint_id="ep", field_name="user_id")
    assert g.chains() == []  # an endpoint chaining to itself is not a cross-object path


def test_ingest_finding_adds_exposure():
    g = build_from_endpoints([
        {"id": "debug", "method": "GET", "path": "/users/v1/_debug"},
        {"id": "get_user", "method": "GET", "path": "/users/{user_id}", "parameters": [{"name": "user_id"}]},
    ])
    g.ingest_finding({"endpoint_id": "debug", "exposed_fields": ["user_id", "password"]})
    chains = g.chains()
    assert any(c.source_endpoint_id == "debug" and c.id_kind == "user_id" for c in chains)


def test_recon_context_shape_feeds_strategist():
    g = build_from_endpoints([
        {"id": "ep1", "method": "GET", "path": "/users/{user_id}", "auth_types_found": ["bearer"], "parameters": [{"name": "user_id"}]},
    ])
    ctx = g.recon_context()
    assert ctx[0]["id"] == "ep1"
    assert ctx[0]["method"] == "GET"
    assert ctx[0]["auth_types_found"] == ["bearer"]
    assert ctx[0]["private_variable_count"] >= 1


def test_merge_accumulates_across_scans():
    g1 = build_from_endpoints([{"id": "a", "method": "GET", "path": "/a"}])
    g2 = build_from_endpoints([{"id": "b", "method": "GET", "path": "/b"}])
    g2.observe_response_identifier(endpoint_id="b", field_name="user_id")
    g1.merge(g2)
    keys = {n.endpoint_id for n in g1.endpoints()}
    assert keys == {"a", "b"}


def test_roundtrip_serialization():
    g = build_from_endpoints([
        {"id": "ep1", "method": "GET", "path": "/users/{user_id}", "auth_types_found": ["bearer"], "parameters": [{"name": "user_id"}]},
    ])
    g.observe_response_identifier(endpoint_id="ep1", field_name="user_id")
    data = g.as_dict()
    restored = KnowledgeGraph.from_dict(data)
    assert len(restored.endpoints()) == 1
    assert restored.endpoints()[0].exposes_ids == {"user_id"}
