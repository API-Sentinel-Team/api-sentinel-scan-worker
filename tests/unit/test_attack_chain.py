"""Tests for the 2-step capture->reuse attack-chain executor."""
from __future__ import annotations

import pytest

from sentinel_core.models.core import TestAccount
from sentinel_worker.modules.identity import attack_chain as ac
from sentinel_worker.modules.identity.attack_chain import (
    capture_object_ids,
    run_attack_chain,
)


def _acct(id_, role, token, name=None):
    a = TestAccount(id=id_, account_id=1000000, name=name or f"u{id_}", role=role, auth_token=token)
    return a


class _AllowGuard:
    def validate_url(self, url, base_url=None):
        return None


# ── ID capture ───────────────────────────────────────────────────────────────

def test_capture_ids_from_list():
    assert capture_object_ids({"body": '[{"id":1},{"id":2}]'}) == ["1", "2"]


def test_capture_ids_nested_and_typed():
    assert capture_object_ids({"body": '{"user":{"user_id":"u-7"}}'}) == ["u-7"]


def test_capture_ids_none_when_no_id_fields():
    assert capture_object_ids({"body": '{"color":"red"}'}) == []
    assert capture_object_ids({"body": ""}) == []
    assert capture_object_ids({"body": "not json"}) == []


def test_capture_prefers_username_handle_over_email():
    # REST APIs route by username/slug, not email — username must come first so
    # the chain targets a real path segment (this was a live VAmPI bug fix).
    ids = capture_object_ids({"body": '[{"username":"name1","email":"mail1@x.com"}]'})
    assert ids[0] == "name1"


def test_capture_id_like_beats_handles():
    ids = capture_object_ids({"body": '[{"id":"7","username":"name1"}]'})
    assert ids[0] == "7"


# ── full 2-step chain ────────────────────────────────────────────────────────

_SOURCE = {"id": "list", "method": "GET", "path": "/users", "host": "api.example.com", "protocol": "https"}
_TARGET = {"id": "get", "method": "GET", "path": "/users/{id}", "host": "api.example.com", "protocol": "https"}


@pytest.mark.asyncio
async def test_chain_confirms_bola_with_captured_id(monkeypatch):
    victim_obj = '{"id":"42","email":"alice@x.com"}'

    async def fake_execute(request, *, timeout):
        url = request["url"]
        headers = {str(k).lower(): v for k, v in request.get("headers", {}).items()}
        if url.endswith("/users"):  # step 1: capture
            return {"status_code": 200, "headers": {}, "body": '[{"id":"42"}]', "url": url}
        if not headers.get("authorization"):  # no-auth control on target -> denied
            return {"status_code": 401, "headers": {}, "body": "no", "url": url}
        # victim + attacker both get object 42 -> cross-object access
        return {"status_code": 200, "headers": {}, "body": victim_obj, "url": url}

    monkeypatch.setattr(ac, "_execute", fake_execute)

    result = await run_attack_chain(
        source_endpoint=_SOURCE, target_endpoint=_TARGET,
        victim=_acct(1, "USER", "alice-tok"), attacker=_acct(2, "USER", "bob-tok"),
        id_kind="user_id", target_guard=_AllowGuard(),
    )
    assert result["is_vulnerable"] is True
    assert result["type"] == "BOLA"
    assert result["chain"]["steps"] == 2
    assert result["chain"]["control_indicates_public"] is False


@pytest.mark.asyncio
async def test_chain_reclassifies_public_target_as_broken_auth(monkeypatch):
    obj = '{"id":"42","email":"alice@x.com"}'

    async def fake_execute(request, *, timeout):
        url = request["url"]
        if url.endswith("/users"):
            return {"status_code": 200, "headers": {}, "body": '[{"id":"42"}]', "url": url}
        # EVERYONE (incl. no-auth control) gets the object -> public target
        return {"status_code": 200, "headers": {}, "body": obj, "url": url}

    monkeypatch.setattr(ac, "_execute", fake_execute)

    result = await run_attack_chain(
        source_endpoint=_SOURCE, target_endpoint=_TARGET,
        victim=_acct(1, "USER", "alice-tok"), attacker=_acct(2, "USER", "bob-tok"),
        target_guard=_AllowGuard(),
    )
    assert result["type"] == "BROKEN_AUTH"
    assert result["chain"]["control_indicates_public"] is True


@pytest.mark.asyncio
async def test_chain_skips_when_no_id_captured(monkeypatch):
    async def fake_execute(request, *, timeout):
        return {"status_code": 200, "headers": {}, "body": '{"color":"red"}', "url": request["url"]}

    monkeypatch.setattr(ac, "_execute", fake_execute)

    result = await run_attack_chain(
        source_endpoint=_SOURCE, target_endpoint=_TARGET,
        victim=_acct(1, "USER", "t1"), attacker=_acct(2, "USER", "t2"),
        target_guard=_AllowGuard(),
    )
    assert result["is_vulnerable"] is False
    assert result["skip_reason"] == "no_object_id_captured"


@pytest.mark.asyncio
async def test_chain_not_vulnerable_when_attacker_denied(monkeypatch):
    async def fake_execute(request, *, timeout):
        url = request["url"]
        headers = {str(k).lower(): v for k, v in request.get("headers", {}).items()}
        if url.endswith("/users"):
            return {"status_code": 200, "headers": {}, "body": '[{"id":"42"}]', "url": url}
        if headers.get("authorization") == "Bearer bob-tok":  # attacker denied
            return {"status_code": 403, "headers": {}, "body": "forbidden", "url": url}
        if not headers.get("authorization"):
            return {"status_code": 401, "headers": {}, "body": "no", "url": url}
        return {"status_code": 200, "headers": {}, "body": '{"id":"42"}', "url": url}

    monkeypatch.setattr(ac, "_execute", fake_execute)

    result = await run_attack_chain(
        source_endpoint=_SOURCE, target_endpoint=_TARGET,
        victim=_acct(1, "USER", "alice-tok"), attacker=_acct(2, "USER", "bob-tok"),
        target_guard=_AllowGuard(),
    )
    assert result["is_vulnerable"] is False


@pytest.mark.asyncio
async def test_chain_classifies_bfla_on_role_difference(monkeypatch):
    obj = '{"id":"42"}'

    async def fake_execute(request, *, timeout):
        url = request["url"]
        headers = {str(k).lower(): v for k, v in request.get("headers", {}).items()}
        if url.endswith("/users"):
            return {"status_code": 200, "headers": {}, "body": '[{"id":"42"}]', "url": url}
        if not headers.get("authorization"):
            return {"status_code": 401, "headers": {}, "body": "no", "url": url}
        return {"status_code": 200, "headers": {}, "body": obj, "url": url}

    monkeypatch.setattr(ac, "_execute", fake_execute)

    result = await run_attack_chain(
        source_endpoint=_SOURCE, target_endpoint=_TARGET,
        victim=_acct(1, "ADMIN", "admin-tok"), attacker=_acct(2, "USER", "user-tok"),
        target_guard=_AllowGuard(),
    )
    assert result["is_vulnerable"] is True
    assert result["type"] == "BFLA"  # privileged victim, low attacker -> BFLA
