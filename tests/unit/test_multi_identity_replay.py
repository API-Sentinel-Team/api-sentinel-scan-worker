"""Tests for multi-identity BOLA/BFLA replay confirmation (no network)."""
from __future__ import annotations

import pytest

from sentinel_core.models.core import TestAccount
from sentinel_worker.modules.identity import multi_identity_replay as mir
from sentinel_worker.modules.identity.multi_identity_replay import (
    pick_identity_pair,
    run_multi_identity_replay,
)


def _acct(id_, role, token):
    return TestAccount(id=id_, account_id=1000000, name=f"u{id_}", role=role, auth_token=token)


# ── identity pairing ─────────────────────────────────────────────────────────

def test_pick_pair_excludes_inactive_and_expired_accounts():
    from datetime import datetime, timedelta, timezone
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    future = datetime.now(timezone.utc) + timedelta(hours=1)

    suspended = _acct(3, "USER", "t3")
    suspended.status = "SUSPENDED"
    expired = _acct(4, "USER", "t4")
    expired.status = "ACTIVE"
    expired.expired_at = past
    valid = _acct(5, "USER", "t5")
    valid.status = "ACTIVE"
    valid.expired_at = future
    valid2 = _acct(6, "USER", "t6")
    valid2.status = "ACTIVE"
    valid2.expired_at = None

    # Only 1 usable active non-expired account among 4 candidates → no pair
    assert pick_identity_pair([_acct(1, "USER", "t1"), suspended, expired], issue="BOLA") is None
    # Two valid active accounts → pair returned
    pair = pick_identity_pair([suspended, expired, valid, valid2], issue="BOLA")
    assert pair is not None
    assert {pair[0].id, pair[1].id} == {5, 6}


def test_pick_pair_requires_two_usable_identities():
    assert pick_identity_pair([_acct(1, "USER", "t1")], issue="BOLA") is None
    # account with no token is unusable
    no_tok = TestAccount(id=9, account_id=1000000, name="x", role="USER", auth_token=None)
    assert pick_identity_pair([_acct(1, "USER", "t1"), no_tok], issue="BOLA") is None


def test_pick_pair_bola_any_two():
    pair = pick_identity_pair([_acct(1, "USER", "t1"), _acct(2, "USER", "t2")], issue="BOLA")
    assert pair is not None
    assert {pair[0].id, pair[1].id} == {1, 2}


def test_pick_pair_bfla_prefers_privilege_boundary():
    # Admin victim + user attacker -> the privilege-boundary pair is chosen.
    pair = pick_identity_pair([_acct(1, "ADMIN", "t1"), _acct(2, "USER", "t2")], issue="BFLA")
    assert pair is not None
    assert pair[0].role == "ADMIN" and pair[1].role == "USER"


def test_pick_pair_bfla_falls_back_to_any_two_without_boundary():
    # No clear privilege boundary -> still returns a cross-identity pair so the
    # replay can run; classification happens post-hoc from roles.
    pair = pick_identity_pair([_acct(1, "USER", "t1"), _acct(2, "USER", "t2")], issue="BFLA")
    assert pair is not None
    assert {pair[0].id, pair[1].id} == {1, 2}


# ── replay confirmation (mocked transport) ───────────────────────────────────

@pytest.mark.asyncio
async def test_replay_confirms_bola_when_attacker_gets_victim_resource(monkeypatch):
    victim_body = '{"username":"alice","email":"alice@x.com","admin":false}'

    async def fake_execute(request, *, timeout):
        # Victim + attacker (authenticated) get alice's data; anonymous control is
        # denied -> access is gated -> a genuine BOLA.
        headers = {str(k).lower(): v for k, v in request.get("headers", {}).items()}
        if not headers.get("authorization"):
            return {"status_code": 401, "headers": {}, "body": "unauthorized", "url": request["url"]}
        return {"status_code": 200, "headers": {}, "body": victim_body, "url": request["url"]}

    monkeypatch.setattr(mir, "_execute", fake_execute)

    endpoint = {"id": "ep1", "method": "GET", "path": "/users/v1/alice",
                "host": "api.example.com", "protocol": "https"}
    result = await run_multi_identity_replay(
        endpoint=endpoint,
        victim=_acct(1, "USER", "alice-tok"),
        attacker=_acct(2, "USER", "bob-tok"),
        target_guard=_AllowGuard(),
    )
    assert result["is_vulnerable"] is True
    assert result["type"] == "BOLA"
    assert result["confidence"] == "HIGH"
    assert result["evidence"]["engine"] == "authorization_replay"


@pytest.mark.asyncio
async def test_public_sensitive_endpoint_reclassified_as_broken_auth(monkeypatch):
    # Victim + attacker get the same body, AND an unauthenticated control also gets
    # it -> NOT a cross-identity BOLA. But returning the resource with no auth IS a
    # real finding: reclassify as BROKEN_AUTH rather than drop it (and never call
    # it BOLA, which would be a false positive).
    sensitive_body = '{"username":"alice","email":"alice@x.com"}'

    async def fake_execute(request, *, timeout):
        # Everyone (incl. no-auth control) gets 200 + same body.
        return {"status_code": 200, "headers": {}, "body": sensitive_body, "url": request["url"]}

    monkeypatch.setattr(mir, "_execute", fake_execute)

    endpoint = {"id": "ep1", "method": "GET", "path": "/users/v1/alice",
                "host": "api.example.com", "protocol": "https"}
    result = await run_multi_identity_replay(
        endpoint=endpoint,
        victim=_acct(1, "USER", "alice-tok"),
        attacker=_acct(2, "USER", "bob-tok"),
        target_guard=_AllowGuard(),
    )
    assert result["assessment"]["control_indicates_public"] is True
    assert result["type"] == "BROKEN_AUTH"  # NOT BOLA
    assert result["is_vulnerable"] is True   # still a real, surfaced finding


@pytest.mark.asyncio
async def test_real_bola_survives_control_when_anon_denied(monkeypatch):
    # Victim + attacker get alice's data, but anonymous control is denied (403) ->
    # access IS gated -> the BOLA finding stands.
    victim_body = '{"username":"alice","email":"alice@x.com"}'

    async def fake_execute(request, *, timeout):
        headers = {str(k).lower(): v for k, v in request.get("headers", {}).items()}
        if not headers.get("authorization"):  # anonymous control
            return {"status_code": 403, "headers": {}, "body": "forbidden", "url": request["url"]}
        return {"status_code": 200, "headers": {}, "body": victim_body, "url": request["url"]}

    monkeypatch.setattr(mir, "_execute", fake_execute)

    endpoint = {"id": "ep1", "method": "GET", "path": "/users/v1/alice",
                "host": "api.example.com", "protocol": "https"}
    result = await run_multi_identity_replay(
        endpoint=endpoint,
        victim=_acct(1, "USER", "alice-tok"),
        attacker=_acct(2, "USER", "bob-tok"),
        target_guard=_AllowGuard(),
    )
    assert result["is_vulnerable"] is True
    assert result["type"] == "BOLA"
    assert result["assessment"]["control_indicates_public"] is False


@pytest.mark.asyncio
async def test_replay_not_vulnerable_when_attacker_denied(monkeypatch):
    async def fake_execute(request, *, timeout):
        # Attacker's token (bob-tok) is denied 403; victim gets 200.
        if "bob-tok" in str(request.get("headers", {})):
            return {"status_code": 403, "headers": {}, "body": '{"error":"forbidden"}', "url": request["url"]}
        return {"status_code": 200, "headers": {}, "body": '{"username":"alice"}', "url": request["url"]}

    monkeypatch.setattr(mir, "_execute", fake_execute)

    endpoint = {"id": "ep1", "method": "GET", "path": "/users/v1/alice",
                "host": "api.example.com", "protocol": "https"}
    result = await run_multi_identity_replay(
        endpoint=endpoint,
        victim=_acct(1, "USER", "alice-tok"),
        attacker=_acct(2, "USER", "bob-tok"),
        target_guard=_AllowGuard(),
    )
    assert result["is_vulnerable"] is False


@pytest.mark.asyncio
async def test_replay_blocked_by_state_change_guard(monkeypatch):
    called = {"n": 0}

    async def fake_execute(request, *, timeout):
        called["n"] += 1
        return {"status_code": 200, "headers": {}, "body": "{}", "url": request["url"]}

    monkeypatch.setattr(mir, "_execute", fake_execute)

    # A DELETE replay with state-change NOT armed must be blocked before any request.
    endpoint = {"id": "ep1", "method": "DELETE", "path": "/users/v1/alice",
                "host": "api.example.com", "protocol": "https"}
    result = await run_multi_identity_replay(
        endpoint=endpoint,
        victim=_acct(1, "ADMIN", "alice-tok"),
        attacker=_acct(2, "USER", "bob-tok"),
        target_guard=_AllowGuard(),
        allow_state_change=False,
    )
    assert result["is_vulnerable"] is False
    assert result["skip_reason"] == "state_change_guard"
    assert called["n"] == 0  # no network egress when blocked


def test_victim_object_url_substitutes_victim_identifier():
    from sentinel_worker.modules.identity.multi_identity_replay import _victim_object_url

    victim = _acct(1, "USER", "t1")
    victim.name = "alice"
    # Templated segment -> victim's own id (correct BOLA setup).
    ep = {"method": "GET", "path": "/users/v1/{username}", "host": "api.example.com", "protocol": "https"}
    assert _victim_object_url(ep, victim) == "https://api.example.com/users/v1/alice"
    # Numeric placeholder "1" also substituted.
    ep2 = {"method": "GET", "path": "/users/v1/1", "host": "api.example.com", "protocol": "https"}
    assert _victim_object_url(ep2, victim) == "https://api.example.com/users/v1/alice"
    # Non-templated path is unchanged.
    ep3 = {"method": "GET", "path": "/users/v1/_debug", "host": "api.example.com", "protocol": "https"}
    assert _victim_object_url(ep3, victim) == "https://api.example.com/users/v1/_debug"


class _AllowGuard:
    """A TargetGuard stand-in that allows everything (test isolation)."""

    def validate_url(self, url, base_url=None):
        return None
