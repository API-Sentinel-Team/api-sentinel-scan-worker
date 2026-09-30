"""Tests for the mass-assignment (BOPLA / OWASP API3) detector."""
from __future__ import annotations

import pytest

from sentinel_worker.modules.identity import mass_assignment as ma
from sentinel_worker.modules.identity.mass_assignment import (
    detect_mass_assignment,
    detect_privileged_reflection,
)


class _AllowGuard:
    def validate_url(self, url, base_url=None):
        return None


_ENDPOINT = {
    "id": "register",
    "method": "POST",
    "path": "/users/v1/register",
    "host": "api.example.com",
    "protocol": "https",
}
_BASE_PAYLOAD = {"username": "eve", "password": "pw", "email": "eve@x.com"}


# ── pure reflection check ─────────────────────────────────────────────────────

def test_reflection_true_when_admin_echoed():
    assert detect_privileged_reflection({"username": "eve", "admin": True}, "admin", True) is True


def test_reflection_true_when_nested():
    body = {"user": {"username": "eve", "admin": True}}
    assert detect_privileged_reflection(body, "admin", True) is True


def test_reflection_false_when_admin_false():
    assert detect_privileged_reflection({"username": "eve", "admin": False}, "admin", True) is False


def test_reflection_false_when_field_absent():
    assert detect_privileged_reflection({"username": "eve"}, "admin", True) is False
    assert detect_privileged_reflection(None, "admin", True) is False


def test_reflection_role_string():
    assert detect_privileged_reflection({"role": "admin"}, "role", "admin") is True
    assert detect_privileged_reflection({"role": "user"}, "role", "admin") is False


# ── full detector with stubbed network ────────────────────────────────────────

@pytest.mark.asyncio
async def test_detects_mass_assignment_when_admin_accepted(monkeypatch):
    async def fake_http(method, url, headers, json_body, timeout):
        # Server honors client-supplied admin and echoes it in a 201.
        if json_body.get("admin") is True:
            return {
                "status_code": 201,
                "headers": {},
                "body": '{"username":"eve","admin":true}',
                "url": url,
            }
        return {"status_code": 200, "headers": {}, "body": '{"username":"eve"}', "url": url}

    monkeypatch.setattr(ma, "_http_request", fake_http)

    result = await detect_mass_assignment(
        endpoint=_ENDPOINT,
        base_payload=_BASE_PAYLOAD,
        target_guard=_AllowGuard(),
    )
    assert result["is_vulnerable"] is True
    assert result["type"] == "MASS_ASSIGNMENT"
    assert result["severity"] == "HIGH"
    assert result["evidence"]["injected_field"] == "admin"
    assert result["evidence"]["engine"] == "mass_assignment"
    assert result["evidence"]["reflected"] is True
    assert result["evidence"]["status_code"] == 201


@pytest.mark.asyncio
async def test_no_hit_when_server_ignores_field(monkeypatch):
    async def fake_http(method, url, headers, json_body, timeout):
        # Server ignores the privileged field: always returns admin:false, no echo.
        return {
            "status_code": 200,
            "headers": {},
            "body": '{"username":"eve","admin":false}',
            "url": url,
        }

    monkeypatch.setattr(ma, "_http_request", fake_http)

    result = await detect_mass_assignment(
        endpoint=_ENDPOINT,
        base_payload=_BASE_PAYLOAD,
        target_guard=_AllowGuard(),
    )
    assert result["is_vulnerable"] is False
    assert result["skip_reason"] == "no_mass_assignment"


@pytest.mark.asyncio
async def test_state_change_guard_blocks_before_egress(monkeypatch):
    calls = {"n": 0}

    async def fake_http(method, url, headers, json_body, timeout):
        calls["n"] += 1
        return {"status_code": 201, "headers": {}, "body": "{}", "url": url}

    monkeypatch.setattr(ma, "_http_request", fake_http)

    result = await detect_mass_assignment(
        endpoint=_ENDPOINT,
        base_payload=_BASE_PAYLOAD,
        target_guard=_AllowGuard(),
        allow_state_change=False,
    )
    assert result["is_vulnerable"] is False
    assert result["skip_reason"] == "state_change_guard"
    # Guard must block BEFORE any network egress happens.
    assert calls["n"] == 0
