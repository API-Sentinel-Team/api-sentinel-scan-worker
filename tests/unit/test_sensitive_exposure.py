"""Tests for the sensitive-data-exposure detector."""
from __future__ import annotations

import pytest

from sentinel_worker.modules.identity import sensitive_exposure as se
from sentinel_worker.modules.identity.sensitive_exposure import (
    detect_sensitive_exposure,
    scan_sensitive_fields,
)


class _AllowGuard:
    def validate_url(self, url, base_url=None):
        return None


# -- scan_sensitive_fields (pure, no network) ---------------------------------

def test_scan_detects_password_field():
    scan = scan_sensitive_fields({"username": "a", "password": "x"})
    assert "password" in scan["sensitive_fields"]
    assert scan["has_credentials"] is True


def test_scan_detects_bulk_pii_list():
    body = {
        "users": [
            {"username": "a", "email": "a@x"},
            {"username": "b", "email": "b@x"},
            {"username": "c", "email": "c@x"},
        ]
    }
    scan = scan_sensitive_fields(body)
    # No credential fields, but >=3 PII objects -> bulk dump flagged.
    assert "bulk_pii" in scan["sensitive_fields"]
    assert scan["has_credentials"] is False
    assert scan["record_count"] == 3


def test_scan_has_credentials_true_for_token():
    scan = scan_sensitive_fields({"data": [{"token": "abc"}]})
    assert "token" in scan["sensitive_fields"]
    assert scan["has_credentials"] is True


def test_scan_empty_for_benign_body():
    scan = scan_sensitive_fields({"color": "red"})
    assert scan["sensitive_fields"] == []
    assert scan["has_credentials"] is False


def test_scan_two_pii_objects_not_bulk():
    body = [{"email": "a@x"}, {"email": "b@x"}]
    scan = scan_sensitive_fields(body)
    assert "bulk_pii" not in scan["sensitive_fields"]


# -- detect_sensitive_exposure (network monkeypatched) ------------------------

_ENDPOINT = {
    "id": "debug",
    "method": "GET",
    "path": "/users/v1/_debug",
    "host": "vampi.example.com",
    "protocol": "https",
}

# Distinctive sentinel values so we can prove no raw value leaks into evidence
# (a bare "x" would collide with substrings of words like "exposure").
_VAMPI_DEBUG_BODY = {
    "users": [
        {"username": "alice", "password": "SECRETVAL1", "email": "alice@vampi"},
        {"username": "bob", "password": "SECRETVAL2", "email": "bob@vampi"},
        {"username": "carol", "password": "SECRETVAL3", "email": "carol@vampi"},
    ]
}


@pytest.mark.asyncio
async def test_detect_flags_vampi_debug_dump(monkeypatch):
    async def fake_get(url, headers, timeout):
        return {
            "status_code": 200,
            "headers": {},
            "body": _VAMPI_DEBUG_BODY,
            "url": url,
        }

    monkeypatch.setattr(se, "_http_get", fake_get)

    result = await detect_sensitive_exposure(
        endpoint=_ENDPOINT, target_guard=_AllowGuard()
    )

    assert result["is_vulnerable"] is True
    assert result["type"] == "SENSITIVE_DATA_EXPOSURE"
    assert result["severity"] == "HIGH"
    assert "password" in result["evidence"]["exposed_fields"]
    assert result["evidence"]["engine"] == "sensitive_exposure"
    assert result["evidence"]["status_code"] == 200
    # No raw values must leak into the returned evidence.
    assert "SECRETVAL1" not in str(result)
    assert "alice" not in str(result)


@pytest.mark.asyncio
async def test_detect_no_sensitive_exposure(monkeypatch):
    async def fake_get(url, headers, timeout):
        return {"status_code": 200, "headers": {}, "body": {"color": "red"}, "url": url}

    monkeypatch.setattr(se, "_http_get", fake_get)

    result = await detect_sensitive_exposure(
        endpoint=_ENDPOINT, target_guard=_AllowGuard()
    )
    assert result["is_vulnerable"] is False
    assert result["skip_reason"] == "no_sensitive_exposure"
    assert result["status_code"] == 200


@pytest.mark.asyncio
async def test_detect_bulk_pii_medium_severity(monkeypatch):
    body = {
        "users": [
            {"username": "a", "email": "a@x"},
            {"username": "b", "email": "b@x"},
            {"username": "c", "email": "c@x"},
        ]
    }

    async def fake_get(url, headers, timeout):
        return {"status_code": 200, "headers": {}, "body": body, "url": url}

    monkeypatch.setattr(se, "_http_get", fake_get)

    result = await detect_sensitive_exposure(
        endpoint=_ENDPOINT, target_guard=_AllowGuard()
    )
    assert result["is_vulnerable"] is True
    assert result["severity"] == "MEDIUM"
    assert "bulk_pii" in result["evidence"]["exposed_fields"]


@pytest.mark.asyncio
async def test_detect_target_guard_blocks(monkeypatch):
    from sentinel_core.modules.test_executor.target_guard import TargetGuardError

    class _BlockGuard:
        def validate_url(self, url, base_url=None):
            raise TargetGuardError("private targets are blocked")

    called = {"net": False}

    async def fake_get(url, headers, timeout):
        called["net"] = True
        return {"status_code": 200, "headers": {}, "body": {}, "url": url}

    monkeypatch.setattr(se, "_http_get", fake_get)

    result = await detect_sensitive_exposure(
        endpoint=_ENDPOINT, target_guard=_BlockGuard()
    )
    assert result["is_vulnerable"] is False
    assert result["skip_reason"] == "target_guard"
    assert called["net"] is False


@pytest.mark.asyncio
async def test_detect_network_error_never_raises(monkeypatch):
    async def fake_get(url, headers, timeout):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(se, "_http_get", fake_get)

    result = await detect_sensitive_exposure(
        endpoint=_ENDPOINT, target_guard=_AllowGuard()
    )
    assert result["is_vulnerable"] is False
    assert "error" in result
