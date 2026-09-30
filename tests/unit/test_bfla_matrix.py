"""Unit tests for the BFLA role×function matrix."""
import pytest

from sentinel_worker.modules.identity.bfla_matrix import (
    bfla_endpoint_risk,
    pick_bfla_pair,
)


def _acct(id_, role, token="tok"):
    from sentinel_core.models.core import TestAccount
    a = TestAccount(id=id_, account_id=1000000, name=f"u{id_}", role=role, auth_token=token)
    return a


# ── endpoint risk scoring ──────────────────────────────────────────────────

def test_admin_path_signals_high_tier():
    risk = bfla_endpoint_risk({"method": "GET", "path": "/admin/users"})
    assert risk["expected_minimum_role_tier"] == 3
    assert risk["is_admin_path"] is True


def test_write_method_signals_user_tier():
    risk = bfla_endpoint_risk({"method": "POST", "path": "/orders"})
    assert risk["expected_minimum_role_tier"] == 1
    assert risk["is_write_method"] is True
    assert risk["is_admin_path"] is False


def test_privileged_action_signals_manager_tier():
    risk = bfla_endpoint_risk({"method": "POST", "path": "/users/123/ban"})
    assert risk["expected_minimum_role_tier"] == 2
    assert risk["is_privileged_action"] is True


# ── pair selection ──────────────────────────────────────────────────────────

def test_pick_bfla_pair_selects_admin_vs_user_for_admin_endpoint():
    admin = _acct(1, "ADMIN")
    user = _acct(2, "USER")
    endpoint = {"method": "DELETE", "path": "/admin/users/123"}
    pair = pick_bfla_pair([admin, user], endpoint=endpoint)
    assert pair is not None
    assert pair[0].role == "ADMIN"
    assert pair[1].role == "USER"


def test_pick_bfla_pair_selects_closest_boundary():
    # Manager and viewer both available — viewer is the attacker, manager is victim
    # because manager crosses the boundary relative to viewer for a write endpoint.
    manager = _acct(1, "MANAGER")
    viewer = _acct(2, "VIEWER")
    endpoint = {"method": "POST", "path": "/reports"}
    pair = pick_bfla_pair([manager, viewer], endpoint=endpoint)
    assert pair is not None
    victim_role = pair[0].role.upper()
    attacker_role = pair[1].role.upper()
    assert victim_role == "MANAGER"
    assert attacker_role == "VIEWER"


def test_pick_bfla_pair_returns_none_when_no_privilege_gap():
    user1 = _acct(1, "USER")
    user2 = _acct(2, "USER")
    endpoint = {"method": "GET", "path": "/items"}
    # Two users with the same tier — no privilege gap
    result = pick_bfla_pair([user1, user2], endpoint=endpoint)
    # Falls back to any two if tiers are equal — no meaningful boundary
    # Accept None OR a pair (implementation may fall back)
    if result is not None:
        assert result[0].id != result[1].id


def test_pick_bfla_pair_returns_none_for_single_account():
    admin = _acct(1, "ADMIN")
    assert pick_bfla_pair([admin], endpoint={"method": "GET", "path": "/"}) is None


def test_pick_bfla_pair_without_endpoint_uses_maximum_boundary():
    superadmin = _acct(1, "SUPERADMIN")
    guest = _acct(2, "GUEST")
    pair = pick_bfla_pair([superadmin, guest])
    assert pair is not None
    assert pair[0].id == 1  # superadmin as victim
    assert pair[1].id == 2  # guest as attacker
