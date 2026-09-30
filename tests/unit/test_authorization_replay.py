from sentinel_core.models import core as models
from sentinel_worker.modules.identity.authorization_replay import (
    build_authorization_replay_evidence,
    build_replay_request,
    classify_authorization_issue,
    evaluate_authorization_replay,
    auth_headers_for_account,
    infer_victim_account,
)
from sentinel_core.modules.identity.roles_context import RolesContextBuilder
from sentinel_core.modules.vulnerability_detector.lifecycle import verify_vulnerability_evidence


def _account(account_id: str, role: str, token: str) -> models.TestAccount:
    return models.TestAccount(
        id=account_id,
        account_id=1000000,
        name=role.title(),
        role=role,
        auth_headers={"Authorization": f"Bearer {token}"},
    )


def _anonymous_account() -> models.TestAccount:
    return models.TestAccount(
        id="anonymous",
        account_id=1000000,
        name="Unauthenticated",
        role="ANONYMOUS",
        auth_headers={},
    )


def test_build_replay_request_replaces_existing_auth_headers():
    attacker = _account("attacker", "MEMBER", "attacker-token")
    request = {
        "method": "GET",
        "url": "https://api.example.com/users/42",
        "headers": {
            "Authorization": "Bearer victim-token",
            "X-API-Key": "victim-key",
            "Accept": "application/json",
        },
    }

    replay = build_replay_request(request, attacker)

    assert replay["headers"]["Authorization"] == "Bearer attacker-token"
    assert "X-API-Key" not in replay["headers"]
    assert replay["headers"]["Accept"] == "application/json"


def test_build_replay_request_removes_victim_identity_boundary_headers():
    attacker = _account("attacker", "MEMBER", "attacker-token")
    request = {
        "method": "GET",
        "url": "https://api.example.com/users/42",
        "headers": {
            "Authorization": "Bearer victim-token",
            "X-Tenant-ID": "victim-tenant",
            "X-Account-ID": "victim-account",
            "Accept": "application/json",
        },
    }

    replay = build_replay_request(request, attacker)

    assert replay["headers"]["Authorization"] == "Bearer attacker-token"
    assert replay["headers"]["Accept"] == "application/json"
    assert "X-Tenant-ID" not in replay["headers"]
    assert "X-Account-ID" not in replay["headers"]


def test_build_replay_request_keeps_attacker_identity_boundary_headers():
    attacker = _account("attacker", "MEMBER", "attacker-token")
    attacker.auth_headers["X-Tenant-ID"] = "attacker-tenant"
    request = {
        "method": "GET",
        "url": "https://api.example.com/users/42",
        "headers": {
            "Authorization": "Bearer victim-token",
            "X-Tenant-ID": "victim-tenant",
            "Accept": "application/json",
        },
    }

    replay = build_replay_request(request, attacker)

    assert replay["headers"]["Authorization"] == "Bearer attacker-token"
    assert replay["headers"]["X-Tenant-ID"] == "attacker-tenant"
    assert replay["headers"]["Accept"] == "application/json"


def test_build_replay_request_replaces_privilege_boundary_headers():
    attacker = _account("attacker", "MEMBER", "attacker-token")
    attacker.auth_headers["X-User-Role"] = "finance-readonly-beta"
    attacker.auth_headers["X-Scopes"] = "orders:read"
    request = {
        "method": "GET",
        "url": "https://api.example.com/admin/orders/42",
        "headers": {
            "Authorization": "Bearer victim-token",
            "X-User-Role": "finance-admin-alpha",
            "X-Scopes": "orders:read orders:refund",
            "Accept": "application/json",
        },
    }

    replay = build_replay_request(request, attacker)

    assert replay["headers"]["Authorization"] == "Bearer attacker-token"
    assert replay["headers"]["X-User-Role"] == "finance-readonly-beta"
    assert replay["headers"]["X-Scopes"] == "orders:read"
    assert replay["headers"]["Accept"] == "application/json"


def test_anonymous_replay_strips_auth_and_records_redacted_evidence():
    victim = _account("victim", "OWNER", "victim-token")
    anonymous = _anonymous_account()
    original_request = {
        "method": "GET",
        "url": "https://api.example.com/users/42?token=victim-token",
        "headers": {
            "Authorization": "Bearer victim-token",
            "X-API-Key": "victim-api-key",
            "Accept": "application/json",
        },
    }
    replay_request = build_replay_request(original_request, anonymous)
    original_response = {"status_code": 200, "body": {"id": 42, "email": "victim@example.com"}}
    anonymous_response = {"status_code": 200, "body": '{"id":42,"email":"victim@example.com"}'}
    assessment = evaluate_authorization_replay(original_response, anonymous_response)

    evidence = build_authorization_replay_evidence(
        endpoint_id="endpoint-anonymous",
        issue_type="BFLA",
        victim=victim,
        attacker=anonymous,
        original_request=original_request,
        original_response=original_response,
        replay_request=replay_request,
        attacker_response=anonymous_response,
        assessment=assessment,
    )

    assert auth_headers_for_account(anonymous) == {"Authorization": ""}
    assert RolesContextBuilder().build([anonymous]) == {"ANONYMOUS": ""}
    assert "Authorization" not in replay_request["headers"]
    assert "X-API-Key" not in replay_request["headers"]
    assert replay_request["headers"]["Accept"] == "application/json"
    assert evidence["identity_pair"]["attacker"]["role"] == "ANONYMOUS"
    assert evidence["matched_rule"]["attacker_role"] == "ANONYMOUS"
    assert evidence["matched_rule"]["victim_role"] == "OWNER"
    assert evidence["matched_rule"]["identity_boundary"] == {
        "boundary_kind": "cross_role",
        "same_boundary": False,
        "compared_fields": ["x-user-role"],
        "changed_fields": ["x-user-role"],
        "unchanged_fields": [],
        "inferred_from_identity_matrix": True,
    }
    assert evidence["replay_request"]["headers"] == {"Accept": "application/json"}
    evidence_blob = str(evidence)
    assert verify_vulnerability_evidence(evidence)["verified"] is True
    assert "victim-token" not in evidence_blob
    assert "victim-api-key" not in evidence_blob
    assert "victim@example.com" not in evidence_blob


def test_infer_victim_account_matches_captured_auth_header():
    victim = _account("victim", "ADMIN", "victim-token")
    attacker = _account("attacker", "MEMBER", "attacker-token")

    matched = infer_victim_account(
        [attacker, victim],
        {"headers": {"Authorization": "Bearer victim-token"}},
    )

    assert matched is victim


def test_evaluate_authorization_replay_requires_similarity_by_default():
    original = {"status_code": 200, "body": {"id": 42, "email": "victim@example.com"}}
    attacker = {"status_code": 200, "body": '{"message":"different"}'}

    assessment = evaluate_authorization_replay(original, attacker)

    assert assessment["access_granted"] is True
    assert assessment["is_vulnerable"] is False
    assert assessment["confidence"] == "LOW"


def test_evaluate_authorization_replay_flags_matching_successful_replay():
    original = {"status_code": 200, "body": {"id": 42, "email": "victim@example.com"}}
    attacker = {"status_code": 200, "body": '{"id":42,"email":"victim@example.com"}'}

    assessment = evaluate_authorization_replay(original, attacker)

    assert assessment["is_vulnerable"] is True
    assert assessment["response_similar"] is True
    assert assessment["confidence"] == "HIGH"


def test_classify_authorization_issue_distinguishes_cross_role_bfla():
    victim = _account("victim", "ADMIN", "victim-token")
    attacker = _account("attacker", "MEMBER", "attacker-token")
    same_role_peer = _account("same-role-peer", "MEMBER", "peer-token")
    assessment = {"is_vulnerable": True}

    assert classify_authorization_issue(victim=victim, attacker=attacker, assessment=assessment) == "BFLA"
    assert classify_authorization_issue(victim=same_role_peer, attacker=attacker, assessment=assessment) == "BOLA"
    assert classify_authorization_issue(victim=attacker, attacker=attacker, assessment=assessment) is None


def test_classify_authorization_issue_uses_cross_tenant_boundary_as_bola():
    victim = _account("victim", "MEMBER", "victim-token")
    attacker = _account("attacker", "MEMBER", "attacker-token")
    assessment = {"is_vulnerable": True}
    original_request = {
        "headers": {
            "Authorization": "Bearer victim-token",
            "X-Tenant-ID": "tenant-a",
        },
    }
    replay_request = {
        "headers": {
            "Authorization": "Bearer attacker-token",
            "X-Tenant-ID": "tenant-b",
        },
    }

    assert (
        classify_authorization_issue(
            victim=victim,
            attacker=attacker,
            assessment=assessment,
            original_request=original_request,
            replay_request=replay_request,
        )
        == "BOLA"
    )


def test_classify_authorization_issue_uses_scope_boundary_as_bfla():
    victim = _account("victim", "MEMBER", "victim-token")
    attacker = _account("attacker", "MEMBER", "attacker-token")
    assessment = {"is_vulnerable": True}
    original_request = {
        "headers": {
            "Authorization": "Bearer victim-token",
            "X-Scopes": "orders:read orders:refund",
        },
    }
    replay_request = {
        "headers": {
            "Authorization": "Bearer attacker-token",
            "X-Scopes": "orders:read",
        },
    }

    assert (
        classify_authorization_issue(
            victim=victim,
            attacker=attacker,
            assessment=assessment,
            original_request=original_request,
            replay_request=replay_request,
        )
        == "BFLA"
    )


def test_classify_authorization_issue_ignores_secret_fragments_in_role_metadata():
    victim = _account("victim", "MEMBER token=victim-role-token", "victim-token")
    attacker = _account("attacker", "MEMBER token=attacker-role-token", "attacker-token")
    admin = _account("admin", "ADMIN token=admin-role-token", "admin-token")
    assessment = {"is_vulnerable": True}

    assert classify_authorization_issue(victim=victim, attacker=attacker, assessment=assessment) == "BOLA"
    assert classify_authorization_issue(victim=admin, attacker=attacker, assessment=assessment) == "BFLA"


def test_authorization_replay_evidence_is_redacted_hashed_and_body_minimized():
    victim = _account("victim", "ADMIN", "victim-token")
    attacker = _account("attacker", "MEMBER", "attacker-token")
    original_request = {
        "method": "GET",
        "url": "https://api.example.com/users/42?token=victim-token",
        "headers": {"Authorization": "Bearer victim-token"},
    }
    replay_request = {
        "method": "GET",
        "url": "https://api.example.com/users/42?token=victim-token",
        "headers": {"Authorization": "Bearer attacker-token"},
    }
    original_response = {"status_code": 200, "body": {"id": 42, "email": "victim@example.com"}}
    attacker_response = {"status_code": 200, "body": '{"id":42,"email":"victim@example.com"}'}
    assessment = evaluate_authorization_replay(original_response, attacker_response)

    first = build_authorization_replay_evidence(
        endpoint_id="endpoint-1",
        issue_type="BFLA",
        victim=victim,
        attacker=attacker,
        original_request=original_request,
        original_response=original_response,
        replay_request=replay_request,
        attacker_response=attacker_response,
        assessment=assessment,
    )
    second = build_authorization_replay_evidence(
        endpoint_id="endpoint-1",
        issue_type="BFLA",
        victim=victim,
        attacker=attacker,
        original_request=original_request,
        original_response=original_response,
        replay_request=replay_request,
        attacker_response=attacker_response,
        assessment=assessment,
    )
    blob = str(first)

    assert first["evidence_hash"] == second["evidence_hash"]
    assert verify_vulnerability_evidence(first)["verified"] is True
    assert first["scope_validation"] == {
        "validated": True,
        "policy": "target_guard",
        "scope": "same_origin_or_allowlisted",
        "target": "https://api.example.com/users/42?token=****",
        "evidence_url": "https://api.example.com/users/42?token=****",
    }
    assert first["captured_response"]["body_sha256"]
    assert first["replay_response"]["body_sha256"]
    assert first["finding_status"] == "CONFIRMED"
    assert first["matched_rule"] == {
        "rule_id": "authorization_replay_successful_cross_identity",
        "issue_type": "BFLA",
        "victim_role": "ADMIN",
        "attacker_role": "MEMBER",
        "identity_boundary": {
            "boundary_kind": "cross_role",
            "same_boundary": False,
            "compared_fields": ["x-user-role"],
            "changed_fields": ["x-user-role"],
            "unchanged_fields": [],
            "inferred_from_identity_matrix": True,
        },
    }
    assert first["authorization_boundary_coverage"] == {
        "complete": True,
        "field_names_only": True,
        "value_material_retained": False,
        "primary_boundary_kind": "cross_role",
        "boundary_kinds": ["cross_role"],
        "compared_field_count": 1,
        "changed_field_count": 1,
        "unchanged_field_count": 0,
        "compared_fields": ["x-user-role"],
        "changed_fields": ["x-user-role"],
        "unchanged_fields": [],
    }
    assert first["similarity"] == {
        "similarity_pct": 100.0,
        "schema_match_pct": 100.0,
        "body_similarity_threshold": 70.0,
        "schema_similarity_threshold": 70.0,
    }
    assert first["evidence_reproducibility"] == {
        "redaction_policy": "api_sentinel_redactor",
        "raw_payload_persisted": False,
        "deterministic_hash": True,
        "hash_algorithm": "sha256",
        "reproduction_available": True,
        "scope_validated": True,
        "evidence_complete": True,
    }
    assert "authorization" in first["remediation"].lower()
    assert first["evidence_completeness"]["complete"] is True
    assert first["evidence_completeness"]["missing"] == []
    assert "matched_rule" in first["evidence_completeness"]["present"]
    assert "similarity" in first["evidence_completeness"]["present"]
    assert first["retest_support"] == {
        "supported": True,
        "queued_scan_supported": True,
        "manual_outcome_supported": True,
        "reason": "authorization_replay_matrix_available",
        "missing_fields": [],
    }
    assert first["safety_policies"]["target_guard_policy"] == {
        "policy": "target_guard",
        "blocked": False,
        "url": "https://api.example.com/users/42?token=****",
        "base_url": "https://api.example.com/users/42?token=****",
        "scope": "same_origin_or_allowlisted",
    }
    assert first["safety_policies"]["state_change_policy"] == {
        "policy": "state_change_guard",
        "method": "GET",
        "destructive_method": False,
        "allow_state_change": False,
        "allow_destructive_methods": False,
    }
    assert "body" not in first["captured_response"]
    assert "body" not in first["replay_response"]
    assert "curl -i -X GET" in first["reproduction"]["curl"]
    assert "victim-token" not in blob
    assert "attacker-token" not in blob
    assert "victim@example.com" not in blob


def test_authorization_replay_evidence_includes_redacted_response_diff_summary():
    victim = _account("victim", "MEMBER", "victim-token")
    attacker = _account("attacker", "MEMBER", "attacker-token")
    attacker.auth_headers["X-Tenant-ID"] = "tenant-attacker-secret"
    original_request = {
        "method": "GET",
        "url": "https://api.example.com/orders/order-secret-001",
        "headers": {
            "Authorization": "Bearer victim-token",
            "X-Tenant-ID": "tenant-victim-secret",
        },
    }
    replay_request = {
        "method": "GET",
        "url": "https://api.example.com/orders/order-secret-001",
        "headers": {
            "Authorization": "Bearer attacker-token",
            "X-Tenant-ID": "tenant-attacker-secret",
        },
    }
    original_response = {
        "status_code": 200,
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "trace-victim-secret",
        },
        "body": {
            "id": "order-secret-001",
            "tenant_id": "tenant-victim-secret",
            "owner_id": "user-victim-secret",
            "email": "victim@example.com",
            "api_key": "sk_live_victim_secret",
            "profile": {"user_id": "user-victim-secret"},
        },
    }
    attacker_response = {
        "status_code": 200,
        "headers": {
            "Content-Type": "application/json",
            "X-Request-ID": "trace-attacker-secret",
        },
        "body": {
            "id": "order-secret-001",
            "tenant_id": "tenant-victim-secret",
            "owner_id": "user-victim-secret",
            "email": "victim@example.com",
            "api_key": "sk_live_victim_secret",
            "profile": {"user_id": "user-victim-secret"},
        },
    }
    assessment = evaluate_authorization_replay(original_response, attacker_response)

    evidence = build_authorization_replay_evidence(
        endpoint_id="endpoint-response-diff",
        issue_type="BOLA",
        victim=victim,
        attacker=attacker,
        original_request=original_request,
        original_response=original_response,
        replay_request=replay_request,
        attacker_response=attacker_response,
        assessment=assessment,
    )

    diff = evidence["response_diff"]
    assert diff["status"] == {
        "captured_status_code": 200,
        "replay_status_code": 200,
        "changed": False,
        "both_successful": True,
    }
    assert diff["headers"] == {
        "captured_only": [],
        "replay_only": [],
        "common_fields": ["content-type", "x-request-id"],
        "changed_fields": ["x-request-id"],
        "changed": True,
        "value_material_retained": False,
    }
    assert diff["body_schema"]["schema_match_pct"] == 100.0
    assert diff["body_schema"]["common_fields"] == [
        "api_key",
        "email",
        "id",
        "owner_id",
        "profile.user_id",
        "tenant_id",
    ]
    assert diff["object_ownership"] == {
        "observed": True,
        "field_names": ["id", "owner_id", "profile.user_id", "tenant_id"],
        "field_count": 4,
        "value_material_retained": False,
    }
    assert diff["sensitive_fields"] == {
        "observed": True,
        "field_names": ["api_key", "email"],
        "field_count": 2,
        "value_material_retained": False,
    }
    assert diff["identity_boundary"] == {
        "boundary_kinds": ["cross_tenant"],
        "boundary_labels": ["cross_tenant:x-tenant-id"],
        "changed_fields": ["x-tenant-id"],
        "value_material_retained": False,
    }
    assert verify_vulnerability_evidence(evidence)["verified"] is True
    evidence_blob = str(evidence)
    for raw_value in [
        "tenant-victim-secret",
        "tenant-attacker-secret",
        "user-victim-secret",
        "victim-token",
        "attacker-token",
        "victim@example.com",
        "sk_live_victim_secret",
        "trace-victim-secret",
        "trace-attacker-secret",
    ]:
        assert raw_value not in evidence_blob


def test_authorization_replay_evidence_records_request_object_reference_surface_without_values():
    victim = _account("victim", "MEMBER", "victim-token")
    attacker = _account("attacker", "MEMBER", "attacker-token")
    original_request = {
        "method": "POST",
        "url": "https://api.example.com/tenants/tenant-secret/orders/order-secret-001?customer_id=customer-secret",
        "headers": {
            "Authorization": "Bearer victim-token",
            "X-Workspace-ID": "workspace-victim-secret",
        },
        "body": {
            "order_id": "order-secret-001",
            "owner": {"user_id": "user-victim-secret"},
            "note": "Authorization: Bearer victim-token",
        },
    }
    replay_request = {
        "method": "POST",
        "url": "https://api.example.com/tenants/tenant-secret/orders/order-secret-001?customer_id=customer-secret",
        "headers": {
            "Authorization": "Bearer attacker-token",
            "X-Workspace-ID": "workspace-attacker-secret",
        },
        "body": {
            "order_id": "order-secret-001",
            "owner": {"user_id": "user-victim-secret"},
            "note": "Authorization: Bearer victim-token",
        },
    }
    original_response = {"status_code": 200, "body": {"id": "order-secret-001"}}
    attacker_response = {"status_code": 200, "body": {"id": "order-secret-001"}}
    assessment = evaluate_authorization_replay(original_response, attacker_response)

    evidence = build_authorization_replay_evidence(
        endpoint_id="endpoint-object-reference-surface",
        issue_type="BOLA",
        victim=victim,
        attacker=attacker,
        original_request=original_request,
        original_response=original_response,
        replay_request=replay_request,
        attacker_response=attacker_response,
        assessment=assessment,
    )

    references = evidence["request_object_reference"]

    assert references["observed"] is True
    assert references["field_names_only"] is True
    assert references["value_material_retained"] is False
    assert references["location_counts"] == {
        "body": 3,
        "header": 1,
        "path": 4,
        "query": 1,
    }
    assert references["references"] == [
        {"location": "body", "name": "order_id", "value_sha256": references["references"][0]["value_sha256"]},
        {"location": "body", "name": "owner", "value_sha256": references["references"][1]["value_sha256"]},
        {"location": "body", "name": "owner.user_id", "value_sha256": references["references"][2]["value_sha256"]},
        {"location": "header", "name": "x-workspace-id", "value_sha256": references["references"][3]["value_sha256"]},
        {"location": "path", "name": "segment[1]", "value_sha256": references["references"][4]["value_sha256"]},
        {"location": "path", "name": "segment[2]", "value_sha256": references["references"][5]["value_sha256"]},
        {"location": "path", "name": "segment[3]", "value_sha256": references["references"][6]["value_sha256"]},
        {"location": "path", "name": "segment[4]", "value_sha256": references["references"][7]["value_sha256"]},
        {"location": "query", "name": "customer_id", "value_sha256": references["references"][8]["value_sha256"]},
    ]
    assert all(len(item["value_sha256"]) == 64 for item in references["references"])
    assert references["reference_count"] == 9
    assert references["reference_report_truncated"] is False
    assert verify_vulnerability_evidence(evidence)["verified"] is True
    evidence_blob = str(evidence)
    for raw_value in [
        "tenant-secret",
        "order-secret-001",
        "customer-secret",
        "workspace-victim-secret",
        "workspace-attacker-secret",
        "user-victim-secret",
        "victim-token",
        "attacker-token",
    ]:
        assert raw_value not in evidence_blob


def test_authorization_replay_evidence_redacts_identity_display_metadata():
    victim = _account("victim", "ADMIN token=victim-role-token", "victim-token")
    victim.name = "Admin Victim token=victim-name-token"
    attacker = _account("attacker", "MEMBER token=attacker-role-token", "attacker-token")
    attacker.name = "Member Attacker cookie=attacker-name-token"
    original_request = {
        "method": "GET",
        "url": "https://api.example.com/users/42",
        "headers": {"Authorization": "Bearer victim-token"},
    }
    replay_request = {
        "method": "GET",
        "url": "https://api.example.com/users/42",
        "headers": {"Authorization": "Bearer attacker-token"},
    }
    original_response = {"status_code": 200, "body": {"id": 42}}
    attacker_response = {"status_code": 200, "body": '{"id":42}'}
    assessment = evaluate_authorization_replay(original_response, attacker_response)

    evidence = build_authorization_replay_evidence(
        endpoint_id="endpoint-1",
        issue_type="BFLA",
        victim=victim,
        attacker=attacker,
        original_request=original_request,
        original_response=original_response,
        replay_request=replay_request,
        attacker_response=attacker_response,
        assessment=assessment,
    )

    assert evidence["identity_pair"]["victim"] == {
        "id": "victim",
        "role": "ADMIN token=****",
        "name": "Admin Victim token=****",
    }
    assert evidence["identity_pair"]["attacker"] == {
        "id": "attacker",
        "role": "MEMBER token=****",
        "name": "Member Attacker cookie=****",
    }
    assert verify_vulnerability_evidence(evidence)["verified"] is True
    evidence_blob = str(evidence)
    assert "victim-role-token" not in evidence_blob
    assert "victim-name-token" not in evidence_blob
    assert "attacker-role-token" not in evidence_blob
    assert "attacker-name-token" not in evidence_blob


def test_authorization_replay_evidence_records_cross_tenant_boundary_without_values():
    victim = _account("victim", "MEMBER", "victim-token")
    attacker = _account("attacker", "MEMBER", "attacker-token")
    attacker.auth_headers["X-Tenant-ID"] = "tenant-b"
    original_request = {
        "method": "GET",
        "url": "https://api.example.com/orders/42",
        "headers": {
            "Authorization": "Bearer victim-token",
            "X-Tenant-ID": "tenant-a",
        },
    }
    replay_request = {
        "method": "GET",
        "url": "https://api.example.com/orders/42",
        "headers": {
            "Authorization": "Bearer attacker-token",
            "X-Tenant-ID": "tenant-b",
        },
    }
    original_response = {"status_code": 200, "body": {"id": 42, "tenant": "tenant-a"}}
    attacker_response = {"status_code": 200, "body": '{"id":42,"tenant":"tenant-a"}'}
    assessment = evaluate_authorization_replay(original_response, attacker_response)

    assert classify_authorization_issue(victim=victim, attacker=attacker, assessment=assessment) == "BOLA"

    evidence = build_authorization_replay_evidence(
        endpoint_id="endpoint-tenant",
        issue_type="BOLA",
        victim=victim,
        attacker=attacker,
        original_request=original_request,
        original_response=original_response,
        replay_request=replay_request,
        attacker_response=attacker_response,
        assessment=assessment,
    )

    boundary = evidence["matched_rule"]["identity_boundary"]
    evidence_blob = str(evidence)
    assert boundary == {
        "boundary_kind": "cross_tenant",
        "same_boundary": False,
        "compared_fields": ["x-tenant-id"],
        "changed_fields": ["x-tenant-id"],
        "unchanged_fields": [],
    }
    assert verify_vulnerability_evidence(evidence)["verified"] is True
    assert "tenant-a" not in evidence_blob
    assert "tenant-b" not in evidence_blob
    assert "victim-token" not in evidence_blob
    assert "attacker-token" not in evidence_blob


def test_authorization_replay_evidence_records_cross_principal_bola_boundary_without_values():
    victim = _account("victim-user", "MEMBER", "victim-token")
    attacker = _account("attacker-user", "MEMBER", "attacker-token")
    original_request = {
        "method": "GET",
        "url": "https://api.example.com/orders/42?token=victim-token",
        "headers": {
            "Authorization": "Bearer victim-token",
        },
    }
    replay_request = {
        "method": "GET",
        "url": "https://api.example.com/orders/42?token=victim-token",
        "headers": {
            "Authorization": "Bearer attacker-token",
        },
    }
    original_response = {
        "status_code": 200,
        "body": {"id": 42, "owner_id": "victim-user"},
    }
    attacker_response = {
        "status_code": 200,
        "body": '{"id":42,"owner_id":"victim-user"}',
    }
    assessment = evaluate_authorization_replay(original_response, attacker_response)
    issue_type = classify_authorization_issue(
        victim=victim,
        attacker=attacker,
        assessment=assessment,
        original_request=original_request,
        replay_request=replay_request,
    )

    evidence = build_authorization_replay_evidence(
        endpoint_id="endpoint-cross-principal",
        issue_type=issue_type,
        victim=victim,
        attacker=attacker,
        original_request=original_request,
        original_response=original_response,
        replay_request=replay_request,
        attacker_response=attacker_response,
        assessment=assessment,
    )

    assert issue_type == "BOLA"
    assert evidence["matched_rule"]["identity_boundary"] == {
        "boundary_kind": "identity_boundary_changed",
        "same_boundary": False,
        "compared_fields": ["x-principal-id"],
        "changed_fields": ["x-principal-id"],
        "unchanged_fields": [],
        "inferred_from_identity_matrix": True,
    }
    assert evidence["authorization_boundary_coverage"] == {
        "complete": True,
        "field_names_only": True,
        "value_material_retained": False,
        "primary_boundary_kind": "identity_boundary_changed",
        "boundary_kinds": ["identity_boundary_changed"],
        "compared_field_count": 1,
        "changed_field_count": 1,
        "unchanged_field_count": 0,
        "compared_fields": ["x-principal-id"],
        "changed_fields": ["x-principal-id"],
        "unchanged_fields": [],
    }
    assert evidence["authorization_issue_classification"] == {
        "primary_issue_type": "BOLA",
        "issue_types": ["BOLA"],
        "boundary_kinds": ["identity_boundary_changed"],
        "boundary_field_count": 1,
        "classification_reason": "cross_identity_replay_with_object_boundary",
        "value_material_retained": False,
    }
    assert verify_vulnerability_evidence(evidence)["verified"] is True
    evidence_blob = str(evidence)
    assert "victim-token" not in evidence_blob
    assert "attacker-token" not in evidence_blob


def test_authorization_replay_evidence_records_cross_role_boundary_without_values():
    victim = _account("victim", "ADMIN", "victim-token")
    attacker = _account("attacker", "MEMBER", "attacker-token")
    attacker.auth_headers["X-User-Role"] = "finance-readonly-beta"
    original_request = {
        "method": "GET",
        "url": "https://api.example.com/admin/orders/42",
        "headers": {
            "Authorization": "Bearer victim-token",
            "X-User-Role": "finance-admin-alpha",
        },
    }
    replay_request = {
        "method": "GET",
        "url": "https://api.example.com/admin/orders/42",
        "headers": {
            "Authorization": "Bearer attacker-token",
            "X-User-Role": "finance-readonly-beta",
        },
    }
    original_response = {"status_code": 200, "body": {"id": 42, "status": "refunded"}}
    attacker_response = {"status_code": 200, "body": '{"id":42,"status":"refunded"}'}
    assessment = evaluate_authorization_replay(original_response, attacker_response)

    evidence = build_authorization_replay_evidence(
        endpoint_id="endpoint-role",
        issue_type="BFLA",
        victim=victim,
        attacker=attacker,
        original_request=original_request,
        original_response=original_response,
        replay_request=replay_request,
        attacker_response=attacker_response,
        assessment=assessment,
    )

    boundary = evidence["matched_rule"]["identity_boundary"]
    evidence_blob = str(evidence)
    assert boundary == {
        "boundary_kind": "cross_role",
        "same_boundary": False,
        "compared_fields": ["x-user-role"],
        "changed_fields": ["x-user-role"],
        "unchanged_fields": [],
    }
    assert evidence["captured_request"]["headers"]["X-User-Role"] == "****"
    assert evidence["replay_request"]["headers"]["X-User-Role"] == "****"
    assert verify_vulnerability_evidence(evidence)["verified"] is True
    assert "finance-admin-alpha" not in evidence_blob
    assert "finance-readonly-beta" not in evidence_blob


def test_authorization_replay_evidence_reports_boundary_coverage_without_values():
    victim = _account("victim", "ADMIN", "victim-token")
    attacker = _account("attacker", "MEMBER", "attacker-token")
    attacker.auth_headers["X-Tenant-ID"] = "tenant-b"
    attacker.auth_headers["X-User-Role"] = "finance-readonly-beta"
    attacker.auth_headers["X-Scopes"] = "orders:read"
    original_request = {
        "method": "GET",
        "url": "https://api.example.com/admin/orders/42",
        "headers": {
            "Authorization": "Bearer victim-token",
            "X-Tenant-ID": "tenant-a",
            "X-User-Role": "finance-admin-alpha",
            "X-Scopes": "orders:read orders:refund",
        },
    }
    replay_request = {
        "method": "GET",
        "url": "https://api.example.com/admin/orders/42",
        "headers": {
            "Authorization": "Bearer attacker-token",
            "X-Tenant-ID": "tenant-b",
            "X-User-Role": "finance-readonly-beta",
            "X-Scopes": "orders:read",
        },
    }
    original_response = {"status_code": 200, "body": {"id": 42, "status": "refunded"}}
    attacker_response = {"status_code": 200, "body": '{"id":42,"status":"refunded"}'}
    assessment = evaluate_authorization_replay(original_response, attacker_response)

    evidence = build_authorization_replay_evidence(
        endpoint_id="endpoint-multi-boundary",
        issue_type="BFLA",
        victim=victim,
        attacker=attacker,
        original_request=original_request,
        original_response=original_response,
        replay_request=replay_request,
        attacker_response=attacker_response,
        assessment=assessment,
    )

    assert evidence["authorization_boundary_coverage"] == {
        "complete": True,
        "field_names_only": True,
        "value_material_retained": False,
        "primary_boundary_kind": "cross_tenant",
        "boundary_kinds": ["cross_tenant", "cross_role", "cross_scope"],
        "compared_field_count": 3,
        "changed_field_count": 3,
        "unchanged_field_count": 0,
        "compared_fields": ["x-tenant-id", "x-user-role", "x-scopes"],
        "changed_fields": ["x-tenant-id", "x-user-role", "x-scopes"],
        "unchanged_fields": [],
    }
    assert verify_vulnerability_evidence(evidence)["verified"] is True
    evidence_blob = str(evidence)
    assert "tenant-a" not in evidence_blob
    assert "tenant-b" not in evidence_blob
    assert "finance-admin-alpha" not in evidence_blob
    assert "finance-readonly-beta" not in evidence_blob
    assert "orders:refund" not in evidence_blob


def test_authorization_replay_evidence_reports_multi_boundary_issue_classification_without_values():
    victim = _account("victim", "ADMIN", "victim-token")
    attacker = _account("attacker", "MEMBER", "attacker-token")
    attacker.auth_headers["X-Tenant-ID"] = "tenant-b"
    attacker.auth_headers["X-Scopes"] = "orders:read"
    original_request = {
        "method": "GET",
        "url": "https://api.example.com/admin/orders/42",
        "headers": {
            "Authorization": "Bearer victim-token",
            "X-Tenant-ID": "tenant-a",
            "X-Scopes": "orders:read orders:refund",
        },
    }
    replay_request = {
        "method": "GET",
        "url": "https://api.example.com/admin/orders/42",
        "headers": {
            "Authorization": "Bearer attacker-token",
            "X-Tenant-ID": "tenant-b",
            "X-Scopes": "orders:read",
        },
    }
    original_response = {"status_code": 200, "body": {"id": 42, "status": "refunded"}}
    attacker_response = {"status_code": 200, "body": '{"id":42,"status":"refunded"}'}
    assessment = evaluate_authorization_replay(original_response, attacker_response)
    issue_type = classify_authorization_issue(
        victim=victim,
        attacker=attacker,
        assessment=assessment,
        original_request=original_request,
        replay_request=replay_request,
    )

    evidence = build_authorization_replay_evidence(
        endpoint_id="endpoint-multi-classification",
        issue_type=issue_type,
        victim=victim,
        attacker=attacker,
        original_request=original_request,
        original_response=original_response,
        replay_request=replay_request,
        attacker_response=attacker_response,
        assessment=assessment,
    )

    assert evidence["authorization_issue_classification"] == {
        "primary_issue_type": "BFLA",
        "issue_types": ["BOLA", "BFLA"],
        "boundary_kinds": ["cross_tenant", "cross_role", "cross_scope"],
        "boundary_field_count": 2,
        "classification_reason": "cross_identity_replay_with_object_and_function_boundaries",
        "value_material_retained": False,
    }
    assert verify_vulnerability_evidence(evidence)["verified"] is True
    evidence_blob = str(evidence)
    assert "tenant-a" not in evidence_blob
    assert "tenant-b" not in evidence_blob
    assert "orders:refund" not in evidence_blob
    assert "victim-token" not in evidence_blob
    assert "attacker-token" not in evidence_blob


def test_authorization_replay_evidence_hash_ignores_response_timing_metadata():
    victim = _account("victim", "ADMIN", "victim-token")
    attacker = _account("attacker", "MEMBER", "attacker-token")
    original_request = {
        "method": "GET",
        "url": "https://api.example.com/users/42?session=victim-session",
        "headers": {"Authorization": "Bearer victim-token"},
    }
    replay_request = {
        "method": "GET",
        "url": "https://api.example.com/users/42?session=victim-session",
        "headers": {"Authorization": "Bearer attacker-token"},
    }
    original_response = {"status_code": 200, "body": {"id": 42}}
    first_replay_response = {"status_code": 200, "body": '{"id":42}', "duration_ms": 15}
    second_replay_response = {"status_code": 200, "body": '{"id":42}', "duration_ms": 937}
    assessment = evaluate_authorization_replay(original_response, first_replay_response)

    first = build_authorization_replay_evidence(
        endpoint_id="endpoint-1",
        issue_type="BOLA",
        victim=victim,
        attacker=attacker,
        original_request=original_request,
        original_response=original_response,
        replay_request=replay_request,
        attacker_response=first_replay_response,
        assessment=assessment,
    )
    second = build_authorization_replay_evidence(
        endpoint_id="endpoint-1",
        issue_type="BOLA",
        victim=victim,
        attacker=attacker,
        original_request=original_request,
        original_response=original_response,
        replay_request=replay_request,
        attacker_response=second_replay_response,
        assessment=assessment,
    )

    assert first["evidence_hash"] == second["evidence_hash"]
    assert first["observation_metadata"]["replay_response_duration_ms"] == 15
    assert second["observation_metadata"]["replay_response_duration_ms"] == 937
    assert "duration_ms" not in first["replay_response"]
    assert first["scope_validation"]["validated"] is True
    assert verify_vulnerability_evidence(first)["verified"] is True
    assert verify_vulnerability_evidence(second)["verified"] is True
    assert "victim-session" not in str(first)
