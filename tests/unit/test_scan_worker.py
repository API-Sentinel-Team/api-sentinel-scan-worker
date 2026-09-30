import asyncio
import datetime
import sys
import types

import pytest
import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
import pytest_asyncio
from unittest.mock import AsyncMock

from sentinel_core.config import settings
from sentinel_core.models import Base
from sentinel_core.models import core as models
from sentinel_core.modules.test_executor.evidence import evidence_digest
from sentinel_core.modules.pentest.execution_artifacts import verify_execution_artifact_payload
from sentinel_core.modules.test_executor.scan_plan import build_readable_scan_plan
from sentinel_worker.modules.test_executor.scan_worker import (
    claim_next_pending_run,
    heartbeat_claimed_run,
    normalize_worker_id,
    run_pending_scan_once,
    run_worker_loop,
)
from sentinel_core.modules.test_executor.scan_queue import worker_queue_health
from sentinel_core.modules.vulnerability_detector.lifecycle import (
    isoformat,
    retest_outcome_digest,
    verify_vulnerability_evidence,
)


@pytest.mark.asyncio
async def test_external_dispatch_rejects_unhashed_plan_before_loading_targets(monkeypatch):
    from sentinel_worker.modules.test_executor import scan_worker as worker
    claimed = worker.ClaimedScanRun(
        run_id="untrusted", account_id=7, endpoint_ids=[], template_ids=[],
        scan_plan={"engine_plan": [{"engine": "zap", "status": "ready"}]},
    )
    with pytest.raises(ValueError, match="integrity"):
        await worker._execute_planned_external_engines(
            claimed, db_bind=None, worker_isolation_context=None,
        )


def test_worker_spec_is_limited_to_selected_methods_and_rejects_remote_refs():
    from sentinel_core.modules.test_executor.scan_queue import scoped_worker_spec
    endpoint = types.SimpleNamespace(host="api.example.test", protocol="https", path="/users", method="GET")
    spec = {"openapi": "3.0.0", "paths": {
        "/users": {"get": {"responses": {}}, "delete": {"responses": {}}},
        "/admin": {"get": {"responses": {}}},
    }, "servers": [{"url": "https://elsewhere.test"}]}
    scoped = scoped_worker_spec(spec, [endpoint], "https://api.example.test")
    assert set(scoped["paths"]) == {"/users"}
    assert set(scoped["paths"]["/users"]) == {"get"}
    assert scoped["servers"] == [{"url": "https://api.example.test"}]
    assert "/admin" in spec["paths"]
    spec["components"] = {"schemas": {"User": {"$ref": "https://elsewhere.test/user.json"}}}
    with pytest.raises(ValueError, match="reference_blocked"):
        scoped_worker_spec(spec, [endpoint], "https://api.example.test")


@pytest.mark.asyncio
async def test_worker_external_failure_stops_primary_phase(test_engine, monkeypatch):
    from sentinel_worker.modules.test_executor import scan_worker as worker
    from sentinel_worker.modules.test_executor import run_executor
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(account_id=710, status="PENDING", template_ids=["t"], endpoint_ids=["e"])
        db.add(run)
        await db.commit()
        run_id = run.id
    primary = AsyncMock()
    monkeypatch.setattr(run_executor, "run_security_tasks", primary)
    monkeypatch.setattr(worker, "_execute_planned_external_engines", AsyncMock(return_value={"status": "failed"}))
    result = await worker.run_pending_scan_once(db_bind=test_engine, account_id=710)
    assert result["status"] == "failed"
    primary.assert_not_awaited()
    async with session_factory() as db:
        stored = await db.get(models.TestRun, run_id)
        assert stored.status == "FAILED"


@pytest.mark.asyncio
async def test_bound_external_scan_persists_verified_artifact(test_engine, monkeypatch):
    from sentinel_worker.modules.test_executor import scan_worker as worker
    from sentinel_core.modules.test_executor.scan_plan import finalize_scan_plan_hash
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        auth = models.AuthProfile(account_id=712, name="test", auth_mode="bearer", token="test-worker-token", scope_domains=["api.example.test"])
        endpoint = models.APIEndpoint(account_id=712, protocol="https", host="api.example.test", path="/users", method="GET")
        spec = models.OpenAPISpec(account_id=712, spec_json={"openapi": "3.0.0", "paths": {"/users": {"get": {"responses": {"200": {"description": "ok"}}}}}})
        db.add_all([auth, endpoint, spec])
        await db.flush()
        profile = models.PentestProfile(account_id=712, name="test", auth_profile_id=auth.id, schemathesis_enabled=True)
        db.add(profile)
        await db.flush()
        plan = finalize_scan_plan_hash({
            "engine_plan": [{"engine": "schemathesis", "status": "ready"}],
            "external_engine_scope": {"target_url": "https://api.example.test", "openapi_spec_id": spec.id, "openapi_spec_sha256": worker.worker_spec_digest(spec.spec_json)},
        })
        run = models.TestRun(account_id=712, status="PENDING", template_ids=["t"], endpoint_ids=[endpoint.id], pentest_profile_id=profile.id, scan_plan=plan)
        db.add(run)
        await db.commit()
    fake_scan = AsyncMock(return_value={"status": "COMPLETED", "junit_xml": '<testsuites><testsuite tests="1"/></testsuites>', "failures": 0})
    monkeypatch.setattr(worker.SchemathesisRunner, "run_scan", fake_scan)
    claimed = await worker.claim_next_pending_run(db_bind=test_engine, account_id=712, worker_id="bound-worker")
    result = await worker._execute_planned_external_engines(claimed, db_bind=test_engine, worker_isolation_context=None)
    assert result["status"] == "completed"
    assert result["engine_count"] == 1
    assert fake_scan.await_args.kwargs["auth_profile"].token == "test-worker-token"
    assert set(fake_scan.await_args.kwargs["openapi_spec"]["paths"]) == {"/users"}
    async with session_factory() as db:
        artifact = (await db.execute(select(models.PentestArtifact).where(models.PentestArtifact.run_id == claimed.run_id))).scalar_one()
        assert verify_execution_artifact_payload(artifact.content_json)["verified"] is True
        assert "test-worker-token" not in str(artifact.content_json)


@pytest.mark.asyncio
async def test_external_phase_runs_while_claim_is_dispatched(test_engine, monkeypatch):
    from sentinel_worker.modules.test_executor import scan_worker as worker
    from sentinel_worker.modules.test_executor import run_executor
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(account_id=711, status="PENDING", template_ids=["t"], endpoint_ids=["e"])
        db.add(run)
        await db.commit()
    phases = []
    async def external(claimed, **kwargs):
        async with session_factory() as db:
            stored = await db.get(models.TestRun, claimed.run_id)
            assert stored.status == "DISPATCHED"
            assert stored.dispatch_lease_expires_at is not None
        phases.append("external")
        return {"status": "completed", "engines": []}
    async def primary(*args, **kwargs):
        phases.append("primary")
        return {"status": "completed"}
    monkeypatch.setattr(worker, "_execute_planned_external_engines", external)
    monkeypatch.setattr(run_executor, "run_security_tasks", primary)
    await worker.run_pending_scan_once(db_bind=test_engine, account_id=711)
    assert phases == ["external", "primary"]


@pytest.mark.asyncio
async def test_external_findings_status_completes_phase(test_engine, monkeypatch):
    """Contract A: a non-zero exit with findings is the scanners' normal success path."""
    from sentinel_worker.modules.test_executor import scan_worker as worker
    from sentinel_core.modules.test_executor.scan_plan import finalize_scan_plan_hash
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        auth = models.AuthProfile(account_id=713, name="test", auth_mode="bearer", token="findings-token", scope_domains=["api.example.test"])
        endpoint = models.APIEndpoint(account_id=713, protocol="https", host="api.example.test", path="/users", method="GET")
        spec = models.OpenAPISpec(account_id=713, spec_json={"openapi": "3.0.0", "paths": {"/users": {"get": {"responses": {"200": {"description": "ok"}}}}}})
        db.add_all([auth, endpoint, spec])
        await db.flush()
        profile = models.PentestProfile(account_id=713, name="test", auth_profile_id=auth.id, schemathesis_enabled=True)
        db.add(profile)
        await db.flush()
        plan = finalize_scan_plan_hash({
            "engine_plan": [{"engine": "schemathesis", "status": "ready"}],
            "external_engine_scope": {"target_url": "https://api.example.test", "openapi_spec_id": spec.id, "openapi_spec_sha256": worker.worker_spec_digest(spec.spec_json)},
        })
        run = models.TestRun(account_id=713, status="PENDING", template_ids=["t"], endpoint_ids=[endpoint.id], pentest_profile_id=profile.id, scan_plan=plan)
        db.add(run)
        await db.commit()
    fake_scan = AsyncMock(return_value={"status": "FAILED_WITH_FINDINGS", "junit_xml": '<testsuites><testsuite tests="1" failures="1"/></testsuites>', "failures": 1})
    monkeypatch.setattr(worker.SchemathesisRunner, "run_scan", fake_scan)
    claimed = await worker.claim_next_pending_run(db_bind=test_engine, account_id=713, worker_id="findings-worker")
    result = await worker._execute_planned_external_engines(claimed, db_bind=test_engine, worker_isolation_context=None)
    assert result["status"] == "completed"
    assert result["engines"][0]["status"] == "FAILED_WITH_FINDINGS"


@pytest.mark.asyncio
async def test_queued_external_phase_honors_cancel_requested(test_engine, monkeypatch):
    """Contract C: an operator cancel terminates the in-flight engine within the wait window."""
    from sentinel_worker.modules.test_executor import scan_worker as worker
    monkeypatch.setattr(settings, "PENTEST_SCAN_DISPATCH_LEASE_SECONDS", 3)
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(account_id=714, status="PENDING", template_ids=["t"], endpoint_ids=["e"])
        db.add(run)
        await db.commit()
    claimed = await worker.claim_next_pending_run(db_bind=test_engine, account_id=714, worker_id="cancel-worker")
    assert claimed is not None
    started = asyncio.Event()

    async def blocked_external(*args, **kwargs):
        started.set()
        await asyncio.sleep(30)
        return {"status": "completed"}

    monkeypatch.setattr(worker, "_execute_planned_external_engines", blocked_external)
    monkeypatch.setattr(worker, "_claimed_run_cancel_requested", AsyncMock(return_value=True))
    with pytest.raises(worker.ScanCancelRequestedError):
        await worker._run_external_with_lease(claimed, db_bind=test_engine)


@pytest.mark.asyncio
async def test_run_pending_scan_once_finalizes_canceled_run(test_engine, monkeypatch):
    from sentinel_worker.modules.test_executor import scan_worker as worker
    from sentinel_worker.modules.test_executor import run_executor
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(account_id=715, status="PENDING", template_ids=["t"], endpoint_ids=["e"])
        db.add(run)
        await db.commit()
        run_id = run.id
    primary = AsyncMock()

    async def cancelled_external(*args, **kwargs):
        raise worker.ScanCancelRequestedError("cancel_requested")

    monkeypatch.setattr(worker, "_execute_planned_external_engines", cancelled_external)
    monkeypatch.setattr(run_executor, "run_security_tasks", primary)
    result = await worker.run_pending_scan_once(db_bind=test_engine, account_id=715, worker_id="cancel-finalize")
    primary.assert_not_awaited()
    assert result["status"] == "canceled"
    async with session_factory() as db:
        stored = await db.get(models.TestRun, run_id)
        assert stored.status == "CANCELED"
        assert stored.completed_at is not None
        assert stored.dispatch_lease_expires_at is None


@pytest.fixture(autouse=True)
def _allow_unauthenticated_active_scans_for_worker_unit_tests(monkeypatch):
    monkeypatch.setattr(settings, "PENTEST_REQUIRE_AUTH_PROFILE_FOR_ACTIVE_SCANS", False)


@pytest_asyncio.fixture
async def test_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.mark.asyncio
async def test_claim_next_pending_run_marks_it_dispatched(test_engine):
    account_id = 1000100
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=["template-1"],
            endpoint_ids=["endpoint-1"],
            pentest_profile_id="profile-1",
            trigger_source="vulnerability_retest",
            source_vulnerability_id="vuln-1",
            source_schedule_id="schedule-1",
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    claimed = await claim_next_pending_run(db_bind=test_engine, account_id=account_id, worker_id="worker-a")

    assert claimed is not None
    assert claimed.run_id == run_id
    assert claimed.template_ids == ["template-1"]
    assert claimed.endpoint_ids == ["endpoint-1"]
    assert claimed.account_id == account_id
    assert claimed.pentest_profile_id == "profile-1"
    assert claimed.trigger_source == "vulnerability_retest"
    assert claimed.source_vulnerability_id == "vuln-1"
    assert claimed.source_schedule_id == "schedule-1"
    assert claimed.worker_id == "worker-a"
    assert claimed.lease_expires_at is not None
    assert claimed.claim_count == 1

    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == run_id,
                    models.AuditLog.action == "SCAN_RUN_CLAIMED",
                )
            )
        ).scalar_one()
    assert stored.status == "DISPATCHED"
    assert stored.worker_id == "worker-a"
    assert stored.dispatch_lease_expires_at is not None
    assert stored.worker_heartbeat_at is not None
    assert stored.claim_count == 1
    assert audit.details["worker_id"] == "worker-a"
    assert audit.details["claim_count"] == 1
    assert audit.details["previous_status"] == "PENDING"
    assert audit.details["trigger_source"] == "vulnerability_retest"
    assert audit.details["source_vulnerability_id"] == "vuln-1"
    assert audit.details["source_schedule_id"] == "schedule-1"
    assert audit.details["template_count"] == 1
    assert audit.details["endpoint_count"] == 1
    assert audit.details["lease_expires_at"]


@pytest.mark.asyncio
async def test_claim_next_pending_run_audits_worker_governance_policy(test_engine, monkeypatch):
    account_id = 1000115
    monkeypatch.setattr(settings, "PENTEST_SCAN_DISPATCH_LEASE_SECONDS", 37)
    monkeypatch.setattr(settings, "PENTEST_SCAN_MAX_CLAIMS", 5)
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=["template-governance"],
            endpoint_ids=["endpoint-governance"],
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    claimed = await claim_next_pending_run(
        db_bind=test_engine,
        account_id=account_id,
        worker_id="worker-governance",
    )

    assert claimed is not None
    async with session_factory() as db:
        audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == run_id,
                    models.AuditLog.action == "SCAN_RUN_CLAIMED",
                )
            )
        ).scalar_one()

    assert audit.details["worker_governance"] == {
        "lease_seconds": 37,
        "max_claims": 5,
        "tenant_scoped": True,
        "kill_switch_enforced": True,
        "isolation_mode": "background",
        "per_run_worker_required": True,
        "kubernetes_job_ready": False,
        "kubernetes_namespace": "api-sentinel",
        "kubernetes_service_account": "api-sentinel-scan-worker",
        "resource_limits_required": True,
        "resource_limits": {
            "cpu": "1000m",
            "memory": "1Gi",
            "ephemeral_storage": "2Gi",
        },
    }


@pytest.mark.asyncio
async def test_claim_next_pending_run_audits_multi_engine_accountability(test_engine):
    account_id = 1000118
    engine_plan = [
        {"engine": "templates", "status": "ready", "reason": "requirements_satisfied"},
        {"engine": "schemathesis", "status": "ready", "reason": "requirements_satisfied"},
        {"engine": "nuclei", "status": "blocked", "reason": "missing_auth_profile token=raw-engine-token"},
        {"engine": "zap", "status": "ready", "reason": "requirements_satisfied"},
        {"engine": "passive", "status": "available", "reason": "continuous_ingestion_pipeline"},
    ]
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=["template-engine-accountability"],
            endpoint_ids=["endpoint-engine-accountability"],
            scan_plan={
                "schema_version": "scan_plan.v1",
                "test_intensity": "deep",
                "engine_plan": engine_plan,
            },
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    claimed = await claim_next_pending_run(
        db_bind=test_engine,
        account_id=account_id,
        worker_id="worker-engine-accountability",
    )

    assert claimed is not None
    accountability = claimed.engine_accountability
    assert accountability is not None
    assert accountability["isolation_model"] == "leased_external_worker"
    assert accountability["lease_required"] is True
    assert accountability["artifact_hash_required"] is True
    assert accountability["artifact_verification_required"] is True
    assert accountability["ready_active_engines"] == ["templates", "schemathesis", "zap"]
    assert accountability["claim_execution_engines"] == ["templates", "schemathesis", "zap"]
    assert accountability["blocked_engines"] == ["nuclei"]
    assert accountability["continuous_engines"] == ["passive"]

    required_artifacts = {item["engine"]: item for item in accountability["required_artifacts"]}
    assert set(required_artifacts) == {"templates", "schemathesis", "zap"}
    assert required_artifacts["templates"]["artifact_type"] == "templates_execution"
    assert all(item["hash_required"] is True for item in required_artifacts.values())
    assert all(item["verification_required"] is True for item in required_artifacts.values())
    planned_external_artifacts = {
        item["engine"]: item for item in accountability["planned_external_artifacts"]
    }
    assert planned_external_artifacts == {}
    assert "raw-engine-token" not in str(accountability)
    assert "token=****" in str(accountability)

    async with session_factory() as db:
        audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == run_id,
                    models.AuditLog.action == "SCAN_RUN_CLAIMED",
                )
            )
        ).scalar_one()

    assert audit.details["engine_accountability"] == accountability
    assert "raw-engine-token" not in str(audit.details)


@pytest.mark.asyncio
async def test_claim_next_pending_run_summarizes_context_coverage_targets_without_leaking_plan_content(test_engine):
    account_id = 1000119
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=["template-coverage"],
            endpoint_ids=["endpoint-coverage"],
            scan_plan={
                "schema_version": "scan_plan.v1",
                "test_intensity": "standard",
                "selection": {
                    "template_endpoint_pair_count": 2,
                    "selected_pair_count": 1,
                    "skipped_pair_count": 1,
                },
                "context": {"status": "partial"},
                "coverage_targets": {
                    "authorization": {
                        "template_requested": True,
                        "template_covered": False,
                        "endpoint_signal_count": 1,
                        "status": "gap",
                        "signals": ["auth_context", "private_identifier", "token=raw-plan-token"],
                        "identity_context": {
                            "role_count": 2,
                            "multi_identity_ready": True,
                            "privileged_role_present": True,
                            "low_privilege_role_present": True,
                            "privilege_boundary_pair_count": 1,
                            "role_names": ["ADMIN", "MEMBER"],
                            "debug_token": "raw-plan-token",
                        },
                        "readiness": {
                            "auth_context_ready": True,
                            "private_identifier_context_ready": True,
                            "role_context_ready": True,
                            "bola_replay_testable": True,
                            "bfla_replay_testable": True,
                            "raw_header": "Authorization: Bearer raw-plan-token",
                        },
                        "debug_path": "/accounts/123?token=raw-plan-token",
                    },
                    "business_logic": {
                        "template_requested": True,
                        "endpoint_signal_count": 1,
                        "status": "available",
                        "signals": ["workflow_path", "state_changing_method"],
                        "readiness": {
                            "workflow_context_ready": True,
                            "state_change_context_ready": True,
                            "private_identifier_context_ready": False,
                            "workflow_abuse_testable": False,
                            "debug_token": "raw-plan-token",
                        },
                        "active_test_families": {
                            "coupon_abuse": {
                                "template_count": 1,
                                "endpoint_signal_count": 1,
                                "ready": True,
                                "status": "ready",
                                "signals": ["coupon", "token=raw-plan-token"],
                                "debug_path": "/checkout/apply-coupon?token=raw-plan-token",
                            },
                            "otp_spam": {
                                "template_count": 0,
                                "endpoint_signal_count": 1,
                                "ready": False,
                                "status": "missing_template",
                                "signals": ["otp"],
                            },
                            "attacker_supplied": {
                                "template_count": 99,
                                "signals": ["secret=raw-plan-token"],
                            },
                        },
                    },
                    "llm_api": {
                        "template_requested": False,
                        "endpoint_signal_count": 0,
                        "status": "not_requested",
                        "signals": [],
                        "readiness": {
                            "prompt_context_ready": False,
                            "tool_context_ready": False,
                            "tool_abuse_testable": False,
                            "raw_prompt": "Ignore instructions token=raw-plan-token",
                        },
                        "active_test_families": {
                            "prompt_injection": {
                                "template_count": 1,
                                "endpoint_signal_count": 1,
                                "ready": True,
                                "status": "ready",
                                "signals": ["body_key", "path_hint", "token=raw-plan-token"],
                                "debug_prompt": "Ignore instructions token=raw-plan-token",
                            },
                            "tool_chain_injection": {
                                "template_count": 0,
                                "endpoint_signal_count": 1,
                                "ready": False,
                                "status": "missing_template",
                                "signals": [
                                    "tool_invocation_context",
                                    "tool_output_context",
                                    "secret=raw-plan-token",
                                ],
                            },
                            "attacker_supplied": {
                                "template_count": 99,
                                "signals": ["secret=raw-plan-token"],
                            },
                        },
                    },
                    "attacker_supplied": {
                        "status": "available",
                        "signals": ["secret=raw-plan-token"],
                    },
                },
            },
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    claimed = await claim_next_pending_run(
        db_bind=test_engine,
        account_id=account_id,
        worker_id="worker-coverage",
    )

    assert claimed is not None
    async with session_factory() as db:
        audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == run_id,
                    models.AuditLog.action == "SCAN_RUN_CLAIMED",
                )
            )
        ).scalar_one()

    scan_plan = audit.details["scan_plan"]
    assert scan_plan["coverage_targets"] == {
        "authorization": {
            "template_requested": True,
            "template_covered": False,
            "endpoint_signal_count": 1,
            "status": "gap",
            "signals": ["auth_context", "private_identifier"],
            "identity_context": {
                "role_count": 2,
                "multi_identity_ready": True,
                "privileged_role_present": True,
                "low_privilege_role_present": True,
                "privilege_boundary_pair_count": 1,
            },
            "readiness": {
                "auth_context_ready": True,
                "private_identifier_context_ready": True,
                "role_context_ready": True,
                "bola_replay_testable": True,
                "bfla_replay_testable": True,
            },
        },
        "business_logic": {
            "template_requested": True,
            "template_covered": False,
            "endpoint_signal_count": 1,
            "status": "available",
            "signals": ["state_changing_method", "workflow_path"],
            "readiness": {
                "workflow_context_ready": True,
                "state_change_context_ready": True,
                "private_identifier_context_ready": False,
                "workflow_abuse_testable": False,
            },
            "active_test_families": {
                "coupon_abuse": {
                    "template_count": 1,
                    "endpoint_signal_count": 1,
                    "ready": True,
                    "status": "ready",
                    "signals": ["coupon"],
                },
                "otp_spam": {
                    "template_count": 0,
                    "endpoint_signal_count": 1,
                    "ready": False,
                    "status": "missing_template",
                    "signals": ["otp"],
                },
            },
        },
        "llm_api": {
            "template_requested": False,
            "template_covered": False,
            "endpoint_signal_count": 0,
            "status": "not_requested",
            "signals": [],
            "readiness": {
                "prompt_context_ready": False,
                "tool_context_ready": False,
                "tool_abuse_testable": False,
            },
            "active_test_families": {
                "prompt_injection": {
                    "template_count": 1,
                    "endpoint_signal_count": 1,
                    "ready": True,
                    "status": "ready",
                    "signals": ["body_key", "path_hint"],
                },
                "tool_chain_injection": {
                    "template_count": 0,
                    "endpoint_signal_count": 1,
                    "ready": False,
                    "status": "missing_template",
                    "signals": [
                        "tool_invocation_context",
                        "tool_output_context",
                    ],
                },
            },
        },
    }
    assert "attacker_supplied" not in scan_plan["coverage_targets"]
    assert "raw-plan-token" not in str(scan_plan)
    assert "/accounts/123" not in str(scan_plan)


@pytest.mark.asyncio
async def test_claim_next_pending_run_audits_scan_plan_integrity(test_engine):
    account_id = 1000124
    scan_plan = build_readable_scan_plan(
        templates=[
            {
                "id": "authz-private-object",
                "security_category": "authorization",
                "auth": {"authenticated": True},
                "api_selection_filters": {
                    "method": {"eq": "GET"},
                    "private_variable_context": {"gt": 0},
                },
            }
        ],
        endpoints=[
            {
                "id": "endpoint-integrity",
                "method": "GET",
                "url": "https://api.example.test/accounts/123?token=raw-plan-token",
                "path": "/accounts/123",
                "auth_types_found": ["bearer"],
                "last_request_body": '{"account_id":"acct-123","token":"raw-plan-token"}',
                "private_variable_count": 1,
            }
        ],
        test_intensity="standard",
    )
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=["template-integrity"],
            endpoint_ids=["endpoint-integrity"],
            scan_plan=scan_plan,
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    claimed = await claim_next_pending_run(
        db_bind=test_engine,
        account_id=account_id,
        worker_id="worker-integrity",
    )

    assert claimed is not None
    assert claimed.scan_plan["scan_plan_hash"] == scan_plan["scan_plan_hash"]
    assert claimed.scan_plan["scan_plan_integrity"] == {
        "verified": True,
        "status": "VERIFIED",
        "hash_algorithm": "sha256",
        "expected_hash": scan_plan["scan_plan_hash"],
        "actual_hash": scan_plan["scan_plan_hash"],
    }

    async with session_factory() as db:
        audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == run_id,
                    models.AuditLog.action == "SCAN_RUN_CLAIMED",
                )
            )
        ).scalar_one()

    assert audit.details["scan_plan"]["scan_plan_hash"] == scan_plan["scan_plan_hash"]
    assert audit.details["scan_plan"]["scan_plan_integrity"]["verified"] is True
    assert "raw-plan-token" not in str(audit.details)
    assert "/accounts/123" not in str(audit.details)


@pytest.mark.asyncio
async def test_claim_next_pending_run_redacts_and_normalizes_worker_identity(test_engine):
    account_id = 1000113
    raw_worker_id = "worker token=raw-worker-token\nregion=prod"
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=["template-worker-secret"],
            endpoint_ids=["endpoint-worker-secret"],
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    claimed = await claim_next_pending_run(db_bind=test_engine, account_id=account_id, worker_id=raw_worker_id)

    assert claimed is not None
    assert claimed.run_id == run_id
    assert claimed.worker_id == "worker-token=****-region=prod"
    assert "raw-worker-token" not in claimed.worker_id

    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == run_id,
                    models.AuditLog.action == "SCAN_RUN_CLAIMED",
                )
            )
        ).scalar_one()
    assert stored.worker_id == claimed.worker_id
    assert "\n" not in stored.worker_id
    assert normalize_worker_id(raw_worker_id) == claimed.worker_id
    assert audit.details["worker_id"] == "worker-token=****-region=prod"
    assert "raw-worker-token" not in str(audit.details)


@pytest.mark.asyncio
async def test_claim_next_pending_run_records_non_secret_auth_posture(test_engine, monkeypatch):
    account_id = 1000114
    monkeypatch.setattr(settings, "PENTEST_REQUIRE_AUTH_PROFILE_FOR_ACTIVE_SCANS", True)
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        auth_profile = models.AuthProfile(
            account_id=account_id,
            name="worker claim bearer",
            auth_mode="bearer",
            token="Bearer worker-claim-secret",
            is_active=True,
        )
        db.add(auth_profile)
        await db.flush()
        pentest_profile = models.PentestProfile(
            account_id=account_id,
            name="Worker claim profile",
            auth_profile_id=auth_profile.id,
        )
        db.add(pentest_profile)
        await db.flush()
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=["template-auth-posture"],
            endpoint_ids=["endpoint-auth-posture"],
            pentest_profile_id=pentest_profile.id,
            trigger_source="schedule",
            source_schedule_id="schedule-auth-posture",
        )
        db.add(run)
        await db.commit()
        run_id = run.id
        pentest_profile_id = pentest_profile.id
        auth_profile_id = auth_profile.id

    claimed = await claim_next_pending_run(
        db_bind=test_engine,
        account_id=account_id,
        worker_id="worker-auth-posture",
    )

    assert claimed is not None
    assert claimed.run_id == run_id
    assert claimed.auth_context == {
        "pentest_profile_id": pentest_profile_id,
        "auth_resolution_status": "resolved",
        "auth_required": True,
        "auth_profile_id": auth_profile_id,
        "auth_profile_present": True,
        "auth_mode": "bearer",
    }

    async with session_factory() as db:
        audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == run_id,
                    models.AuditLog.action == "SCAN_RUN_CLAIMED",
                )
            )
        ).scalar_one()

    assert audit.details["pentest_profile_id"] == pentest_profile_id
    assert audit.details["auth_resolution_status"] == "resolved"
    assert audit.details["auth_required"] is True
    assert audit.details["auth_profile_id"] == auth_profile_id
    assert audit.details["auth_profile_present"] is True
    assert audit.details["auth_mode"] == "bearer"
    assert "worker-claim-secret" not in str(audit.details)
    assert "worker-claim-secret" not in str(claimed.auth_context)


@pytest.mark.asyncio
async def test_claim_next_pending_run_recovers_stale_dispatched_run(test_engine, monkeypatch):
    account_id = 1000101
    monkeypatch.setattr(settings, "PENTEST_SCAN_DISPATCH_LEASE_SECONDS", 60)
    stale_started_at = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=20)
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            status="DISPATCHED",
            started_at=stale_started_at,
            template_ids=["template-stale"],
            endpoint_ids=["endpoint-stale"],
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    claimed = await claim_next_pending_run(db_bind=test_engine, account_id=account_id, worker_id="worker-new")

    assert claimed is not None
    assert claimed.run_id == run_id
    assert claimed.worker_id == "worker-new"

    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
    assert stored.status == "DISPATCHED"
    assert stored.started_at is not None
    assert stored.started_at != stale_started_at
    assert stored.worker_id == "worker-new"
    assert stored.claim_count == 1


@pytest.mark.asyncio
async def test_claim_next_pending_run_ignores_fresh_dispatched_run(test_engine, monkeypatch):
    account_id = 1000102
    monkeypatch.setattr(settings, "PENTEST_SCAN_DISPATCH_LEASE_SECONDS", 60)
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            status="DISPATCHED",
            started_at=datetime.datetime.now(datetime.timezone.utc),
            template_ids=["template-fresh"],
            endpoint_ids=["endpoint-fresh"],
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    claimed = await claim_next_pending_run(db_bind=test_engine, account_id=account_id)

    assert claimed is None
    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
    assert stored.status == "DISPATCHED"


@pytest.mark.asyncio
async def test_claim_next_pending_run_recovers_expired_running_worker_lease(test_engine, monkeypatch):
    account_id = 1000106
    monkeypatch.setattr(settings, "PENTEST_SCAN_DISPATCH_LEASE_SECONDS", 60)
    expired_lease = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            status="RUNNING",
            started_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=20),
            worker_id="dead-worker",
            dispatch_lease_expires_at=expired_lease,
            worker_heartbeat_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=20),
            claim_count=2,
            template_ids=["template-running-stale"],
            endpoint_ids=["endpoint-running-stale"],
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    claimed = await claim_next_pending_run(db_bind=test_engine, account_id=account_id, worker_id="worker-rescue")

    assert claimed is not None
    assert claimed.run_id == run_id
    assert claimed.worker_id == "worker-rescue"
    assert claimed.claim_count == 3

    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
    assert stored.status == "DISPATCHED"
    assert stored.worker_id == "worker-rescue"
    assert stored.claim_count == 3


@pytest.mark.asyncio
async def test_claim_next_pending_run_dead_letters_exhausted_worker_claims(test_engine, monkeypatch):
    account_id = 1000108
    raw_worker_id = "dead-worker token=raw-dead-worker-token"
    monkeypatch.setattr(settings, "PENTEST_SCAN_DISPATCH_LEASE_SECONDS", 60)
    monkeypatch.setattr(settings, "PENTEST_SCAN_MAX_CLAIMS", 3)
    expired_lease = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            status="RUNNING",
            started_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=30),
            worker_id=raw_worker_id,
            dispatch_lease_expires_at=expired_lease,
            worker_heartbeat_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=30),
            claim_count=3,
            template_ids=["template-poisoned"],
            endpoint_ids=["endpoint-poisoned"],
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    claimed = await claim_next_pending_run(db_bind=test_engine, account_id=account_id, worker_id="worker-rescue")

    assert claimed is None
    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == run_id,
                    models.AuditLog.action == "SCAN_RUN_DEAD_LETTERED",
                )
            )
        ).scalar_one()

    assert stored.status == "FAILED"
    assert stored.error_count == 1
    assert stored.dispatch_lease_expires_at is None
    assert stored.worker_id == "dead-worker-token=****"
    assert stored.claim_count == 3
    assert audit.details["reason"] == "worker_claim_limit_exceeded"
    assert audit.details["claim_count"] == 3
    assert audit.details["max_claims"] == 3
    assert audit.details["previous_status"] == "RUNNING"
    assert audit.details["worker_id"] == "dead-worker-token=****"
    assert "raw-dead-worker-token" not in str(audit.details)


@pytest.mark.asyncio
async def test_claim_next_pending_run_skips_dead_lettered_run_and_claims_next(test_engine, monkeypatch):
    account_id = 1000109
    monkeypatch.setattr(settings, "PENTEST_SCAN_DISPATCH_LEASE_SECONDS", 60)
    monkeypatch.setattr(settings, "PENTEST_SCAN_MAX_CLAIMS", 2)
    expired_lease = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        poisoned = models.TestRun(
            account_id=account_id,
            status="DISPATCHED",
            started_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=30),
            worker_id="stale-worker",
            dispatch_lease_expires_at=expired_lease,
            worker_heartbeat_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=30),
            claim_count=2,
            template_ids=["template-poisoned"],
            endpoint_ids=["endpoint-poisoned"],
        )
        next_run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=["template-next"],
            endpoint_ids=["endpoint-next"],
        )
        db.add_all([poisoned, next_run])
        await db.commit()
        poisoned_id = poisoned.id
        next_run_id = next_run.id

    claimed = await claim_next_pending_run(db_bind=test_engine, account_id=account_id, worker_id="worker-next")

    assert claimed is not None
    assert claimed.run_id == next_run_id
    async with session_factory() as db:
        poisoned_stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == poisoned_id))).scalar_one()
        next_stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == next_run_id))).scalar_one()

    assert poisoned_stored.status == "FAILED"
    assert next_stored.status == "DISPATCHED"
    assert next_stored.worker_id == "worker-next"
    assert next_stored.claim_count == 1


@pytest.mark.asyncio
async def test_dead_lettered_vulnerability_retest_records_hashed_retest_outcome(test_engine, monkeypatch):
    account_id = 1000110
    monkeypatch.setattr(settings, "PENTEST_SCAN_DISPATCH_LEASE_SECONDS", 60)
    monkeypatch.setattr(settings, "PENTEST_SCAN_MAX_CLAIMS", 1)
    expired_lease = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
    finding_evidence = {
        "engine": "template",
        "template_id": "auth-bypass",
        "hash_algorithm": "sha256",
    }
    finding_evidence["evidence_hash"] = evidence_digest(finding_evidence)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        vulnerability = models.Vulnerability(
            account_id=account_id,
            template_id="auth-bypass",
            endpoint_id="endpoint-retest",
            url="https://api.example.test/admin",
            method="GET",
            severity="HIGH",
            type="BOLA",
            status="IN_REMEDIATION",
            evidence=finding_evidence,
        )
        db.add(vulnerability)
        await db.flush()
        run = models.TestRun(
            account_id=account_id,
            status="RUNNING",
            started_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=30),
            worker_id="dead-worker",
            dispatch_lease_expires_at=expired_lease,
            worker_heartbeat_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=30),
            claim_count=1,
            template_ids=["auth-bypass"],
            endpoint_ids=["endpoint-retest"],
            trigger_source="vulnerability_retest",
            source_vulnerability_id=vulnerability.id,
        )
        db.add(run)
        await db.commit()
        run_id = run.id
        vulnerability_id = vulnerability.id

    claimed = await claim_next_pending_run(db_bind=test_engine, account_id=account_id, worker_id="worker-rescue")

    assert claimed is None
    async with session_factory() as db:
        stored_run = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        stored_vulnerability = await db.get(models.Vulnerability, vulnerability_id)
        audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == vulnerability_id,
                    models.AuditLog.action == "VULNERABILITY_RETEST_COMPLETED",
                )
            )
        ).scalar_one()

    latest = stored_vulnerability.evidence["latest_remediation_retest"]
    assert stored_run.status == "FAILED"
    assert stored_vulnerability.status == "IN_REMEDIATION"
    assert latest["run_id"] == run_id
    assert latest["status"] == "FAILED"
    assert latest["outcome"] == "FAILED"
    assert latest["reason"] == "worker_claim_limit_exceeded"
    assert latest["executed"] == 0
    assert latest["errors"] == 1
    assert latest["hash_algorithm"] == "sha256"
    assert latest["retest_hash"] == retest_outcome_digest(latest)
    assert verify_vulnerability_evidence(stored_vulnerability.evidence)["verified"] is True
    assert audit.details["reason"] == "worker_claim_limit_exceeded"
    assert audit.details["previous_status"] == "IN_REMEDIATION"
    assert audit.details["new_status"] == "IN_REMEDIATION"
    assert audit.details["hash_algorithm"] == "sha256"
    assert audit.details["retest_hash"] == latest["retest_hash"]
    assert audit.details["retest_integrity"]["status"] == "VERIFIED"
    assert audit.details["retest_integrity"]["verified"] is True


@pytest.mark.asyncio
async def test_dead_lettered_fix_event_retest_records_hashed_retest_outcome(test_engine, monkeypatch):
    account_id = 1000116
    monkeypatch.setattr(settings, "PENTEST_SCAN_DISPATCH_LEASE_SECONDS", 60)
    monkeypatch.setattr(settings, "PENTEST_SCAN_MAX_CLAIMS", 1)
    expired_lease = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
    finding_evidence = {
        "engine": "template",
        "template_id": "fix-event-auth-bypass",
        "hash_algorithm": "sha256",
    }
    finding_evidence["evidence_hash"] = evidence_digest(finding_evidence)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        vulnerability = models.Vulnerability(
            account_id=account_id,
            template_id="fix-event-auth-bypass",
            endpoint_id="endpoint-fix-event-retest",
            url="https://api.example.test/fix-event",
            method="GET",
            severity="HIGH",
            type="BOLA",
            status="IN_REMEDIATION",
            evidence=finding_evidence,
        )
        db.add(vulnerability)
        await db.flush()
        run = models.TestRun(
            account_id=account_id,
            status="RUNNING",
            started_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=30),
            worker_id="dead-fix-event-worker",
            dispatch_lease_expires_at=expired_lease,
            worker_heartbeat_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=30),
            claim_count=1,
            template_ids=["fix-event-auth-bypass"],
            endpoint_ids=["endpoint-fix-event-retest"],
            trigger_source="vulnerability_fix_event",
            source_vulnerability_id=vulnerability.id,
        )
        db.add(run)
        await db.commit()
        run_id = run.id
        vulnerability_id = vulnerability.id

    claimed = await claim_next_pending_run(db_bind=test_engine, account_id=account_id, worker_id="worker-rescue")

    assert claimed is None
    async with session_factory() as db:
        stored_run = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        stored_vulnerability = await db.get(models.Vulnerability, vulnerability_id)
        audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == vulnerability_id,
                    models.AuditLog.action == "VULNERABILITY_RETEST_COMPLETED",
                )
            )
        ).scalar_one()

    latest = stored_vulnerability.evidence["latest_remediation_retest"]
    assert stored_run.status == "FAILED"
    assert latest["run_id"] == run_id
    assert latest["outcome"] == "FAILED"
    assert latest["reason"] == "worker_claim_limit_exceeded"
    assert latest["retest_hash"] == retest_outcome_digest(latest)
    assert verify_vulnerability_evidence(stored_vulnerability.evidence)["verified"] is True
    assert audit.details["reason"] == "worker_claim_limit_exceeded"
    assert audit.details["retest_hash"] == latest["retest_hash"]


@pytest.mark.asyncio
async def test_worker_heartbeat_extends_only_owned_active_run(test_engine, monkeypatch):
    account_id = 1000107
    monkeypatch.setattr(settings, "PENTEST_SCAN_DISPATCH_LEASE_SECONDS", 120)
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            status="DISPATCHED",
            worker_id="worker-a",
            dispatch_lease_expires_at=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5),
            worker_heartbeat_at=datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5),
            template_ids=["template-heartbeat"],
            endpoint_ids=["endpoint-heartbeat"],
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    wrong_worker = await heartbeat_claimed_run(run_id, "worker-b", db_bind=test_engine, account_id=account_id)
    wrong_account = await heartbeat_claimed_run(run_id, "worker-a", db_bind=test_engine, account_id=account_id + 1)
    right_worker = await heartbeat_claimed_run(run_id, "worker-a", db_bind=test_engine, account_id=account_id)

    assert wrong_worker is False
    assert wrong_account is False
    assert right_worker is True
    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
    assert stored.worker_heartbeat_at is not None
    lease = stored.dispatch_lease_expires_at
    if lease.tzinfo is None:
        lease = lease.replace(tzinfo=datetime.timezone.utc)
    assert lease > datetime.datetime.now(datetime.timezone.utc)


@pytest.mark.asyncio
async def test_worker_heartbeat_audits_lease_refresh_for_owned_run(test_engine, monkeypatch):
    account_id = 1000125
    monkeypatch.setattr(settings, "PENTEST_SCAN_DISPATCH_LEASE_SECONDS", 120)
    previous_lease = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=30)
    previous_heartbeat = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            status="RUNNING",
            worker_id="worker-heartbeat-audit",
            dispatch_lease_expires_at=previous_lease,
            worker_heartbeat_at=previous_heartbeat,
            claim_count=2,
            template_ids=["template-heartbeat-audit"],
            endpoint_ids=["endpoint-heartbeat-audit"],
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    refreshed = await heartbeat_claimed_run(
        run_id,
        "worker-heartbeat-audit",
        db_bind=test_engine,
        account_id=account_id,
    )

    assert refreshed is True
    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == run_id,
                    models.AuditLog.action == "SCAN_RUN_HEARTBEAT",
                )
            )
        ).scalar_one()

    assert audit.account_id == account_id
    assert audit.details["worker_id"] == "worker-heartbeat-audit"
    assert audit.details["status"] == "RUNNING"
    assert audit.details["claim_count"] == 2
    assert audit.details["previous_lease_expires_at"] == isoformat(previous_lease)
    assert audit.details["lease_expires_at"] == isoformat(stored.dispatch_lease_expires_at)
    assert audit.details["heartbeat_at"] == isoformat(stored.worker_heartbeat_at)


@pytest.mark.asyncio
async def test_worker_heartbeat_rejects_expired_owned_lease(test_engine):
    account_id = 1000116
    expired_lease = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=1)
    old_heartbeat = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            status="RUNNING",
            worker_id="worker-expired",
            dispatch_lease_expires_at=expired_lease,
            worker_heartbeat_at=old_heartbeat,
            template_ids=["template-heartbeat-expired"],
            endpoint_ids=["endpoint-heartbeat-expired"],
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    refreshed = await heartbeat_claimed_run(
        run_id,
        "worker-expired",
        db_bind=test_engine,
        account_id=account_id,
    )

    assert refreshed is False
    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()

    stored_lease = stored.dispatch_lease_expires_at
    stored_heartbeat = stored.worker_heartbeat_at
    if stored_lease.tzinfo is None:
        stored_lease = stored_lease.replace(tzinfo=datetime.timezone.utc)
    if stored_heartbeat.tzinfo is None:
        stored_heartbeat = stored_heartbeat.replace(tzinfo=datetime.timezone.utc)
    assert stored_lease == expired_lease
    assert stored_heartbeat == old_heartbeat


@pytest.mark.asyncio
async def test_worker_queue_health_reports_governance_and_reclaim_pressure(test_engine, monkeypatch):
    account_id = 1000117
    monkeypatch.setattr(settings, "PENTEST_SCAN_DISPATCH_LEASE_SECONDS", 90)
    monkeypatch.setattr(settings, "PENTEST_SCAN_MAX_CLAIMS", 3)
    now = datetime.datetime.now(datetime.timezone.utc)
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        db.add_all(
            [
                models.TestRun(
                    id="worker-health-reclaimable",
                    account_id=account_id,
                    status="RUNNING",
                    worker_id="worker-reclaimable token=raw-worker-health-token",
                    dispatch_lease_expires_at=now - datetime.timedelta(seconds=120),
                    claim_count=1,
                    template_ids=["template-reclaimable"],
                    endpoint_ids=["endpoint-reclaimable"],
                    trigger_source="schedule",
                    source_schedule_id="schedule-health-reclaimable",
                ),
                models.TestRun(
                    id="worker-health-exhausted",
                    account_id=account_id,
                    status="DISPATCHED",
                    worker_id="worker-exhausted token=raw-worker-health-token",
                    dispatch_lease_expires_at=now - datetime.timedelta(seconds=240),
                    claim_count=3,
                    template_ids=["template-exhausted"],
                    endpoint_ids=["endpoint-exhausted"],
                    trigger_source="vulnerability_retest",
                    source_vulnerability_id="vuln-health-exhausted",
                ),
                models.TestRun(
                    id="worker-health-other-tenant",
                    account_id=account_id + 1,
                    status="RUNNING",
                    worker_id="other-tenant-worker token=raw-other-tenant-token",
                    dispatch_lease_expires_at=now - datetime.timedelta(seconds=600),
                    claim_count=3,
                    template_ids=["template-other-tenant"],
                    endpoint_ids=["endpoint-other-tenant"],
                ),
            ]
        )
        await db.commit()

        health = await worker_queue_health(db, account_id=account_id)

    assert health["worker_governance"] == {
        "lease_seconds": 90,
        "max_claims": 3,
        "tenant_scoped": True,
        "kill_switch_enforced": True,
        "isolation_mode": "background",
        "per_run_worker_required": True,
        "kubernetes_job_ready": False,
        "kubernetes_namespace": "api-sentinel",
        "kubernetes_service_account": "api-sentinel-scan-worker",
        "resource_limits_required": True,
        "resource_limits": {
            "cpu": "1000m",
            "memory": "1Gi",
            "ephemeral_storage": "2Gi",
        },
    }
    assert health["engine_accountability_policy"] == {
        "isolation_model": "leased_external_worker",
        "lease_required": True,
        "worker_identity_required": True,
        "worker_isolation_manifest_required": True,
        "sandbox_cleanup_required": True,
        "artifact_hash_required": True,
        "artifact_verification_required": True,
        "redacted_evidence_required": True,
        "secret_values_persisted": False,
        "external_engine_artifact_types": [
            "schemathesis_execution",
            "nuclei_execution",
            "zap_execution",
        ],
    }
    assert health["expired_lease_count"] == 2
    assert health["reclaimable_count"] == 1
    assert health["dead_letter_ready_count"] == 1
    assert health["oldest_expired_lease_age_seconds"] >= 200
    assert health["reclaimable_runs"] == [
        {
            "run_id": "worker-health-reclaimable",
            "status": "RUNNING",
            "worker_id": "worker-reclaimable-token=****",
            "claim_count": 1,
            "max_claims": 3,
            "lease_expires_at": isoformat(now - datetime.timedelta(seconds=120)),
            "seconds_since_lease_expired": health["reclaimable_runs"][0]["seconds_since_lease_expired"],
            "trigger_source": "schedule",
            "source_schedule_id": "schedule-health-reclaimable",
            "template_count": 1,
            "endpoint_count": 1,
        }
    ]
    assert health["reclaimable_runs"][0]["seconds_since_lease_expired"] >= 100
    assert health["dead_letter_ready_runs"] == [
        {
            "run_id": "worker-health-exhausted",
            "status": "DISPATCHED",
            "worker_id": "worker-exhausted-token=****",
            "claim_count": 3,
            "max_claims": 3,
            "lease_expires_at": isoformat(now - datetime.timedelta(seconds=240)),
            "seconds_since_lease_expired": health["dead_letter_ready_runs"][0]["seconds_since_lease_expired"],
            "trigger_source": "vulnerability_retest",
            "source_vulnerability_id": "vuln-health-exhausted",
            "template_count": 1,
            "endpoint_count": 1,
        }
    ]
    assert health["dead_letter_ready_runs"][0]["seconds_since_lease_expired"] >= 200
    assert "raw-worker-health-token" not in str(health)
    assert "raw-other-tenant-token" not in str(health)
    assert "worker-health-other-tenant" not in str(health)


@pytest.mark.asyncio
async def test_claim_records_worker_engine_capability_advertisement(test_engine, monkeypatch):
    """ISO-1: the claim records what the executing worker can actually run."""
    from sentinel_worker.modules.test_executor import scan_worker as worker

    monkeypatch.setattr(worker.SchemathesisRunner, "is_available", staticmethod(lambda: True))
    monkeypatch.setattr(worker.NucleiRunner, "is_available", staticmethod(lambda: True))
    monkeypatch.setattr(worker.ZapRunner, "is_available", classmethod(lambda cls: False))
    monkeypatch.setattr(
        worker.SchemathesisRunner,
        "cli_path",
        staticmethod(lambda: "/usr/local/bin/schemathesis"),
    )

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=1000199,
            status="PENDING",
            template_ids=["t"],
            endpoint_ids=["e"],
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    claimed = await worker.claim_next_pending_run(
        db_bind=test_engine,
        account_id=1000199,
        worker_id="capability-worker",
    )
    assert claimed is not None

    async with session_factory() as db:
        audit = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.account_id == 1000199,
                    models.AuditLog.action == "SCAN_RUN_CLAIMED",
                    models.AuditLog.resource_id == run_id,
                )
            )
        ).scalar_one()

    advertisement = audit.details["worker_capabilities"]
    assert advertisement["engines"] == {
        "schemathesis": {"available": True},
        "nuclei": {"available": True},
        "zap": {"available": False},
    }
    assert advertisement["advertised_at"]
    # The advertisement is an audit record: no worker binary paths or secrets.
    assert "/usr/local/bin/schemathesis" not in str(audit.details)
    assert audit.details["worker_capability_digest"] == advertisement["digest"]



@pytest.mark.asyncio
async def test_run_pending_scan_once_executes_claimed_run(test_engine, monkeypatch):
    from sentinel_worker.modules.test_executor import run_executor
    account_id = 1000103

    template = {
        "id": "worker-template",
        "info": {"severity": "LOW"},
        "execute": {"requests": [{"req": [{}]}]},
    }
    fake_wm = run_executor.WordlistManager

    class _WorkerFakeWordlistManager:
        templates = [template]

    class _WorkerFakeEngine:
        def __init__(self, *args, **kwargs):
            from sentinel_core.modules.identity.roles_context import RolesContextBuilder

            self.roles_context_builder = RolesContextBuilder()

        async def execute_test(self, endpoint, template, selection_context=None):
            return {
                "template_id": template["id"],
                "severity": "LOW",
                "is_vulnerable": False,
                "sent_request": {"url": endpoint["url"]},
                "received_response": {"status_code": 200},
                "results": [{"vulnerable": False}],
            }

    monkeypatch.setattr(fake_wm, "get_instance", lambda *args, **kwargs: _WorkerFakeWordlistManager())
    monkeypatch.setattr(run_executor, "ExecutionEngine", _WorkerFakeEngine)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=account_id,
            method="GET",
            protocol="http",
            host="api.example.test",
            path="/worker",
        )
        db.add(endpoint)
        await db.flush()
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=[template["id"]],
            endpoint_ids=[endpoint.id],
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    result = await run_pending_scan_once(db_bind=test_engine, account_id=account_id)

    assert result["status"] == "executed"
    assert result["execution"]["status"] == "completed"
    assert result["run_id"] == run_id
    assert result["engine_accountability"]["required_artifacts"] == [
        {
            "engine": "templates",
            "artifact_type": "templates_execution",
            "hash_required": True,
            "verification_required": True,
        }
    ]

    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        artifact = (
            await db.execute(select(models.PentestArtifact).where(models.PentestArtifact.run_id == run_id))
        ).scalar_one()
    assert stored.status == "COMPLETED"
    assert stored.total_tests == 1
    assert artifact.artifact_type == "templates_execution"
    assert artifact.filename == "templates-execution.json"
    assert artifact.pentest_profile_id is None
    assert artifact.content_json["engine"] == "templates"
    assert artifact.content_json["run_id"] == run_id
    assert artifact.content_json["execution"]["status"] == "COMPLETED"
    assert artifact.content_json["execution"]["executed"] == 1
    assert artifact.content_json["artifact_hash"]
    assert verify_execution_artifact_payload(artifact.content_json)["verified"] is True


@pytest.mark.asyncio
async def test_run_pending_scan_once_executes_authorization_replay_matrix_retest(test_engine, monkeypatch):
    account_id = 1000114

    class _ReplayResponse:
        status_code = 200
        headers = {"content-type": "application/json"}
        text = '{"id":42,"email":"victim@example.com"}'

    class _ReplayClient:
        calls = []

        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        async def request(self, **kwargs):
            self.calls.append(kwargs)
            return _ReplayResponse()

    monkeypatch.setattr(httpx, "AsyncClient", _ReplayClient)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=account_id,
            method="GET",
            protocol="https",
            host="api.example.com",
            path="/users/42",
            port=443,
        )
        victim = models.TestAccount(
            id="worker-replay-victim",
            account_id=account_id,
            name="Admin Victim",
            role="ADMIN",
            auth_headers={"Authorization": "Bearer worker-replay-victim-token"},
        )
        attacker = models.TestAccount(
            id="worker-replay-attacker",
            account_id=account_id,
            name="Member Attacker",
            role="MEMBER",
            auth_headers={"Authorization": "Bearer worker-replay-attacker-token"},
        )
        db.add_all([endpoint, victim, attacker])
        await db.flush()
        sample = models.SampleData(
            account_id=account_id,
            endpoint_id=endpoint.id,
            request={
                "method": "GET",
                "url": "https://api.example.com/users/42",
                "headers": {
                    "Authorization": "Bearer worker-replay-victim-token",
                    "Accept": "application/json",
                },
                "body": "",
            },
            response={
                "status_code": 200,
                "body": {"id": 42, "email": "victim@example.com"},
                "headers": {"content-type": "application/json"},
            },
        )
        vulnerability = models.Vulnerability(
            account_id=account_id,
            template_id="AUTHORIZATION_REPLAY_MATRIX",
            endpoint_id=endpoint.id,
            url="https://api.example.com/users/42",
            method="GET",
            severity="HIGH",
            type="BFLA",
            status="IN_REMEDIATION",
            evidence={
                "engine": "authorization_replay",
                "retest_support": {
                    "supported": True,
                    "queued_scan_supported": True,
                    "reason": "authorization_replay_matrix_available",
                    "missing_fields": [],
                },
            },
        )
        db.add_all([sample, vulnerability])
        await db.flush()
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=["AUTHORIZATION_REPLAY_MATRIX"],
            endpoint_ids=[endpoint.id],
            trigger_source="vulnerability_retest",
            source_vulnerability_id=vulnerability.id,
            scan_plan={
                "schema_version": "scan_plan.v1",
                "engine_plan": [
                    {"engine": "authorization_replay", "status": "ready", "artifact_type": "authorization_replay_execution"}
                ],
                "authorization_replay": {
                    "require_response_similarity": True,
                    "body_similarity_threshold": 70,
                    "schema_similarity_threshold": 70,
                },
            },
        )
        db.add(run)
        await db.commit()
        run_id = run.id
        vulnerability_id = vulnerability.id

    result = await run_pending_scan_once(
        db_bind=test_engine,
        account_id=account_id,
        worker_id="worker-authz-replay",
    )

    assert result["status"] == "executed"
    assert result["execution"]["engine"] == "authorization_replay"
    assert result["execution"]["vulnerable"] == 1
    assert result["execution"]["executed"] == 1
    assert _ReplayClient.calls[0]["headers"]["Authorization"] == "Bearer worker-replay-attacker-token"

    async with session_factory() as db:
        stored_run = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        replay_result = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalar_one()
        vulnerability = (
            await db.execute(select(models.Vulnerability).where(models.Vulnerability.id == vulnerability_id))
        ).scalar_one()
        artifact = (
            await db.execute(select(models.PentestArtifact).where(models.PentestArtifact.run_id == run_id))
        ).scalar_one()

    assert stored_run.status == "COMPLETED"
    assert stored_run.total_tests == 1
    assert stored_run.vulnerable_count == 1
    assert replay_result.template_id.startswith("BFLA_AUTHZ_REPLAY_")
    assert artifact.artifact_type == "authorization_replay_execution"
    assert artifact.filename == "authorization_replay-execution.json"
    assert artifact.content_json["engine"] == "authorization_replay"
    assert artifact.content_json["run_id"] == run_id
    assert artifact.content_json["execution"]["trigger_source"] == "vulnerability_retest"
    assert verify_execution_artifact_payload(artifact.content_json)["verified"] is True
    latest_retest = vulnerability.evidence["latest_remediation_retest"]
    assert latest_retest["run_id"] == run_id
    assert latest_retest["outcome"] == "STILL_VULNERABLE"
    assert latest_retest["executed"] == 1
    assert latest_retest["vulnerable"] == 1
    assert "worker-replay-victim-token" not in str(vulnerability.evidence)
    assert "worker-replay-attacker-token" not in str(vulnerability.evidence)


@pytest.mark.asyncio
async def test_template_execution_artifact_preserves_scan_plan_engine_accountability(test_engine, monkeypatch):
    from sentinel_worker.modules.test_executor import run_executor

    account_id = 1000109
    template = {
        "id": "worker-engine-plan-template",
        "info": {"severity": "LOW"},
        "execute": {"requests": [{"req": [{}]}]},
    }

    class _WorkerFakeWordlistManager:
        templates = [template]

    class _WorkerFakeEngine:
        def __init__(self, *args, **kwargs):
            from sentinel_core.modules.identity.roles_context import RolesContextBuilder

            self.roles_context_builder = RolesContextBuilder()

        async def execute_test(self, endpoint, template, selection_context=None):
            return {
                "template_id": template["id"],
                "severity": "LOW",
                "is_vulnerable": False,
                "sent_request": {"url": endpoint["url"]},
                "received_response": {"status_code": 200},
                "results": [{"vulnerable": False}],
            }

    monkeypatch.setattr(run_executor.WordlistManager, "get_instance", lambda *args, **kwargs: _WorkerFakeWordlistManager())
    monkeypatch.setattr(run_executor, "ExecutionEngine", _WorkerFakeEngine)

    scan_plan = {
        "schema_version": "scan_plan.v1",
        "engine_plan": [
            {"engine": "templates", "status": "ready", "reason": "requirements_satisfied"},
            {
                "engine": "schemathesis",
                "status": "ready",
                "reason": "requirements_satisfied",
                "artifact_type": "schemathesis",
            },
            {
                "engine": "nuclei",
                "status": "blocked",
                "reason": "missing_auth_profile token=raw-plan-token",
                "artifact_type": None,
            },
            {
                "engine": "zap",
                "status": "ready",
                "reason": "requirements_satisfied",
                "artifact_type": "zap_plan",
            },
            {"engine": "passive", "status": "available", "reason": "continuous_ingestion_pipeline"},
        ],
    }

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=account_id,
            method="GET",
            protocol="http",
            host="api.example.test",
            path="/worker-engine-plan",
        )
        db.add(endpoint)
        await db.flush()
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=[template["id"]],
            endpoint_ids=[endpoint.id],
            scan_plan=scan_plan,
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    result = await run_executor.run_security_tasks(
        run_id, [template["id"]], [endpoint.id], account_id, db_bind=test_engine,
    )

    assert result["status"] == "completed"
    async with session_factory() as db:
        artifact = (
            await db.execute(select(models.PentestArtifact).where(models.PentestArtifact.run_id == run_id))
        ).scalar_one()

    payload = artifact.content_json
    artifact_engine_plan = {item["engine"]: item for item in payload["engine_plan"]}
    assert artifact_engine_plan["templates"]["status"] == "ready"
    assert artifact_engine_plan["schemathesis"]["status"] == "ready"
    assert artifact_engine_plan["nuclei"]["status"] == "blocked"
    assert artifact_engine_plan["nuclei"]["reason"] == "missing_auth_profile token=****"
    assert artifact_engine_plan["zap"]["artifact_type"] == "zap_plan"
    assert payload["multi_engine_orchestration"]["ready_active_engines"] == [
        "templates",
        "schemathesis",
        "zap",
    ]
    assert payload["multi_engine_orchestration"]["blocked_engines"] == ["nuclei"]
    assert payload["multi_engine_orchestration"]["continuous_engines"] == ["passive"]
    assert "raw-plan-token" not in str(payload)
    assert verify_execution_artifact_payload(payload)["verified"] is True


@pytest.mark.asyncio
async def test_worker_aborts_without_finalizing_when_claim_is_lost_mid_run(test_engine, monkeypatch):
    from sentinel_worker.modules.test_executor import run_executor

    account_id = 1000110
    calls = {"execute": 0, "heartbeat": 0}
    template = {
        "id": "worker-lost-claim-template",
        "info": {"severity": "LOW"},
        "execute": {"requests": [{"req": [{}]}]},
    }

    class _WorkerFakeWordlistManager:
        templates = [template]

    class _WorkerFakeEngine:
        def __init__(self, *args, **kwargs):
            from sentinel_core.modules.identity.roles_context import RolesContextBuilder

            self.roles_context_builder = RolesContextBuilder()

        async def execute_test(self, endpoint, template, selection_context=None):
            calls["execute"] += 1
            return {
                "template_id": template["id"],
                "severity": "LOW",
                "is_vulnerable": False,
                "sent_request": {"url": endpoint["url"]},
                "received_response": {"status_code": 200},
                "results": [{"vulnerable": False}],
            }

    async def fake_heartbeat_claimed_run(*args, **kwargs):
        calls["heartbeat"] += 1
        return calls["heartbeat"] == 1

    monkeypatch.setattr(
        run_executor.WordlistManager,
        "get_instance",
        lambda *args, **kwargs: _WorkerFakeWordlistManager(),
    )
    monkeypatch.setattr(run_executor, "ExecutionEngine", _WorkerFakeEngine)
    monkeypatch.setattr(run_executor, "heartbeat_claimed_run", fake_heartbeat_claimed_run)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        first = models.APIEndpoint(
            account_id=account_id,
            method="GET",
            protocol="http",
            host="api.example.test",
            path="/worker-first",
        )
        second = models.APIEndpoint(
            account_id=account_id,
            method="GET",
            protocol="http",
            host="api.example.test",
            path="/worker-second",
        )
        db.add_all([first, second])
        await db.flush()
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=[template["id"]],
            endpoint_ids=[first.id, second.id],
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    result = await run_pending_scan_once(
        db_bind=test_engine,
        account_id=account_id,
        worker_id="worker-lost-claim",
    )

    assert result["claimed"] is True
    assert result["status"] == "aborted"
    assert result["execution"]["status"] == "aborted"
    assert result["execution"]["reason"] == "worker_claim_lost"
    assert result["run_id"] == run_id
    assert calls == {"execute": 1, "heartbeat": 2}

    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        result_rows = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalars().all()
        audits = (
            await db.execute(
                select(models.AuditLog)
                .where(models.AuditLog.resource_id == run_id)
                .order_by(models.AuditLog.created_at.asc())
            )
        ).scalars().all()

    assert stored.status == "RUNNING"
    assert stored.worker_id == "worker-lost-claim"
    assert stored.total_tests == 0
    assert stored.completed_at is None
    assert result_rows == []
    assert [audit.action for audit in audits] == ["SCAN_RUN_CLAIMED", "SCAN_RUN_STARTED"]
    assert audits[0].details["worker_id"] == "worker-lost-claim"
    assert audits[0].details["claim_count"] == 1


@pytest.mark.asyncio
async def test_worker_loop_counts_aborted_claims_separately(monkeypatch):
    import sentinel_worker.modules.test_executor.scan_worker as scan_worker

    outcomes = iter(
        [
            {"claimed": True, "status": "aborted"},
            {"claimed": True, "status": "executed"},
        ]
    )

    async def fake_run_pending_scan_once(*args, **kwargs):
        return next(outcomes)

    monkeypatch.setattr(scan_worker, "run_pending_scan_once", fake_run_pending_scan_once)

    result = await run_worker_loop(max_runs=2)

    assert result == {
        "claimed": 2,
        "executed": 1,
        "aborted": 1,
        "failed": 0,
        "canceled": 0,
        "idle_cycles": 0,
    }


@pytest.mark.asyncio
async def test_worker_target_guard_failure_does_not_emit_started_audit(test_engine, monkeypatch):
    from sentinel_worker.modules.test_executor import run_executor

    account_id = 1000111

    class UnexpectedEngine:
        def __init__(self, *args, **kwargs):
            pytest.fail("worker must not construct an execution engine for target-guard-blocked runs")

    monkeypatch.setattr(run_executor, "ExecutionEngine", UnexpectedEngine)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=account_id,
            method="GET",
            protocol="http",
            host="169.254.169.254",
            path="/latest/meta-data",
        )
        db.add(endpoint)
        await db.flush()
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=["template-target-guard"],
            endpoint_ids=[endpoint.id],
            trigger_source="schedule",
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    result = await run_pending_scan_once(
        db_bind=test_engine,
        account_id=account_id,
        worker_id="worker-target-guard",
    )

    assert result["claimed"] is True
    assert result["status"] == "failed"
    assert result["execution"]["status"] == "failed"
    assert result["execution"]["reason"] == "target_guard_blocked"
    assert result["run_id"] == run_id

    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        audits = (
            await db.execute(
                select(models.AuditLog)
                .where(models.AuditLog.resource_id == run_id)
                .order_by(models.AuditLog.created_at.asc())
            )
        ).scalars().all()
        results = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalars().all()

    assert stored.status == "FAILED"
    assert stored.error_count == 1
    assert stored.dispatch_lease_expires_at is None
    assert stored.worker_id == "worker-target-guard"
    assert results == []
    assert [audit.action for audit in audits] == ["SCAN_RUN_CLAIMED", "SCAN_RUN_FAILED"]
    assert audits[0].details["worker_id"] == "worker-target-guard"
    assert audits[0].details["claim_count"] == 1
    assert audits[1].details["reason"] == "target_guard_blocked"
    assert audits[1].details["worker_id"] == "worker-target-guard"
    assert audits[1].details["trigger_source"] == "schedule"
    blocked_endpoint = audits[1].details["blocked_endpoints"][0]
    assert blocked_endpoint["endpoint_id"] == endpoint.id
    assert blocked_endpoint["target_guard_policy"]["policy"] == "target_guard"
    assert blocked_endpoint["target_guard_policy"]["blocked"] is True
    assert blocked_endpoint["target_guard_policy"]["url"] == "http://169.254.169.254/latest/meta-data"
    assert "metadata" in blocked_endpoint["target_guard_policy"]["reason"]


@pytest.mark.asyncio
async def test_worker_auth_scope_failure_does_not_emit_started_audit(test_engine, monkeypatch):
    from sentinel_worker.modules.test_executor import run_executor

    account_id = 1000112

    class UnexpectedEngine:
        def __init__(self, *args, **kwargs):
            pytest.fail("worker must not construct an execution engine for auth-scope-blocked runs")

    monkeypatch.setattr(run_executor, "ExecutionEngine", UnexpectedEngine)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=account_id,
            method="GET",
            protocol="https",
            host="api.example.test",
            path="/scoped",
        )
        auth_profile = models.AuthProfile(
            account_id=account_id,
            name="worker scoped bearer",
            auth_mode="bearer",
            token="Bearer worker-secret-token",
            scope_domains=["other.example.test"],
            is_active=True,
        )
        db.add_all([endpoint, auth_profile])
        await db.flush()
        pentest_profile = models.PentestProfile(
            account_id=account_id,
            name="worker scoped profile",
            auth_profile_id=auth_profile.id,
        )
        db.add(pentest_profile)
        await db.flush()
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=["template-auth-scope"],
            endpoint_ids=[endpoint.id],
            pentest_profile_id=pentest_profile.id,
            trigger_source="manual",
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    result = await run_pending_scan_once(
        db_bind=test_engine,
        account_id=account_id,
        worker_id="worker-auth-scope",
    )

    assert result["claimed"] is True
    assert result["status"] == "failed"
    assert result["execution"]["status"] == "failed"
    assert result["execution"]["reason"] == "auth_profile_scope_blocked"
    assert result["run_id"] == run_id

    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        audits = (
            await db.execute(
                select(models.AuditLog)
                .where(models.AuditLog.resource_id == run_id)
                .order_by(models.AuditLog.created_at.asc())
            )
        ).scalars().all()
        results = (
            await db.execute(select(models.TestResult).where(models.TestResult.run_id == run_id))
        ).scalars().all()

    assert stored.status == "FAILED"
    assert stored.error_count == 1
    assert stored.dispatch_lease_expires_at is None
    assert stored.worker_id == "worker-auth-scope"
    assert results == []
    assert [audit.action for audit in audits] == ["SCAN_RUN_CLAIMED", "SCAN_RUN_FAILED"]
    assert audits[0].details["worker_id"] == "worker-auth-scope"
    assert audits[0].details["claim_count"] == 1
    assert audits[1].details["reason"] == "auth_profile_scope_blocked"
    assert audits[1].details["worker_id"] == "worker-auth-scope"
    assert audits[1].details["trigger_source"] == "manual"
    blocked_endpoint = audits[1].details["blocked_endpoints"][0]
    assert blocked_endpoint["endpoint_id"] == endpoint.id
    policy = blocked_endpoint["auth_profile_scope_policy"]
    assert policy["policy"] == "auth_profile_scope_guard"
    assert policy["blocked"] is True
    assert policy["url"] == "https://api.example.test/scoped"
    assert policy["base_url"] == "https://api.example.test/scoped"
    assert policy["scope_domains_configured"] is True
    assert policy["scope_domain_count"] == 1
    assert "worker-secret-token" not in str(audits[1].details)


@pytest.mark.asyncio
async def test_run_pending_scan_once_passes_pentest_profile_to_runner(test_engine, monkeypatch):
    from sentinel_worker.modules.test_executor import run_executor

    account_id = 1000105
    captured: dict[str, object] = {}

    async def fake_run_security_tasks(
        run_id,
        template_ids,
        endpoint_ids,
        account_id,
        pentest_profile_id=None,
        worker_id=None,
        db_bind=None,
        worker_isolation=None,
        worker_isolation_context=None,
    ):
        captured["run_id"] = run_id
        captured["pentest_profile_id"] = pentest_profile_id
        captured["worker_id"] = worker_id
        captured["worker_isolation_present"] = isinstance(worker_isolation, dict)
        captured["worker_isolation_context_present"] = isinstance(worker_isolation_context, dict)

    monkeypatch.setattr(run_executor, "run_security_tasks", fake_run_security_tasks)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=["template-profile"],
            endpoint_ids=["endpoint-profile"],
            pentest_profile_id="profile-worker",
            trigger_source="schedule",
            source_schedule_id="schedule-worker",
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    result = await run_pending_scan_once(db_bind=test_engine, account_id=account_id)

    assert result["status"] == "executed"
    assert result["run_id"] == run_id
    assert result["pentest_profile_id"] == "profile-worker"
    assert result["source_schedule_id"] == "schedule-worker"
    assert captured == {
        "run_id": run_id,
        "pentest_profile_id": "profile-worker",
        "worker_id": result["worker_id"],
        "worker_isolation_present": True,
        "worker_isolation_context_present": True,
    }


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("configured_isolation_mode", "expected_isolation_mode", "kubernetes_job_enabled"),
    [
        ("external_worker", "leased_external_worker", False),
        ("k8s_job", "kubernetes_job", True),
    ],
)
async def test_run_pending_scan_once_records_worker_isolation_session_and_cleans_sandbox(
    test_engine,
    monkeypatch,
    tmp_path,
    configured_isolation_mode,
    expected_isolation_mode,
    kubernetes_job_enabled,
):
    from sentinel_worker.modules.test_executor import run_executor

    account_id = 1000117
    template = {
        "id": "worker-isolation-template",
        "info": {"severity": "LOW"},
        "execute": {"requests": [{"req": [{}]}]},
    }

    class _WorkerFakeWordlistManager:
        templates = [template]

    captured: dict[str, object] = {}

    class _WorkerFakeEngine:
        def __init__(self, *args, **kwargs):
            from sentinel_core.modules.identity.roles_context import RolesContextBuilder

            self.roles_context_builder = RolesContextBuilder()
            captured["worker_isolation_context"] = kwargs.get("worker_isolation_context")

        async def execute_test(self, endpoint, template, selection_context=None):
            return {
                "template_id": template["id"],
                "severity": "LOW",
                "is_vulnerable": False,
                "sent_request": {"url": endpoint["url"]},
                "received_response": {"status_code": 200},
                "results": [{"vulnerable": False}],
            }

    monkeypatch.setattr(settings, "PENTEST_SCAN_WORK_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_ISOLATION_MODE", configured_isolation_mode)
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_IMAGE", "registry.example.com/api-sentinel/worker:test")
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_JOB_TTL_SECONDS", 1200)
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_RESOURCE_CPU", "500m")
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_RESOURCE_MEMORY", "512Mi")
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_RESOURCE_EPHEMERAL_STORAGE", "1Gi")
    monkeypatch.setattr(
        run_executor.WordlistManager,
        "get_instance",
        lambda *args, **kwargs: _WorkerFakeWordlistManager(),
    )
    monkeypatch.setattr(run_executor, "ExecutionEngine", _WorkerFakeEngine)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        endpoint = models.APIEndpoint(
            account_id=account_id,
            method="GET",
            protocol="http",
            host="api.example.test",
            path="/worker-isolation",
        )
        db.add(endpoint)
        await db.flush()
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=[template["id"]],
            endpoint_ids=[endpoint.id],
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    result = await run_pending_scan_once(
        db_bind=test_engine,
        account_id=account_id,
        worker_id="worker Authorization: Bearer raw-worker-token",
    )

    assert result["status"] == "executed"
    assert result["worker_isolation"]["sandbox"]["created"] is True
    assert result["worker_isolation"]["cleanup"]["status"] == "removed"
    assert result["worker_isolation"]["cleanup"]["path_confined_to_work_dir"] is True
    assert "raw-worker-token" not in str(result["worker_isolation"])
    assert not list((tmp_path / "workers").rglob("worker-isolation.json"))
    assert isinstance(captured["worker_isolation_context"], dict)
    assert captured["worker_isolation_context"]["sandbox_path"]
    assert captured["worker_isolation_context"]["env"]["API_SENTINEL_ENGINE"] == "templates"

    async with session_factory() as db:
        artifact = (
            await db.execute(select(models.PentestArtifact).where(models.PentestArtifact.run_id == run_id))
        ).scalar_one()

    isolation = artifact.content_json["worker_isolation"]
    assert isolation["configured_worker_isolation_mode"] == expected_isolation_mode
    assert isolation["session"]["run_id"] == run_id
    assert isolation["session"]["worker_id"] == "worker-Authorization:-Bearer-****"
    assert isolation["session"]["mode"] == expected_isolation_mode
    assert isolation["sandbox"]["created"] is True
    assert isolation["sandbox"]["path_confined_to_work_dir"] is True
    assert isolation["manifest"]["filename"] == "worker-isolation.json"
    assert len(isolation["manifest"]["sha256"]) == 64
    assert isolation["resource_limits"] == {
        "cpu": "500m",
        "memory": "512Mi",
        "ephemeral_storage": "1Gi",
    }
    assert isolation["kubernetes_job"]["enabled"] is kubernetes_job_enabled
    assert isolation["kubernetes_job"]["job_ttl_seconds"] == 1200
    assert isolation["kubernetes_job"]["pod_spec"]["containers"][0]["resources"] == {
        "limits": {
            "cpu": "500m",
            "memory": "512Mi",
            "ephemeral-storage": "1Gi",
        }
    }
    if kubernetes_job_enabled:
        assert isolation["kubernetes_job"]["job_spec"]["kind"] == "Job"
        assert isolation["kubernetes_job"]["job_spec"]["spec"]["ttlSecondsAfterFinished"] == 1200
        assert isolation["kubernetes_job"]["job_spec"]["spec"]["template"]["spec"]["restartPolicy"] == "Never"
    assert "raw-worker-token" not in str(artifact.content_json)
    assert verify_execution_artifact_payload(artifact.content_json)["verified"] is True
    assert result["worker_artifact"]["present"] is True
    assert result["worker_artifact"]["artifact_type"] == "templates_execution"
    assert result["worker_artifact"]["hash_algorithm"] == "sha256"
    assert result["worker_artifact"]["artifact_hash"] == artifact.content_json["artifact_hash"]
    assert result["worker_artifact"]["artifact_verification"]["verified"] is True
    assert result["worker_acceptance"]["ready"] is True
    assert result["worker_acceptance"]["status"] == "accepted"
    assert result["worker_acceptance"]["blockers"] == []
    assert result["worker_acceptance"]["checks"]["queued_worker_execution"]["ready"] is True
    assert result["worker_acceptance"]["checks"]["sandbox_cleanup"]["ready"] is True
    assert result["worker_acceptance"]["checks"]["resource_limits"]["ready"] is True
    assert result["worker_acceptance"]["checks"]["artifact_generation"]["ready"] is True


@pytest.mark.asyncio
async def test_worker_queue_health_exposes_runtime_validation_for_kubernetes_queue(
    test_engine,
    monkeypatch,
):
    account_id = 1000127
    monkeypatch.setattr(settings, "PENTEST_SCAN_EXECUTION_MODE", "queued")
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_ISOLATION_MODE", "kubernetes_job")
    monkeypatch.setattr(settings, "PENTEST_KILL_SWITCH_ENABLED", False)
    monkeypatch.setattr(settings, "PENTEST_SCAN_DISPATCH_LEASE_SECONDS", 90)
    monkeypatch.setattr(settings, "PENTEST_SCAN_MAX_CLAIMS", 3)
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_RESOURCE_CPU", "500m")
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_RESOURCE_MEMORY", "512Mi")
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_RESOURCE_EPHEMERAL_STORAGE", "1Gi")

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        health = await worker_queue_health(db, account_id=account_id)

    validation = health["runtime_validation"]
    assert validation["ready"] is True
    assert validation["status"] == "ready"
    assert validation["blockers"] == []
    assert validation["checks"]["queued_workers"]["ready"] is True
    assert validation["checks"]["external_worker_mode"]["ready"] is True
    assert validation["checks"]["kubernetes_job_mode"]["ready"] is True
    assert validation["checks"]["lease_expiry"]["evidence"] == {
        "lease_seconds": 90,
        "max_claims": 3,
        "expired_lease_count": 0,
        "dead_letter_ready_count": 0,
    }
    assert validation["checks"]["resource_limits"]["evidence"] == {
        "cpu": "500m",
        "memory": "512Mi",
        "ephemeral_storage": "1Gi",
    }


@pytest.mark.asyncio
async def test_worker_does_not_claim_when_kill_switch_enabled(test_engine, monkeypatch):
    account_id = 1000104
    monkeypatch.setattr(settings, "PENTEST_KILL_SWITCH_ENABLED", True)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=["template-paused"],
            endpoint_ids=["endpoint-paused"],
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    claimed = await claim_next_pending_run(db_bind=test_engine, account_id=account_id)
    result = await run_pending_scan_once(db_bind=test_engine, account_id=account_id)

    assert claimed is None
    assert result == {
        "status": "paused",
        "claimed": False,
        "reason": "pentest_kill_switch_enabled",
    }

    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
    assert stored.status == "PENDING"


@pytest.mark.asyncio
async def test_reclaim_emits_worker_lost_audit(test_engine, monkeypatch):
    account_id = 1000191
    monkeypatch.setattr(settings, "PENTEST_SCAN_DISPATCH_LEASE_SECONDS", 30)
    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    stale_started = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=10)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            status="RUNNING",
            template_ids=["template-lost"],
            endpoint_ids=["endpoint-lost"],
            worker_id="worker-old",
            started_at=stale_started,
            worker_heartbeat_at=stale_started,
            dispatch_lease_expires_at=stale_started,
            claim_count=1,
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    claimed = await claim_next_pending_run(
        db_bind=test_engine,
        account_id=account_id,
        worker_id="worker-new",
    )
    assert claimed is not None
    assert claimed.run_id == run_id
    assert claimed.worker_id == "worker-new"

    async with session_factory() as db:
        audits = (
            await db.execute(
                select(models.AuditLog)
                .where(
                    models.AuditLog.resource_id == run_id,
                    models.AuditLog.action.in_(["SCAN_RUN_CLAIMED", "SCAN_RUN_WORKER_LOST"]),
                )
                .order_by(models.AuditLog.created_at.asc())
            )
        ).scalars().all()
    actions = [audit.action for audit in audits]
    assert "SCAN_RUN_CLAIMED" in actions
    assert "SCAN_RUN_WORKER_LOST" in actions
    lost = next(audit for audit in audits if audit.action == "SCAN_RUN_WORKER_LOST")
    assert lost.details["previous_worker_id"] == "worker-old"
    assert lost.details["new_worker_id"] == "worker-new"
    assert lost.details["run_id"] == run_id


@pytest.mark.asyncio
async def test_run_pending_scan_once_times_out_and_audits(test_engine, monkeypatch):
    account_id = 1000192
    monkeypatch.setattr(settings, "PENTEST_SCAN_WORKER_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(settings, "PENTEST_SCAN_DISPATCH_LEASE_SECONDS", 30)

    async def _slow_tasks(*args, **kwargs):
        await asyncio.sleep(5)
        return {"status": "completed"}

    monkeypatch.setattr(
        "sentinel_worker.modules.test_executor.run_executor.run_security_tasks",
        _slow_tasks,
    )

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=["template-timeout"],
            endpoint_ids=["endpoint-timeout"],
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    result = await run_pending_scan_once(
        db_bind=test_engine,
        account_id=account_id,
        worker_id="worker-timeout",
    )
    assert result["claimed"] is True
    assert result["status"] == "TIMEOUT"
    assert result["execution"]["status"] == "TIMEOUT"

    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        audits = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == run_id,
                    models.AuditLog.action == "SCAN_RUN_TIMED_OUT",
                )
            )
        ).scalars().all()
    assert stored.status == "FAILED"
    assert len(audits) == 1
    assert audits[0].details["run_id"] == run_id
    assert "timed_out" in audits[0].details["reason"]


@pytest.mark.asyncio
async def test_run_pending_scan_once_uncaught_exception_marks_failed(test_engine, monkeypatch):
    account_id = 1000193

    async def _boom(*args, **kwargs):
        raise RuntimeError("secret=raw-worker-token exploded")

    monkeypatch.setattr("sentinel_worker.modules.test_executor.run_executor.run_security_tasks", _boom)

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=["template-boom"],
            endpoint_ids=["endpoint-boom"],
        )
        db.add(run)
        await db.commit()
        run_id = run.id

    result = await run_pending_scan_once(
        db_bind=test_engine,
        account_id=account_id,
        worker_id="worker-boom",
    )
    assert result["claimed"] is True
    assert result["status"] == "failed"
    assert "raw-worker-token" not in str(result)

    async with session_factory() as db:
        stored = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        audits = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == run_id,
                    models.AuditLog.action == "SCAN_RUN_FAILED",
                )
            )
        ).scalars().all()
    assert stored.status == "FAILED"
    assert len(audits) == 1
    assert "raw-worker-token" not in str(audits[0].details)


@pytest.mark.asyncio
async def test_run_pending_scan_once_finalizes_external_engine_retest_outcome(test_engine, monkeypatch):
    """LIFE-1: a queued external-engine retest closes the loop.

    The engine runs in the external phase, findings promote into Vulnerability,
    the retest executor records a hashed STILL_VULNERABLE outcome against the
    source finding, and the templates phase never executes.
    """
    from sentinel_worker.modules.test_executor import scan_worker as worker

    account_id = 1000117

    class _FakeNucleiRunner:
        @staticmethod
        def is_available():
            return True

        @staticmethod
        def cli_path():
            return "/usr/local/bin/nuclei"

        @staticmethod
        async def run_scan(**kwargs):
            return {
                "status": "FAILED_WITH_FINDINGS",
                "findings": [
                    {
                        "template-id": "cve-2024-1234",
                        "info": {"name": "Test CVE", "severity": "high", "remediation": "Patch it"},
                        "matched-at": "https://api.example.com/users/42",
                        "type": "http",
                        "host": "https://api.example.com",
                    }
                ],
                "failures": 1,
                "total_found": 1,
            }

    async def _no_templates_execution(*args, **kwargs):
        raise AssertionError("templates phase must not run for an external-engine retest")

    monkeypatch.setattr(worker.NucleiRunner, "run_scan", staticmethod(_FakeNucleiRunner.run_scan))

    session_factory = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with session_factory() as db:
        auth_profile = models.AuthProfile(
            account_id=account_id,
            name="retest-auth",
            auth_mode="header",
            header_name="X-API-Key",
            header_value="retest-secret",
            scope_domains=["api.example.com"],
            is_active=True,
        )
        profile = models.PentestProfile(
            account_id=account_id,
            name="retest-profile",
            allow_state_change=True,
            allow_destructive_methods=True,
            auth_profile_id=None,
        )
        endpoint = models.APIEndpoint(
            account_id=account_id,
            method="GET",
            protocol="https",
            host="api.example.com",
            path="/users/42",
            port=443,
        )
        db.add_all([auth_profile, profile, endpoint])
        await db.flush()
        profile.auth_profile_id = auth_profile.id
        vulnerability = models.Vulnerability(
            account_id=account_id,
            template_id="NUCLEI:cve-2024-1234",
            endpoint_id=None,
            url="https://api.example.com/users/42",
            method="GET",
            severity="HIGH",
            type="NUCLEI:cve-2024-1234",
            status="IN_REMEDIATION",
            evidence={"engine": "nuclei", "url": "https://api.example.com/users/42"},
        )
        db.add(vulnerability)
        await db.flush()
        from sentinel_core.modules.test_executor.scan_plan import finalize_scan_plan_hash

        scan_plan = finalize_scan_plan_hash({
            "schema_version": "scan_plan.v1",
            "engine_plan": [
                {"engine": "nuclei", "status": "ready", "reason": "retest_external_engine", "artifact_type": "nuclei_execution"},
                {"engine": "schemathesis", "status": "blocked", "reason": "external_engine_scope_required"},
                {"engine": "zap", "status": "blocked", "reason": "external_engine_scope_required"},
            ],
            "external_engine_scope": {"target_url": "https://api.example.com/users/42"},
        })
        run = models.TestRun(
            account_id=account_id,
            status="PENDING",
            template_ids=["EXTERNAL_ENGINE_RETEST"],
            endpoint_ids=[endpoint.id],
            pentest_profile_id=profile.id,
            trigger_source="vulnerability_retest",
            source_vulnerability_id=vulnerability.id,
            scan_plan=scan_plan,
        )
        db.add(run)
        await db.commit()
        run_id = run.id
        vulnerability_id = vulnerability.id
        endpoint_id = endpoint.id

    result = await run_pending_scan_once(
        db_bind=test_engine,
        account_id=account_id,
        worker_id="worker-external-retest",
    )

    assert result["status"] == "executed", result
    assert result["execution"]["status"] == "completed"
    assert result["execution"]["engine"] == "nuclei"
    assert result["execution"]["executed"] == 1
    assert result["execution"]["vulnerable"] == 1

    async with session_factory() as db:
        stored_run = (await db.execute(select(models.TestRun).where(models.TestRun.id == run_id))).scalar_one()
        vulnerability = (
            await db.execute(select(models.Vulnerability).where(models.Vulnerability.id == vulnerability_id))
        ).scalar_one()
        source = (
            await db.execute(select(models.Vulnerability).where(models.Vulnerability.id == vulnerability_id))
        ).scalar_one()
        promoted = (
            await db.execute(
                select(models.Vulnerability).where(
                    models.Vulnerability.account_id == account_id,
                    models.Vulnerability.template_id == "cve-2024-1234",
                )
            )
        ).scalar_one()
        artifact = (
            await db.execute(
                select(models.PentestArtifact).where(
                    models.PentestArtifact.run_id == run_id,
                    models.PentestArtifact.artifact_type == "nuclei_execution",
                )
            )
        ).scalar_one()
        audits = (
            await db.execute(
                select(models.AuditLog).where(
                    models.AuditLog.resource_id == run_id,
                    models.AuditLog.action == "SCAN_RUN_COMPLETED",
                )
            )
        ).scalars().all()

    assert stored_run.status == "COMPLETED"
    assert stored_run.total_tests == 1
    assert stored_run.vulnerable_count == 1
    # The producing engine re-found the issue: the source finding stays open.
    assert source.status == "OPEN"
    latest_retest = source.evidence["latest_remediation_retest"]
    assert latest_retest["run_id"] == run_id
    assert latest_retest["outcome"] == "STILL_VULNERABLE"
    assert latest_retest["executed"] == 1
    assert latest_retest["vulnerable"] == 1
    assert latest_retest["retest_hash"]
    # Engine finding was promoted from the run.
    assert promoted is not None
    assert promoted.endpoint_id is None
    assert artifact.artifact_type == "nuclei_execution"
    assert verify_execution_artifact_payload(artifact.content_json)["verified"] is True
    assert audits and audits[0].details["engine"] == "nuclei"
    assert audits[0].details["execution_mode"] == "queued_retest"
    # The endpoint resolved from evidence must be the one that ran.
    assert stored_run.endpoint_ids == [endpoint_id]
    assert "retest-secret" not in str(vulnerability.evidence)
