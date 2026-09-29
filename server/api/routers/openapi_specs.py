"""OpenAPI spec management, validation, and diffing."""
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from server.models.core import APIEndpoint, OpenAPISpec, PolicyViolation, EvidenceRecord
from server.modules.auth.rbac import Permission, RBAC
from server.modules.cache.redis_cache import bump_cache_version
from server.modules.api_inventory.endpoint_discovery import (
    EndpointDiscovery,
    openapi_operations_to_discovery_entries,
)
from server.modules.api_inventory.openapi_generator import OpenAPIGenerator
from server.modules.api_inventory.openapi_diff import OpenAPIDiffAnalyzer
from server.modules.api_inventory.zap_plan import ZapScanPlanBuilder
from server.modules.pentest.target_policy import target_guard_policy_for_error
from server.modules.persistence.database import get_db
from server.modules.test_executor.target_guard import TargetGuardError
from server.modules.utils.redactor import Redactor
from server.modules.zap.findings import persist_zap_report

router = APIRouter()
_gen = OpenAPIGenerator()
_diff = OpenAPIDiffAnalyzer()
_zap = ZapScanPlanBuilder()


def _target_guard_exception(exc: TargetGuardError, *, target_url: str) -> HTTPException:
    return HTTPException(
        status_code=400,
        detail={
            "message": str(exc),
            "reason": "target_guard_blocked",
            "target_guard_policy": target_guard_policy_for_error(exc, fallback_url=target_url),
        },
    )


class SpecDiffRequest(BaseModel):
    base_spec_id: str | None = None
    revision_spec_id: str | None = None
    base_spec: dict | None = None
    revision_spec: dict | None = None


class OpenAPIImportRequest(BaseModel):
    spec: dict = Field(default_factory=dict)
    version: str = "1.0.0"
    target_url: str
    source: str = "openapi"
    owner: str | None = None


class ZapPlanRequest(BaseModel):
    target_url: str
    spec_id: str | None = None
    spec: dict | None = None
    context_name: str = "api-sentinel"
    max_passive_wait_minutes: int = Field(default=5, ge=1, le=60)
    active_scan_policy: str = "API Policy"
    fail_severity: str = "High"
    warn_severity: str = "Medium"
    auth_header_name: str | None = None
    auth_header_site: str | None = None
    extra_headers: dict[str, str] = Field(default_factory=dict)
    allow_state_change: bool = False
    allow_destructive_methods: bool = False


class ZapReportImportRequest(BaseModel):
    target_url: str
    report: dict = Field(default_factory=dict)


def _serialize_schema_violation(violation: PolicyViolation, endpoint: APIEndpoint | None) -> dict:
    metadata = violation.violation_metadata or {}
    return {
        "id": violation.id,
        "endpoint_id": violation.endpoint_id,
        "endpoint": Redactor.redact_text(
            (endpoint.path_pattern or endpoint.path)
            if endpoint
            else (metadata.get("endpoint") or violation.endpoint_id or "Unknown endpoint")
        ),
        "method": (endpoint.method or "UNKNOWN") if endpoint else str(metadata.get("method") or "UNKNOWN").upper(),
        "violation_type": metadata.get("violation_type") or violation.rule_type or "SCHEMA",
        "field": Redactor.redact_text(str(metadata.get("field") or metadata.get("path") or "payload")),
        "expected": Redactor.redact_text(str(metadata.get("expected") or "OpenAPI contract")),
        "actual": Redactor.redact_text(
            str(metadata.get("actual") or violation.message or "Observed payload did not match schema")
        ),
        "severity": (violation.severity or "MEDIUM").lower(),
        "count": int(metadata.get("count") or 1),
        "last_seen": violation.created_at.isoformat() if violation.created_at else None,
        "status": violation.status,
    }


@router.post("/rebuild")
async def rebuild_openapi(
    payload: dict = Depends(RBAC.require_permission(Permission.ENDPOINTS_WRITE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    spec = await _gen.generate_spec(collection_name="Discovered API", account_id=account_id)
    record = OpenAPISpec(account_id=account_id, spec_json=spec)
    db.add(record)
    await db.commit()
    return {"status": "created", "id": record.id}


@router.post("/import")
async def import_openapi_spec(
    body: OpenAPIImportRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.ENDPOINTS_WRITE)),
    db: AsyncSession = Depends(get_db),
):
    """Store an OpenAPI document and upsert its operations into endpoint inventory."""
    account_id = payload.get("account_id")
    if not body.spec or not isinstance(body.spec.get("paths"), dict):
        raise HTTPException(status_code=400, detail="spec.paths: OpenAPI paths object is required")

    record = OpenAPISpec(account_id=account_id, version=body.version, spec_json=body.spec)
    db.add(record)
    await db.flush()

    discovery = EndpointDiscovery(db)
    entries = openapi_operations_to_discovery_entries(
        spec=body.spec,
        target_url=body.target_url,
        account_id=account_id,
        source=body.source,
        owner=body.owner,
        version=body.version,
    )
    endpoints = []
    for entry in entries:
        endpoints.append(await discovery.discover(entry, commit=False))

    await db.commit()
    await bump_cache_version(account_id)
    return {
        "status": "imported",
        "spec_id": record.id,
        "endpoint_count": len(endpoints),
    }


@router.get("/latest")
async def get_latest_openapi(
    payload: dict = Depends(RBAC.require_permission(Permission.COMPLIANCE_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    result = await db.execute(
        select(OpenAPISpec)
        .where(OpenAPISpec.account_id == account_id)
        .order_by(OpenAPISpec.created_at.desc())
        .limit(1)
    )
    spec = result.scalar_one_or_none()
    if not spec:
        raise HTTPException(status_code=404, detail="No OpenAPI spec found")
    return {"id": spec.id, "spec": _redact_string_values(spec.spec_json or {})}


@router.get("/history")
async def list_openapi_history(
    payload: dict = Depends(RBAC.require_permission(Permission.COMPLIANCE_READ)),
    db: AsyncSession = Depends(get_db),
    limit: int = 10,
):
    account_id = payload.get("account_id")
    result = await db.execute(
        select(OpenAPISpec)
        .where(OpenAPISpec.account_id == account_id)
        .order_by(OpenAPISpec.created_at.desc())
        .limit(min(max(limit, 1), 50))
    )
    specs = result.scalars().all()
    return {
        "total": len(specs),
        "specs": [
            {
                "id": spec.id,
                "version": spec.version,
                "path_count": len((spec.spec_json or {}).get("paths", {})),
                "created_at": spec.created_at.isoformat() if spec.created_at else None,
            }
            for spec in specs
        ],
    }


@router.get("/violations")
async def list_openapi_violations(
    payload: dict = Depends(RBAC.require_permission(Permission.COMPLIANCE_READ)),
    db: AsyncSession = Depends(get_db),
    limit: int = 50,
):
    account_id = payload.get("account_id")
    result = await db.execute(
        select(PolicyViolation, APIEndpoint)
        .outerjoin(APIEndpoint, APIEndpoint.id == PolicyViolation.endpoint_id)
        .where(
            PolicyViolation.account_id == account_id,
            PolicyViolation.rule_type == "SCHEMA",
        )
        .order_by(PolicyViolation.created_at.desc())
        .limit(min(max(limit, 1), 200))
    )
    violations = [
        _serialize_schema_violation(violation, endpoint)
        for violation, endpoint in result.all()
    ]
    return {"total": len(violations), "violations": violations}


@router.post("/diff")
async def diff_openapi_specs(
    body: SpecDiffRequest | None = None,
    payload: dict = Depends(RBAC.require_permission(Permission.COMPLIANCE_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    body = body or SpecDiffRequest()

    if (body.base_spec is None) ^ (body.revision_spec is None):
        raise HTTPException(status_code=400, detail="Provide both base_spec and revision_spec together")
    if (body.base_spec_id is None) ^ (body.revision_spec_id is None):
        raise HTTPException(status_code=400, detail="Provide both base_spec_id and revision_spec_id together")

    base_spec_id = body.base_spec_id
    revision_spec_id = body.revision_spec_id
    base_spec = body.base_spec
    revision_spec = body.revision_spec

    if base_spec is None and revision_spec is None:
        if base_spec_id and revision_spec_id:
            base_record = await _fetch_spec(db, account_id, base_spec_id)
            revision_record = await _fetch_spec(db, account_id, revision_spec_id)
        else:
            result = await db.execute(
                select(OpenAPISpec)
                .where(OpenAPISpec.account_id == account_id)
                .order_by(OpenAPISpec.created_at.desc())
                .limit(2)
            )
            records = result.scalars().all()
            if len(records) < 2:
                raise HTTPException(status_code=404, detail="Need at least two stored OpenAPI specs to diff")
            revision_record, base_record = records[0], records[1]

        base_spec = base_record.spec_json
        revision_spec = revision_record.spec_json
        base_spec_id = base_record.id
        revision_spec_id = revision_record.id

    diff = _redact_string_values(_diff.compare(base_spec, revision_spec))
    return {
        "base_spec_id": base_spec_id,
        "revision_spec_id": revision_spec_id,
        **diff,
    }


@router.post("/scan-plan")
async def build_openapi_scan_plan(
    body: ZapPlanRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_RUN)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    if body.spec is not None and body.spec_id is not None:
        raise HTTPException(status_code=400, detail="Provide either spec or spec_id, not both")

    if body.spec is not None:
        spec = body.spec
        spec_id = body.spec_id
    elif body.spec_id is not None:
        spec_record = await _fetch_spec(db, account_id, body.spec_id)
        spec = spec_record.spec_json
        spec_id = spec_record.id
    else:
        result = await db.execute(
            select(OpenAPISpec)
            .where(OpenAPISpec.account_id == account_id)
            .order_by(OpenAPISpec.created_at.desc())
            .limit(1)
        )
        spec_record = result.scalar_one_or_none()
        if not spec_record:
            raise HTTPException(status_code=404, detail="No OpenAPI spec found")
        spec = spec_record.spec_json
        spec_id = spec_record.id

    try:
        return _redact_string_values(_zap.build(
            spec=spec,
            target_url=body.target_url,
            spec_id=spec_id,
            context_name=body.context_name,
            max_passive_wait_minutes=body.max_passive_wait_minutes,
            active_scan_policy=body.active_scan_policy,
            fail_severity=body.fail_severity,
            warn_severity=body.warn_severity,
            auth_header_name=body.auth_header_name,
            auth_header_site=body.auth_header_site,
            extra_headers=body.extra_headers,
            allow_state_change=body.allow_state_change,
            allow_destructive_methods=body.allow_destructive_methods,
        ))
    except TargetGuardError as exc:
        raise _target_guard_exception(exc, target_url=body.target_url) from exc


@router.post("/zap-report/import")
async def import_zap_report(
    body: ZapReportImportRequest,
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_RUN)),
    db: AsyncSession = Depends(get_db),
):
    """Import OWASP ZAP JSON report alerts into the unified vulnerability lifecycle."""
    account_id = payload.get("account_id")
    if not body.report:
        raise HTTPException(status_code=400, detail="report: ZAP JSON report is required")

    try:
        summary = await persist_zap_report(
            db,
            account_id=account_id,
            target_url=body.target_url,
            report=body.report,
        )
    except TargetGuardError as exc:
        raise _target_guard_exception(exc, target_url=body.target_url) from exc
    await db.commit()
    return {
        "status": "imported",
        "target_url": body.target_url,
        "alerts_imported": summary["imported_alert_instances"],
        "vulnerabilities_created": summary["created_count"],
        "vulnerabilities_merged": summary["merged_count"],
        "vulnerabilities": summary["vulnerabilities"][:10],
    }


@router.post("/validate")
async def validate_against_openapi(
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Validate discovered endpoints against the latest OpenAPI spec."""
    account_id = payload.get("account_id")
    spec_result = await db.execute(
        select(OpenAPISpec)
        .where(OpenAPISpec.account_id == account_id)
        .order_by(OpenAPISpec.created_at.desc())
        .limit(1)
    )
    spec = spec_result.scalar_one_or_none()
    if not spec:
        raise HTTPException(status_code=404, detail="No OpenAPI spec found")

    paths = (spec.spec_json or {}).get("paths", {})
    eps_result = await db.execute(
        select(APIEndpoint).where(APIEndpoint.account_id == account_id)
    )
    endpoints = eps_result.scalars().all()

    violations = []
    for ep in endpoints:
        path_entry = paths.get(ep.path or "")
        if not path_entry or ep.method.lower() not in path_entry:
            message = Redactor.redact_text(f"Endpoint {ep.method} {ep.path} missing from OpenAPI spec")
            v = PolicyViolation(
                account_id=account_id,
                endpoint_id=ep.id,
                rule_type="SCHEMA",
                severity="HIGH",
                message=message,
            )
            db.add(v)
            violations.append(v)

    await db.flush()
    for v in violations:
        db.add(EvidenceRecord(
            account_id=account_id,
            evidence_type="policy",
            ref_id=v.id,
            endpoint_id=v.endpoint_id,
            severity=v.severity,
            summary=Redactor.redact_text(v.message or ""),
        ))

    await db.commit()
    return {"violations_found": len(violations)}


async def _fetch_spec(db: AsyncSession, account_id: int, spec_id: str) -> OpenAPISpec:
    result = await db.execute(
        select(OpenAPISpec).where(
            OpenAPISpec.id == spec_id,
            OpenAPISpec.account_id == account_id,
        )
    )
    spec = result.scalar_one_or_none()
    if not spec:
        raise HTTPException(status_code=404, detail=f"OpenAPI spec '{spec_id}' not found")
    return spec


def _redact_string_values(value):
    if isinstance(value, dict):
        return {
            Redactor.redact_text(key) if isinstance(key, str) else key: _redact_string_values(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_string_values(item) for item in value]
    if isinstance(value, str):
        return Redactor.redact_text(value)
    return value
