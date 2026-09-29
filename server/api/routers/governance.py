"""API Governance — policy rules for naming, security, schema, and rate-limit enforcement."""
from fastapi import APIRouter, Depends, HTTPException, Body, Query
from sqlalchemy.future import select
from sqlalchemy import update, delete, func, and_
from sqlalchemy.ext.asyncio import AsyncSession
from server.modules.persistence.database import get_db
from server.modules.auth.rbac import Permission, RBAC
from server.models.core import GovernanceRule, APIEndpoint, PolicyViolation
from server.modules.auth.audit import log_action
from server.modules.utils.redactor import Redactor

router = APIRouter()

RULE_TYPES = {"NAMING", "SECURITY", "SCHEMA", "RATE_LIMIT"}
ACTIONS = {"WARN", "BLOCK", "ALERT"}

# Built-in governance checks applied per endpoint
_BUILTIN_CHECKS = [
    {
        "name": "No DELETE on sensitive paths",
        "rule_type": "SECURITY",
        "condition": {"field": "method", "op": "eq", "value": "DELETE"},
        "path_contains": ["/user", "/account", "/admin"],
    },
    {
        "name": "Auth endpoints must use HTTPS",
        "rule_type": "SECURITY",
        "condition": {"field": "protocol", "op": "neq", "value": "https"},
        "path_contains": ["/auth", "/login", "/token"],
    },
    {
        "name": "API paths should be lowercase",
        "rule_type": "NAMING",
        "condition": {"field": "path", "op": "has_uppercase"},
    },
]


@router.get("/rules")
async def list_rules(
    payload: dict = Depends(RBAC.require_permission(Permission.COMPLIANCE_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    result = await db.execute(
        select(GovernanceRule).where(GovernanceRule.account_id == account_id)
    )
    rules = result.scalars().all()
    return {
        "total": len(rules),
        "rules": [_serialize_rule(r) for r in rules],
    }


@router.post("/rules")
async def create_rule(
    name: str = Body(...),
    rule_type: str = Body(..., description="NAMING | SECURITY | SCHEMA | RATE_LIMIT"),
    condition: dict = Body(..., description='{"field": "method", "op": "eq", "value": "DELETE"}'),
    action: str = Body("WARN", description="WARN | BLOCK | ALERT"),
    description: str = Body(None),
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    if rule_type.upper() not in RULE_TYPES:
        raise HTTPException(status_code=400, detail=f"rule_type must be one of: {RULE_TYPES}")
    if action.upper() not in ACTIONS:
        raise HTTPException(status_code=400, detail=f"action must be one of: {ACTIONS}")

    rule = GovernanceRule(
        account_id=account_id,
        name=name,
        description=description,
        rule_type=rule_type.upper(),
        condition=condition,
        action=action.upper(),
    )
    db.add(rule)
    await db.commit()
    await log_action(
        db=db,
        account_id=account_id,
        action="POLICY_CREATED",
        user_id=payload.get("user_id"),
        resource_type="governance_rule",
        resource_id=rule.id,
        details={
            "name": Redactor.redact_text(name),
            "rule_type": rule_type.upper(),
            "action": action.upper(),
        },
    )
    await db.commit()
    return {"status": "created", "id": rule.id}


@router.patch("/rules/{rule_id}/toggle")
async def toggle_rule(
    rule_id: str,
    enabled: bool = True,
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    await db.execute(
        update(GovernanceRule).where(
            and_(GovernanceRule.id == rule_id, GovernanceRule.account_id == account_id)
        ).values(enabled=enabled)
    )
    await db.commit()
    await log_action(
        db=db,
        account_id=account_id,
        action="POLICY_TOGGLED",
        user_id=payload.get("user_id"),
        resource_type="governance_rule",
        resource_id=rule_id,
        details={"enabled": enabled},
    )
    await db.commit()
    return {"status": "updated", "id": rule_id, "enabled": enabled}


@router.delete("/rules/{rule_id}")
async def delete_rule(
    rule_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    await db.execute(
        delete(GovernanceRule).where(
            and_(GovernanceRule.id == rule_id, GovernanceRule.account_id == account_id)
        )
    )
    await db.commit()
    await log_action(
        db=db,
        account_id=account_id,
        action="POLICY_DELETED",
        user_id=payload.get("user_id"),
        resource_type="governance_rule",
        resource_id=rule_id,
    )
    await db.commit()
    return {"status": "deleted", "id": rule_id}


@router.post("/scan")
async def scan_endpoints(
    payload: dict = Depends(RBAC.require_permission(Permission.VULNS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Run all enabled governance rules against discovered endpoints and return violations."""
    account_id = payload.get("account_id")
    rules_result = await db.execute(
        select(GovernanceRule).where(
            GovernanceRule.account_id == account_id,
            GovernanceRule.enabled == True,
        )
    )
    rules = rules_result.scalars().all()

    eps_result = await db.execute(
        select(APIEndpoint).where(APIEndpoint.account_id == account_id).limit(500)
    )
    endpoints = eps_result.scalars().all()

    violations = []
    for rule in rules:
        cond = rule.condition or {}
        field = cond.get("field", "")
        op = cond.get("op", "eq")
        value = cond.get("value", "")

        for ep in endpoints:
            ep_val = getattr(ep, field, None)
            if ep_val is None:
                continue
            violated = False
            if op == "eq" and str(ep_val).lower() == str(value).lower():
                violated = True
            elif op == "neq" and str(ep_val).lower() != str(value).lower():
                violated = True
            elif op == "has_uppercase" and ep_val != ep_val.lower():
                violated = True
            elif op == "contains" and str(value).lower() in str(ep_val).lower():
                violated = True

            if violated:
                actual_value = Redactor.redact_text(str(ep_val))
                expected = Redactor.redact_text(f"{op} {value}")
                message = Redactor.redact_text(f"Rule '{rule.name}' violated for {ep.method} {ep.path}")
                violation = PolicyViolation(
                    account_id=account_id,
                    rule_id=rule.id,
                    endpoint_id=ep.id,
                    rule_type=rule.rule_type,
                    severity="MEDIUM",
                    message=message,
                    violation_metadata={
                        "field": field,
                        "actual_value": actual_value,
                        "expected": expected,
                    },
                )
                db.add(violation)
                violations.append({
                    "rule_id": rule.id,
                    "rule_name": Redactor.redact_text(rule.name),
                    "rule_type": rule.rule_type,
                    "action": rule.action,
                    "endpoint_id": ep.id,
                    "endpoint": Redactor.redact_text(f"{ep.method} {ep.host}{ep.path}"),
                    "field": field,
                    "actual_value": actual_value,
                    "expected": expected,
                })
                rule.violation_count = (rule.violation_count or 0) + 1

    await db.commit()
    await log_action(
        db=db,
        account_id=account_id,
        action="POLICY_SCAN",
        user_id=payload.get("user_id"),
        resource_type="governance_rule",
        details={"rules_applied": len(rules), "violations_found": len(violations)},
    )
    await db.commit()
    return {
        "total_endpoints_scanned": len(endpoints),
        "total_rules_applied": len(rules),
        "violations_found": len(violations),
        "violations": violations,
    }


@router.get("/violations")
async def list_policy_violations(
    payload: dict = Depends(RBAC.require_permission(Permission.COMPLIANCE_READ)),
    db: AsyncSession = Depends(get_db),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, le=500),
    status: str | None = Query(None, description="Filter by violation status, e.g. OPEN"),
):
    account_id = payload.get("account_id")
    filters = [PolicyViolation.account_id == account_id]
    if status:
        filters.append(PolicyViolation.status == status.upper())

    total = await db.scalar(
        select(func.count()).select_from(PolicyViolation).where(and_(*filters))
    )
    result = await db.execute(
        select(PolicyViolation)
        .where(and_(*filters))
        .order_by(PolicyViolation.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    violations = result.scalars().all()

    endpoint_ids = sorted({v.endpoint_id for v in violations if v.endpoint_id})
    endpoints_by_id: dict[str, APIEndpoint] = {}
    if endpoint_ids:
        eps_result = await db.execute(
            select(APIEndpoint).where(APIEndpoint.id.in_(endpoint_ids))
        )
        endpoints_by_id = {ep.id: ep for ep in eps_result.scalars().all()}

    return {
        "total": total or 0,
        "violations": [
            _serialize_violation(v, endpoint=endpoints_by_id.get(v.endpoint_id))
            for v in violations
        ],
    }


@router.get("/scan/builtin")
async def scan_builtin(
    payload: dict = Depends(RBAC.require_permission(Permission.COMPLIANCE_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Run built-in governance checks (no configuration needed)."""
    account_id = payload.get("account_id")
    eps_result = await db.execute(
        select(APIEndpoint).where(APIEndpoint.account_id == account_id).limit(500)
    )
    endpoints = eps_result.scalars().all()

    violations = []
    for check in _BUILTIN_CHECKS:
        cond = check["condition"]
        path_filter = check.get("path_contains", [])
        for ep in endpoints:
            if path_filter and not any(p in (ep.path or "") for p in path_filter):
                continue
            ep_val = getattr(ep, cond["field"], None)
            if ep_val is None:
                continue
            violated = False
            if cond["op"] == "eq" and str(ep_val).upper() == str(cond["value"]).upper():
                violated = True
            elif cond["op"] == "neq" and str(ep_val).lower() == str(cond["value"]).lower():
                violated = True
            elif cond["op"] == "has_uppercase" and str(ep_val) != str(ep_val).lower():
                violated = True
            if violated:
                violations.append({
                    "check": check["name"],
                    "rule_type": check["rule_type"],
                    "endpoint": Redactor.redact_text(f"{ep.method} {ep.host}{ep.path}"),
                    "endpoint_id": ep.id,
                })

    return {"violations": violations, "total": len(violations)}


def _serialize_rule(rule: GovernanceRule) -> dict:
    return {
        "id": rule.id,
        "name": Redactor.redact_text(rule.name or ""),
        "description": Redactor.redact_text(rule.description or "") if rule.description else None,
        "rule_type": rule.rule_type,
        "condition": Redactor.redact_json(rule.condition or {}),
        "action": rule.action,
        "enabled": rule.enabled,
        "violation_count": rule.violation_count,
        "created_at": str(rule.created_at),
    }


def _serialize_violation(violation: PolicyViolation, *, endpoint: APIEndpoint | None = None) -> dict:
    timestamp = int(violation.created_at.timestamp()) if violation.created_at else 0
    return {
        "id": violation.id,
        "rule_id": violation.rule_id,
        "endpoint_id": violation.endpoint_id,
        "rule_type": violation.rule_type,
        "severity": violation.severity,
        "status": violation.status,
        "message": Redactor.redact_text(violation.message or "") if violation.message else None,
        "created_at": str(violation.created_at),
        # Event-table fields for the governance dashboard: endpoint method/url
        # (joined, since PolicyViolation only stores endpoint_id), epoch
        # timestamp, and a short display id distinct from the full row id.
        "method": endpoint.method if endpoint else None,
        "url": Redactor.redact_url(f"{endpoint.host or ''}{endpoint.path or ''}") if endpoint else None,
        "timestamp": timestamp,
        "subCategory": violation.rule_type,
        "description": Redactor.redact_text(violation.message or "") if violation.message else None,
        "eventId": violation.id[:8] if violation.id else None,
    }
