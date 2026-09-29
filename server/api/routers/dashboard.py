"""Dashboard statistics endpoint — aggregated view of the security posture."""
from datetime import datetime, timedelta, timezone
import re

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from server.modules.persistence.database import get_read_db
from server.models.core import (
    Vulnerability, TestRun, APIEndpoint, RequestLog, WAFEvent, TestResult, PolicyViolation
)
from server.modules.auth.rbac import RBAC
from server.modules.cache.redis_cache import get_cache_version, get_json, set_json
from server.modules.pentest.north_star_readiness import build_north_star_readiness
from server.modules.utils.redactor import Redactor
from server.config import settings

router = APIRouter()
_CLOSED_FINDING_STATUSES = {"CLOSED", "RESOLVED", "FALSE_POSITIVE", "ACCEPTED_RISK"}
_OPEN_POLICY_STATUSES = {"OPEN", "ACTIVE", "FAILING"}
_SEVERITY_WEIGHT = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 5, "LOW": 1, "INFO": 0}
_SECRET_LITERAL_RE = re.compile(r"(?i)\b(raw[-_]?token|bearer\s+[a-z0-9._~+/=-]+)\b")


def _safe_status(value: str | None, default: str = "OPEN") -> str:
    return (value or default).upper()


def _open_finding(vulnerability: Vulnerability) -> bool:
    return _safe_status(vulnerability.status) not in _CLOSED_FINDING_STATUSES


def _finding_category(vulnerability: Vulnerability) -> str | None:
    evidence = vulnerability.evidence if isinstance(vulnerability.evidence, dict) else {}
    category = str(evidence.get("security_category") or "").lower()
    template_id = str(vulnerability.template_id or "").lower()
    finding_type = str(vulnerability.type or "").lower()
    if category == "llm" or evidence.get("llm_judge_validation") or template_id.startswith("llm_") or "llm" in finding_type:
        return "llm"
    if (
        category == "business_logic"
        or template_id.startswith("business-logic")
        or template_id == "active_business_logic"
        or "business_logic" in finding_type
        or "business logic" in finding_type
    ):
        return "business_logic"
    return None


def _coverage_target_available(coverage_targets: object, target: str) -> bool:
    if not isinstance(coverage_targets, dict):
        return False
    metadata = coverage_targets.get(target)
    if not isinstance(metadata, dict):
        return False
    status = str(metadata.get("status") or "").lower()
    return status in {"available", "ready", "partial", "discovered"}


def _sla_counts(vulnerabilities: list[Vulnerability], now: datetime) -> dict[str, int]:
    due_soon_cutoff = now + timedelta(days=7)
    counts = {"overdue": 0, "due_soon": 0, "on_track": 0, "no_sla": 0}
    for vulnerability in vulnerabilities:
        due_at = vulnerability.sla_due_at
        if due_at is None:
            counts["no_sla"] += 1
            continue
        if due_at.tzinfo is None:
            due_at = due_at.replace(tzinfo=timezone.utc)
        if due_at < now:
            counts["overdue"] += 1
        elif due_at <= due_soon_cutoff:
            counts["due_soon"] += 1
        else:
            counts["on_track"] += 1
    return counts


def _risk_score(vulnerabilities: list[Vulnerability], open_policy_violations: int) -> int:
    raw = open_policy_violations * 5
    for vulnerability in vulnerabilities:
        raw += _SEVERITY_WEIGHT.get(_safe_status(vulnerability.severity, default="INFO"), 0)
    return min(100, raw)


def _dashboard_safe_text(value: str | None) -> str:
    return _SECRET_LITERAL_RE.sub(Redactor.REDACT_VALUE, Redactor.redact_text(str(value or "")))


def _vulnerability_trend(vulnerabilities: list[Vulnerability], now: datetime) -> list[dict]:
    days = [(now - timedelta(days=offset)).date() for offset in range(6, -1, -1)]
    counts = {day.isoformat(): 0 for day in days}
    for vulnerability in vulnerabilities:
        created_at = vulnerability.created_at
        if created_at is None:
            continue
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        day_key = created_at.date().isoformat()
        if day_key in counts:
            counts[day_key] += 1
    return [{"date": day, "open_findings": count} for day, count in counts.items()]


def _top_endpoint_risk(
    vulnerabilities: list[Vulnerability],
    endpoints: list[APIEndpoint],
) -> list[dict]:
    endpoints_by_id = {str(endpoint.id): endpoint for endpoint in endpoints}
    severity_by_endpoint: dict[str, dict[str, int]] = {}
    for vulnerability in vulnerabilities:
        if not vulnerability.endpoint_id:
            continue
        endpoint_counts = severity_by_endpoint.setdefault(str(vulnerability.endpoint_id), {})
        severity = _safe_status(vulnerability.severity, default="INFO")
        endpoint_counts[severity] = endpoint_counts.get(severity, 0) + 1

    rows = []
    for endpoint_id, severity_counts in severity_by_endpoint.items():
        endpoint = endpoints_by_id.get(endpoint_id)
        weighted_findings = sum(_SEVERITY_WEIGHT.get(severity, 0) * count for severity, count in severity_counts.items())
        endpoint_risk = min(100, int((getattr(endpoint, "risk_score", 0) or 0) + weighted_findings))
        rows.append(
            {
                "endpoint_id": endpoint_id,
                "method": Redactor.redact_text(getattr(endpoint, "method", None) or "UNKNOWN") if endpoint else "UNKNOWN",
                "path": Redactor.redact_url(getattr(endpoint, "path", None) or getattr(endpoint, "path_pattern", None) or "/")
                if endpoint
                else "/",
                "risk_score": endpoint_risk,
                "open_findings": sum(severity_counts.values()),
                "severity_counts": severity_counts,
            }
        )
    rows.sort(key=lambda row: (row["risk_score"], row["open_findings"]), reverse=True)
    return rows[:5]


def _governance_release_reports(
    *,
    executive: dict,
    sla: dict,
    top_endpoint_risk: list[dict],
    vulnerability_trend: list[dict],
    north_star_readiness: dict,
    engine_plan: list,
) -> dict:
    blocker_count = len(north_star_readiness.get("production_blockers") or [])
    owner_count = len(north_star_readiness.get("p1_workstreams") or [])
    top_endpoint = top_endpoint_risk[0] if top_endpoint_risk else None
    latest_trend = vulnerability_trend[-1] if vulnerability_trend else None
    deterministic_count = sum(
        1
        for item in north_star_readiness.get("p1_workstreams") or []
        if isinstance(item, dict) and item.get("evidence_status") == "deterministic"
    )
    sla_health = (
        f"{int(sla.get('overdue') or 0)} overdue / "
        f"{int(sla.get('due_soon') or 0)} due soon / "
        f"{int(sla.get('on_track') or 0)} on track"
    )
    return {
        "executive_summary": {
            "readiness_statement": (
                f"{int(executive.get('open_findings') or 0)} open findings with "
                f"{blocker_count} production blockers."
            ),
            "blocker_summary": f"{blocker_count} North Star production blockers remain.",
            "owner_summary": f"{owner_count} P1 workstream owners tracked.",
            "evidence_status": f"{deterministic_count} P1 workstreams have deterministic evidence.",
            "sla_health": sla_health,
        },
        "technical_report": {
            "evidence_status": (
                f"{deterministic_count} deterministic P1 workstreams; "
                f"{blocker_count} production blockers require evidence or control closure."
            ),
            "sla_health": sla_health,
            "endpoint_risk": (
                f"{top_endpoint.get('method')} {top_endpoint.get('path')} "
                f"carries risk {int(top_endpoint.get('risk_score') or 0)}."
                if isinstance(top_endpoint, dict)
                else "No active endpoint risk."
            ),
            "trend_summary": (
                f"{int(latest_trend.get('open_findings') or 0)} open findings on {latest_trend.get('date')}."
                if isinstance(latest_trend, dict)
                else "No trend samples."
            ),
            "artifact_status": f"{len(engine_plan or [])} engine accountability entries in latest scan plan.",
        },
    }


@router.get("/")
async def get_dashboard(
    db: AsyncSession = Depends(get_read_db),
    payload: dict = Depends(RBAC.require_auth),
):
    """Returns all dashboard statistics in a single call."""
    account_id = payload.get("account_id")
    cache_version = await get_cache_version(account_id)
    cache_key = f"dashboard:{account_id}:{cache_version}"
    cached = await get_json(cache_key)
    if cached:
        return cached

    # Total endpoints
    ep_count = await db.scalar(
        select(func.count(APIEndpoint.id)).where(APIEndpoint.account_id == account_id)
    ) or 0

    # Vulnerabilities by severity
    vuln_by_severity = await db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .where(Vulnerability.account_id == account_id, Vulnerability.status == "OPEN")
        .group_by(Vulnerability.severity)
    )
    severity_counts = {row[0]: row[1] for row in vuln_by_severity.all()}
    total_open_vulns = sum(severity_counts.values())

    # Vulnerabilities by type
    vuln_by_type = await db.execute(
        select(Vulnerability.type, func.count(Vulnerability.id))
        .where(Vulnerability.account_id == account_id, Vulnerability.status == "OPEN")
        .group_by(Vulnerability.type)
        .order_by(func.count(Vulnerability.id).desc())
        .limit(10)
    )
    type_counts = [{"type": row[0], "count": row[1]} for row in vuln_by_type.all()]

    # Recent test runs
    recent_runs = await db.execute(
        select(TestRun)
        .where(TestRun.account_id == account_id)
        .order_by(desc(TestRun.created_at))
        .limit(5)
    )
    runs = [
        {"id": r.id, "status": r.status, "vulnerable_count": r.vulnerable_count,
         "total_tests": r.total_tests, "created_at": str(r.created_at)}
        for r in recent_runs.scalars().all()
    ]

    # WAF events last 24h
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=24)
    waf_count = await db.scalar(
        select(func.count(WAFEvent.id)).where(
            WAFEvent.account_id == account_id,
            WAFEvent.created_at >= cutoff,
        )
    ) or 0

    # Request volume last hour
    hour_ago = now - timedelta(hours=1)
    req_count = await db.scalar(
        select(func.count(RequestLog.id)).where(
            RequestLog.account_id == account_id,
            RequestLog.created_at >= hour_ago,
        )
    ) or 0

    # Risk score summary
    critical = severity_counts.get("CRITICAL", 0)
    high = severity_counts.get("HIGH", 0)
    medium = severity_counts.get("MEDIUM", 0)
    risk_score = min(100, critical * 20 + high * 10 + medium * 3)

    response = {
        "account_id": account_id,
        "summary": {
            "total_endpoints": ep_count,
            "total_open_vulnerabilities": total_open_vulns,
            "risk_score": risk_score,
            "waf_events_24h": waf_count,
            "requests_last_hour": req_count,
        },
        "vulnerabilities_by_severity": {
            "CRITICAL": severity_counts.get("CRITICAL", 0),
            "HIGH": severity_counts.get("HIGH", 0),
            "MEDIUM": severity_counts.get("MEDIUM", 0),
            "LOW": severity_counts.get("LOW", 0),
        },
        "top_vulnerability_types": type_counts,
        "recent_test_runs": runs,
    }
    await set_json(cache_key, response, ttl_seconds=settings.DASHBOARD_CACHE_TTL)
    return response


@router.get("/governance")
async def get_governance_dashboard(
    db: AsyncSession = Depends(get_read_db),
    payload: dict = Depends(RBAC.require_auth),
):
    """Tenant-scoped executive rollup for release governance and red-team readiness."""
    account_id = payload.get("account_id")
    now = datetime.now(timezone.utc)
    vulnerabilities = (
        await db.execute(
            select(Vulnerability)
            .where(Vulnerability.account_id == account_id)
            .order_by(desc(Vulnerability.created_at))
        )
    ).scalars().all()
    open_vulnerabilities = [vulnerability for vulnerability in vulnerabilities if _open_finding(vulnerability)]

    endpoint_ids = sorted({str(vulnerability.endpoint_id) for vulnerability in open_vulnerabilities if vulnerability.endpoint_id})
    endpoints = []
    if endpoint_ids:
        endpoints = (
            await db.execute(
                select(APIEndpoint).where(
                    APIEndpoint.account_id == account_id,
                    APIEndpoint.id.in_(endpoint_ids),
                )
            )
        ).scalars().all()

    policy_violations = (
        await db.execute(
            select(PolicyViolation)
            .where(PolicyViolation.account_id == account_id)
            .order_by(desc(PolicyViolation.created_at))
        )
    ).scalars().all()
    open_policy_violations = [
        violation for violation in policy_violations if _safe_status(violation.status) in _OPEN_POLICY_STATUSES
    ]

    latest_run = (
        await db.execute(
            select(TestRun)
            .where(TestRun.account_id == account_id)
            .order_by(desc(TestRun.created_at))
            .limit(1)
        )
    ).scalar_one_or_none()

    severity_counts = {}
    llm_active_findings = 0
    business_logic_active_findings = 0
    for vulnerability in open_vulnerabilities:
        severity = _safe_status(vulnerability.severity, default="INFO")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        category = _finding_category(vulnerability)
        if category == "llm":
            llm_active_findings += 1
        elif category == "business_logic":
            business_logic_active_findings += 1

    engine_plan = []
    coverage_targets = {}
    if isinstance(getattr(latest_run, "scan_plan", None), dict):
        engine_plan = latest_run.scan_plan.get("engine_plan") or []
        coverage_targets = latest_run.scan_plan.get("coverage_targets") or {}

    executive = {
        "open_findings": len(open_vulnerabilities),
        "critical_open_findings": severity_counts.get("CRITICAL", 0),
        "high_open_findings": severity_counts.get("HIGH", 0),
        "medium_open_findings": severity_counts.get("MEDIUM", 0),
        "low_open_findings": severity_counts.get("LOW", 0),
        "risk_score": _risk_score(open_vulnerabilities, len(open_policy_violations)),
    }
    sla = _sla_counts(open_vulnerabilities, now)
    top_endpoint_risk = _top_endpoint_risk(open_vulnerabilities, endpoints)
    vulnerability_trend = _vulnerability_trend(open_vulnerabilities, now)
    north_star_readiness = build_north_star_readiness(
        auth_readiness={"authenticated": False, "status": "unknown"},
        engine_plan=engine_plan,
        lifecycle_controls={
            "confirmatory_retests": False,
            "ticketing": any(bool(getattr(item, "ticket_url", None)) for item in vulnerabilities),
            "sla_tracking": True,
        },
        governance_controls={
            "ci_cd_gates": True,
            "audit_logs": True,
            "tenant_isolation": True,
        },
        evidence_controls={
            "reproducible_redacted_evidence": bool(vulnerabilities),
            "evidence_completeness": bool(vulnerabilities),
            "evidence_completeness_gate": True,
        },
        coverage_controls={
            "bola_bfla": _coverage_target_available(coverage_targets, "authorization"),
            "business_logic": (
                business_logic_active_findings > 0
                or _coverage_target_available(coverage_targets, "business_logic")
            ),
            "llm_api": (
                llm_active_findings > 0
                or _coverage_target_available(coverage_targets, "llm_api")
            ),
            "context_aware_selection": bool(coverage_targets),
            "partial_context_aware_selection": bool(coverage_targets),
        },
    )

    response = {
        "account_id": account_id,
        "generated_at": now.isoformat(),
        "executive": executive,
        "sla": sla,
        "coverage": {
            "llm_active_findings": llm_active_findings,
            "business_logic_active_findings": business_logic_active_findings,
            "latest_run_status": getattr(latest_run, "status", None),
            "latest_run_id": getattr(latest_run, "id", None),
            "latest_run_total_tests": getattr(latest_run, "total_tests", 0) if latest_run else 0,
            "latest_run_vulnerable_count": getattr(latest_run, "vulnerable_count", 0) if latest_run else 0,
            "coverage_targets": Redactor.redact_json(coverage_targets),
            "engine_plan": Redactor.redact_json(engine_plan),
        },
        "governance": {
            "open_policy_violations": len(open_policy_violations),
            "latest_policy_pack": "llm-strict" if llm_active_findings else "strict",
            "latest_policy_violation": _dashboard_safe_text(open_policy_violations[0].message)
            if open_policy_violations
                else None,
        },
        "top_endpoint_risk": top_endpoint_risk,
        "vulnerability_trend": vulnerability_trend,
        "north_star_readiness": north_star_readiness,
        "reports": _governance_release_reports(
            executive=executive,
            sla=sla,
            top_endpoint_risk=top_endpoint_risk,
            vulnerability_trend=vulnerability_trend,
            north_star_readiness=north_star_readiness,
            engine_plan=engine_plan,
        ),
    }
    return Redactor.redact_json(response)


@router.get("/activity")
async def get_activity(
    limit: int = 20,
    db: AsyncSession = Depends(get_read_db),
    payload: dict = Depends(RBAC.require_auth),
):
    """Recent activity feed: vulnerabilities + WAF events + test runs."""
    account_id = payload.get("account_id")
    vulns = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.account_id == account_id)
        .order_by(desc(Vulnerability.created_at))
        .limit(limit // 2)
    )
    waf = await db.execute(
        select(WAFEvent)
        .where(WAFEvent.account_id == account_id)
        .order_by(desc(WAFEvent.created_at))
        .limit(limit // 2)
    )

    activity = []
    for v in vulns.scalars().all():
        activity.append({
            "type": "vulnerability",
            "severity": v.severity,
            "message": f"{v.type} found at {v.url}",
            "created_at": str(v.created_at),
        })
    for e in waf.scalars().all():
        activity.append({
            "type": "waf_event",
            "severity": e.severity,
            "message": f"{e.action}: {e.rule_id} from {e.source_ip}",
            "created_at": str(e.created_at),
        })

    activity.sort(key=lambda x: x["created_at"], reverse=True)
    return {"activity": activity[:limit]}
