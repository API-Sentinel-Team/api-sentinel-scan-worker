"""PII detection router — scan endpoints and sample data for sensitive information."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from server.modules.persistence.database import get_db, get_read_db
from server.modules.vulnerability_detector.pii_scanner import PIIScanner
from server.models.core import SampleData, APIEndpoint, SensitiveDataFinding
from server.modules.auth.rbac import RBAC

router = APIRouter()
_scanner = PIIScanner()

_PII_SEVERITY = {
    "SSN": "critical",
    "CREDIT_CARD": "critical",
    "PASSWORD_HASH": "high",
    "JWT_TOKEN": "high",
    "API_KEY": "high",
    "EMAIL": "medium",
    "PHONE_NUMBER": "medium",
}

_PII_REGULATIONS = {
    "SSN": ["GDPR", "HIPAA"],
    "CREDIT_CARD": ["PCI-DSS"],
    "PASSWORD_HASH": ["SOC2"],
    "JWT_TOKEN": ["SOC2"],
    "API_KEY": ["SOC2"],
    "EMAIL": ["GDPR"],
    "PHONE_NUMBER": ["GDPR", "CCPA"],
}


def _pii_severity(entity_type: str | None) -> str:
    return _PII_SEVERITY.get((entity_type or "").upper(), "medium")


def _pii_regulations(entity_type: str | None) -> list[str]:
    return _PII_REGULATIONS.get((entity_type or "").upper(), ["GDPR"])


@router.get("/")
async def get_pii_findings(
    endpoint_id: str = Query(None),
    limit: int = Query(50),
    db: AsyncSession = Depends(get_read_db),
    payload: dict = Depends(RBAC.require_auth),
):
    """Return persisted PII findings (fast path)."""
    account_id = payload.get("account_id")
    query = select(SensitiveDataFinding).where(SensitiveDataFinding.account_id == account_id).limit(limit)
    if endpoint_id:
        query = query.where(SensitiveDataFinding.endpoint_id == endpoint_id)
    result = await db.execute(query)
    findings = result.scalars().all()
    return {
        "total": len(findings),
        "findings": [
            {
                "endpoint_id": f.endpoint_id,
                "entity_type": f.entity_type,
                "source": f.source,
                "sample_value": f.sample_value,
                "created_at": str(f.created_at),
            }
            for f in findings
        ],
    }


@router.get("/findings")
async def get_pii_findings_enriched(
    endpoint_id: str = Query(None),
    limit: int = Query(50),
    db: AsyncSession = Depends(get_read_db),
    payload: dict = Depends(RBAC.require_auth),
):
    """Return persisted PII findings in the richer shape expected by the customer UI."""
    account_id = payload.get("account_id")
    query = (
        select(SensitiveDataFinding)
        .where(SensitiveDataFinding.account_id == account_id)
        .order_by(SensitiveDataFinding.created_at.desc())
        .limit(limit)
    )
    if endpoint_id:
        query = query.where(SensitiveDataFinding.endpoint_id == endpoint_id)

    result = await db.execute(query)
    findings = result.scalars().all()

    endpoint_map: dict[str, APIEndpoint] = {}
    endpoint_ids = [finding.endpoint_id for finding in findings if finding.endpoint_id]
    if endpoint_ids:
        endpoint_rows = await db.execute(
            select(APIEndpoint).where(
                APIEndpoint.account_id == account_id,
                APIEndpoint.id.in_(endpoint_ids),
            )
        )
        endpoint_map = {endpoint.id: endpoint for endpoint in endpoint_rows.scalars().all()}

    return {
        "total": len(findings),
        "findings": [
            {
                "id": finding.id,
                "endpoint": (
                    endpoint_map[finding.endpoint_id].path_pattern
                    or endpoint_map[finding.endpoint_id].path
                ) if finding.endpoint_id in endpoint_map else (finding.endpoint_id or "Unknown endpoint"),
                "method": endpoint_map[finding.endpoint_id].method if finding.endpoint_id in endpoint_map else "GET",
                "location": finding.source or "response",
                "data_type": finding.entity_type or "UNKNOWN",
                "field_path": "payload",
                "sample_masked": finding.sample_value or "[redacted]",
                "severity": _pii_severity(finding.entity_type),
                "occurrences": 1,
                "last_seen": finding.created_at.isoformat() if finding.created_at else None,
                "encrypted": False,
                "regulations": _pii_regulations(finding.entity_type),
            }
            for finding in findings
        ],
    }


@router.post("/scan-endpoint")
async def scan_endpoint(
    endpoint_id: str,
    db: AsyncSession = Depends(get_db),
    payload: dict = Depends(RBAC.require_auth),
):
    """Scan all captured traffic for a specific endpoint for PII."""
    account_id = payload.get("account_id")
    result = await db.execute(
        select(SampleData).where(
            SampleData.endpoint_id == endpoint_id,
            SampleData.account_id == account_id,
        )
    )
    samples = result.scalars().all()

    findings = []
    for sample in samples:
        for source, payload_body in [("response", (sample.response or {}).get("body", "")),
                                     ("request", (sample.request or {}).get("body", ""))]:
            for f in _scanner.scan_payload(payload_body):
                findings.append({"source": source, "sample_id": sample.id, **f})

    return {
        "endpoint_id": endpoint_id,
        "samples_scanned": len(samples),
        "findings": findings,
        "has_pii": len(findings) > 0,
    }


@router.post("/scan-text")
async def scan_text(text: str, payload: dict = Depends(RBAC.require_auth)):
    """Scan arbitrary text for PII patterns."""
    findings = _scanner.scan_string(text)
    return {"findings": findings, "has_pii": len(findings) > 0}
