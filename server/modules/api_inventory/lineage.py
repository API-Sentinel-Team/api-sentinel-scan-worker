"""Unified lineage view for an API endpoint."""

from __future__ import annotations

from typing import Any

from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import (
    APIEndpoint,
    EndpointRevision,
    EvidenceRecord,
    NucleiScan,
    OpenAPISpec,
    PolicyViolation,
    SourceCodeFinding,
    TestResult,
    Vulnerability,
)
from server.modules.utils.finding_fingerprint import (
    nuclei_fingerprint,
    source_finding_fingerprint,
    vulnerability_fingerprint,
)


class EndpointLineageService:
    async def build(
        self,
        db: AsyncSession,
        *,
        account_id: int,
        endpoint_id: str,
        limit: int = 10,
    ) -> dict[str, Any]:
        endpoint_result = await db.execute(
            select(APIEndpoint).where(
                and_(APIEndpoint.id == endpoint_id, APIEndpoint.account_id == account_id)
            )
        )
        endpoint = endpoint_result.scalar_one_or_none()
        if not endpoint:
            raise LookupError("Endpoint not found")

        revisions = (
            await db.execute(
                select(EndpointRevision)
                .where(
                    EndpointRevision.endpoint_id == endpoint_id,
                    EndpointRevision.account_id == account_id,
                )
                .order_by(EndpointRevision.created_at.desc())
                .limit(limit)
            )
        ).scalars().all()

        vulnerabilities = (
            await db.execute(
                select(Vulnerability)
                .where(
                    Vulnerability.account_id == account_id,
                    Vulnerability.endpoint_id == endpoint_id,
                )
                .order_by(Vulnerability.created_at.desc())
                .limit(limit)
            )
        ).scalars().all()

        policy_violations = (
            await db.execute(
                select(PolicyViolation)
                .where(
                    PolicyViolation.account_id == account_id,
                    PolicyViolation.endpoint_id == endpoint_id,
                )
                .order_by(PolicyViolation.created_at.desc())
                .limit(limit)
            )
        ).scalars().all()

        evidence_records = (
            await db.execute(
                select(EvidenceRecord)
                .where(
                    EvidenceRecord.account_id == account_id,
                    EvidenceRecord.endpoint_id == endpoint_id,
                )
                .order_by(EvidenceRecord.created_at.desc())
                .limit(limit)
            )
        ).scalars().all()

        test_results = (
            await db.execute(
                select(TestResult)
                .where(TestResult.endpoint_id == endpoint_id)
                .order_by(TestResult.created_at.desc())
                .limit(limit)
            )
        ).scalars().all()

        source_findings = (
            await db.execute(
                select(SourceCodeFinding)
                .where(
                    SourceCodeFinding.account_id == account_id,
                    SourceCodeFinding.endpoint_id == endpoint_id,
                )
                .order_by(SourceCodeFinding.created_at.desc())
                .limit(limit)
            )
        ).scalars().all()

        latest_spec = (
            await db.execute(
                select(OpenAPISpec)
                .where(OpenAPISpec.account_id == account_id)
                .order_by(OpenAPISpec.created_at.desc())
                .limit(1)
            )
        ).scalar_one_or_none()
        documentation = self._documentation_status(endpoint, latest_spec)

        nuclei_matches = await self._find_nuclei_matches(
            db,
            account_id=account_id,
            endpoint=endpoint,
            limit=limit,
        )

        activity = self._build_activity_timeline(
            revisions,
            vulnerabilities,
            policy_violations,
            evidence_records,
            test_results,
            source_findings,
            nuclei_matches,
        )

        return {
            "endpoint": {
                "id": endpoint.id,
                "method": endpoint.method,
                "path": endpoint.path,
                "path_pattern": endpoint.path_pattern,
                "host": endpoint.host,
                "protocol": endpoint.protocol,
                "risk_score": endpoint.risk_score,
                "status": endpoint.status,
                "last_seen": endpoint.last_seen.isoformat() if endpoint.last_seen else None,
            },
            "summary": {
                "revision_count": len(revisions),
                "vulnerability_count": len(vulnerabilities),
                "policy_violation_count": len(policy_violations),
                "evidence_count": len(evidence_records),
                "test_result_count": len(test_results),
                "source_finding_count": len(source_findings),
                "nuclei_match_count": len(nuclei_matches),
                "documented_in_latest_openapi": documentation["documented"],
            },
            "documentation": documentation,
            "revisions": [
                {
                    "id": rev.id,
                    "version_hash": rev.version_hash,
                    "created_at": rev.created_at.isoformat() if rev.created_at else None,
                }
                for rev in revisions
            ],
            "vulnerabilities": [
                {
                    "id": vuln.id,
                    "type": vuln.type,
                    "template_id": vuln.template_id,
                    "severity": vuln.severity,
                    "status": vuln.status,
                    "created_at": vuln.created_at.isoformat() if vuln.created_at else None,
                    "fingerprint": vulnerability_fingerprint(vuln),
                }
                for vuln in vulnerabilities
            ],
            "policy_violations": [
                {
                    "id": violation.id,
                    "rule_type": violation.rule_type,
                    "severity": violation.severity,
                    "status": violation.status,
                    "message": violation.message,
                    "created_at": violation.created_at.isoformat() if violation.created_at else None,
                }
                for violation in policy_violations
            ],
            "evidence": [
                {
                    "id": evidence.id,
                    "type": evidence.evidence_type,
                    "severity": evidence.severity,
                    "summary": evidence.summary,
                    "created_at": evidence.created_at.isoformat() if evidence.created_at else None,
                }
                for evidence in evidence_records
            ],
            "test_results": [
                {
                    "id": result.id,
                    "template_id": result.template_id,
                    "is_vulnerable": result.is_vulnerable,
                    "severity": result.severity,
                    "evidence": result.evidence,
                    "created_at": result.created_at.isoformat() if result.created_at else None,
                }
                for result in test_results
            ],
            "source_findings": [
                {
                    "id": finding.id,
                    "repo_id": finding.repo_id,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "finding_type": finding.finding_type,
                    "severity": finding.severity,
                    "title": finding.title,
                    "status": finding.status,
                    "created_at": finding.created_at.isoformat() if finding.created_at else None,
                    "fingerprint": source_finding_fingerprint(finding),
                }
                for finding in source_findings
            ],
            "nuclei": nuclei_matches,
            "activity": activity[: max(limit * 3, 10)],
        }

    def _documentation_status(self, endpoint: APIEndpoint, latest_spec: OpenAPISpec | None) -> dict[str, Any]:
        if not latest_spec:
            return {"documented": False, "status": "missing_spec", "spec_id": None}
        paths = (latest_spec.spec_json or {}).get("paths", {}) or {}
        path_entry = paths.get(endpoint.path or "") or paths.get(endpoint.path_pattern or "")
        method_entry = path_entry.get((endpoint.method or "").lower()) if isinstance(path_entry, dict) else None
        return {
            "documented": bool(method_entry),
            "status": "documented" if method_entry else "shadow",
            "spec_id": latest_spec.id,
            "spec_version": latest_spec.version,
        }

    async def _find_nuclei_matches(
        self,
        db: AsyncSession,
        *,
        account_id: int,
        endpoint: APIEndpoint,
        limit: int,
    ) -> list[dict[str, Any]]:
        scans = (
            await db.execute(
                select(NucleiScan)
                .where(NucleiScan.account_id == account_id)
                .order_by(NucleiScan.created_at.desc())
                .limit(limit)
            )
        ).scalars().all()
        matches: list[dict[str, Any]] = []
        for scan in scans:
            for finding in scan.findings or []:
                if not self._matches_endpoint(endpoint, finding):
                    continue
                matches.append(
                    {
                        "scan_id": scan.id,
                        "status": scan.status,
                        "template_id": finding.get("template-id"),
                        "name": finding.get("name"),
                        "severity": finding.get("severity"),
                        "matched_at": finding.get("matched-at"),
                        "fingerprint": nuclei_fingerprint(
                            finding,
                            target=scan.target,
                            account_id=account_id,
                        ),
                        "created_at": scan.created_at.isoformat() if scan.created_at else None,
                    }
                )
        return matches[:limit]

    def _matches_endpoint(self, endpoint: APIEndpoint, finding: dict[str, Any]) -> bool:
        location = " ".join(
            str(finding.get(key, ""))
            for key in ("matched-at", "host", "url")
        ).lower()
        host = (endpoint.host or "").lower()
        path = (endpoint.path or endpoint.path_pattern or "").lower()
        return bool(location and path and path in location and (not host or host in location))

    def _build_activity_timeline(self, *collections: list[Any]) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for collection in collections:
            for item in collection:
                if isinstance(item, dict):
                    created_at = item.get("created_at")
                    events.append(
                        {
                            "created_at": created_at,
                            "type": item.get("template_id") or item.get("type") or "nuclei",
                            "summary": item.get("name") or item.get("summary") or item.get("message"),
                        }
                    )
                    continue
                created_at = getattr(item, "created_at", None)
                events.append(
                    {
                        "created_at": created_at.isoformat() if created_at else None,
                        "type": item.__class__.__name__,
                        "summary": getattr(item, "title", None)
                        or getattr(item, "message", None)
                        or getattr(item, "summary", None)
                        or getattr(item, "version_hash", None),
                    }
                )
        events.sort(key=lambda entry: entry.get("created_at") or "", reverse=True)
        return events
