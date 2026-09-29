"""External recon ingestion and shadow API detection."""
from __future__ import annotations

from typing import Iterable, Dict, Any, Tuple
from urllib.parse import urlparse
import datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.models.core import APIEndpoint, ExternalReconFinding
from server.modules.api_inventory.path_normalizer import PathNormalizer
from sqlalchemy import select
from server.models.core import EvidenceRecord, PolicyViolation


class ReconProcessor:
    def __init__(self) -> None:
        self.normalizer = PathNormalizer()

    def _parse_url(self, raw_url: str) -> Tuple[str, str, str]:
        parsed = urlparse(raw_url)
        host = parsed.netloc or parsed.hostname or ""
        path = parsed.path or "/"
        return parsed.scheme or "https", host, path

    async def ingest(
        self,
        db: AsyncSession,
        account_id: int,
        source: str,
        items: Iterable[Dict[str, Any]],
    ) -> Dict[str, int]:
        created = 0
        updated = 0
        confirmed = 0
        now = datetime.datetime.now(datetime.timezone.utc)

        for item in items:
            url = (item.get("url") or "").strip()
            if not url:
                continue
            method = (item.get("method") or "GET").upper()
            confidence = float(item.get("confidence") or 0.5)
            scheme, host, path = self._parse_url(url)
            if not host:
                continue
            path_pattern = self.normalizer.normalize(path)

            # Check inventory match
            endpoint = await db.scalar(
                select(APIEndpoint).where(
                    APIEndpoint.account_id == account_id,
                    APIEndpoint.method == method,
                    APIEndpoint.host == host,
                    APIEndpoint.path_pattern == path_pattern,
                )
            )

            finding = await db.scalar(
                select(ExternalReconFinding).where(
                    ExternalReconFinding.account_id == account_id,
                    ExternalReconFinding.source == source,
                    ExternalReconFinding.method == method,
                    ExternalReconFinding.host == host,
                    ExternalReconFinding.path_pattern == path_pattern,
                )
            )

            if finding:
                finding.url = url
                finding.path = path
                finding.confidence = max(finding.confidence or 0.0, confidence)
                finding.last_seen_at = now
                updated += 1
            else:
                finding = ExternalReconFinding(
                    account_id=account_id,
                    source=source,
                    method=method,
                    url=url,
                    host=host,
                    path=path,
                    path_pattern=path_pattern,
                    confidence=confidence,
                    status="NEW",
                )
                db.add(finding)
                created += 1

            if endpoint:
                finding.status = "CONFIRMED"
                finding.endpoint_id = endpoint.id
                confirmed += 1
                # resolve shadow violation if it exists
                await db.execute(
                    PolicyViolation.__table__.update()
                    .where(
                        PolicyViolation.account_id == account_id,
                        PolicyViolation.endpoint_id == endpoint.id,
                        PolicyViolation.rule_type == "SHADOW_ENDPOINT",
                        PolicyViolation.status == "OPEN",
                    )
                    .values(status="RESOLVED")
                )
            else:
                # Mark as shadow candidate in inventory if not present
                if not endpoint:
                    tags = {
                        "shadow_candidate": True,
                        "recon": {"source": source, "confidence": confidence},
                    }
                    endpoint = APIEndpoint(
                        account_id=account_id,
                        method=method,
                        host=host,
                        path=path,
                        path_pattern=path_pattern,
                        protocol=scheme.upper(),
                        access_type="PUBLIC",
                        status="SHADOW",
                        description="External recon discovery",
                        tags=tags,
                        last_seen=now,
                    )
                    db.add(endpoint)
                    db.add(EvidenceRecord(
                        account_id=account_id,
                        evidence_type="recon",
                        ref_id=endpoint.id,
                        endpoint_id=endpoint.id,
                        severity="HIGH",
                        summary="Shadow endpoint detected via external recon",
                        details={
                            "source": source,
                            "url": url,
                            "method": method,
                            "host": host,
                            "path": path,
                            "path_pattern": path_pattern,
                            "confidence": confidence,
                        },
                    ))
                    # Create policy violation if not already open
                    existing = await db.scalar(
                        select(PolicyViolation).where(
                            PolicyViolation.account_id == account_id,
                            PolicyViolation.endpoint_id == endpoint.id,
                            PolicyViolation.rule_type == "SHADOW_ENDPOINT",
                            PolicyViolation.status == "OPEN",
                        )
                    )
                    if not existing:
                        db.add(PolicyViolation(
                            account_id=account_id,
                            endpoint_id=endpoint.id,
                            rule_type="SHADOW_ENDPOINT",
                            severity="HIGH",
                            status="OPEN",
                            message="Shadow endpoint discovered via external recon",
                            violation_metadata={
                                "source": source,
                                "url": url,
                                "confidence": confidence,
                            },
                        ))

        return {"created": created, "updated": updated, "confirmed": confirmed}
