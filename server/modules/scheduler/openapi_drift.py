"""OpenAPI drift processor — auto-generates and diffs the API spec.

Periodically regenerates the OpenAPI spec from discovered endpoints
(``OpenAPIGenerator``) and diffs it against the last stored version
(``OpenAPIDiffAnalyzer``). On drift, persists a new ``OpenAPISpec`` version
and raises a ``PolicyViolation`` + ``Alert`` + ``EvidenceRecord`` per changed
item, using the analyzer's own severity/message/recommendation output.

Gated by ``OPENAPI_DRIFT_ENABLED`` (default off). Mirrors the shape of
``server.modules.scheduler.continuous_testing.ContinuousTestingProcessor``.
"""
from __future__ import annotations

import asyncio

import structlog
from sqlalchemy import select

from server.config import settings
from server.models.core import APIEndpoint
from server.modules.api_inventory.openapi_diff import OpenAPIDiffAnalyzer
from server.modules.api_inventory.openapi_generator import OpenAPIGenerator
from server.modules.persistence.database import AsyncSessionLocal

logger = structlog.get_logger(__name__)


class OpenAPIDriftProcessor:
    def __init__(self, interval_sec: int | None = None) -> None:
        self.interval = interval_sec or settings.OPENAPI_DRIFT_SWEEP_INTERVAL_SECONDS
        self._running = False
        self._task: asyncio.Task | None = None
        self._gen = OpenAPIGenerator()
        self._diff = OpenAPIDiffAnalyzer()

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._loop())

    async def stop(self) -> None:
        self._running = False
        task = self._task
        self._task = None
        if task:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def _loop(self) -> None:
        try:
            while self._running:
                try:
                    await self.sweep()
                except Exception as exc:  # never let the loop die
                    logger.error("openapi_drift_sweep_error", error=str(exc))
                await asyncio.sleep(self.interval)
        except asyncio.CancelledError:
            logger.info("openapi_drift_loop_cancelled")

    async def sweep(self) -> dict:
        """Check every account with discovered endpoints for spec drift."""
        if not settings.OPENAPI_DRIFT_ENABLED:
            return {"status": "disabled"}

        account_ids = await self._accounts_with_endpoints()
        checked = 0
        drifted = 0
        for account_id in account_ids:
            checked += 1
            try:
                result = await self._check_account(account_id)
            except Exception as exc:  # one bad account must not stop the sweep
                logger.error(
                    "openapi_drift_check_error", account_id=account_id, error=str(exc)
                )
                continue
            if result.get("status") == "drifted":
                drifted += 1

        logger.info(
            "openapi_drift_sweep", accounts_checked=checked, accounts_drifted=drifted
        )
        return {"status": "ok", "accounts_checked": checked, "accounts_drifted": drifted}

    async def _check_account(self, account_id: int) -> dict:
        async with AsyncSessionLocal() as db:
            result = await self._check_account_with_session(db, account_id)
            await db.commit()
            return result

    async def _check_account_with_session(self, db, account_id: int) -> dict:
        new_spec = await self._gen.generate_spec(
            collection_name="Discovered API", account_id=account_id
        )
        previous = await self._get_previous_spec(db, account_id)

        if previous is None:
            await self._persist_spec_version(db, account_id, new_spec)
            return {"status": "baseline"}

        if previous.spec_json == new_spec:
            return {"status": "unchanged"}

        previous_paths = previous.spec_json.get("paths") or {}
        new_paths = new_spec.get("paths") or {}
        if previous_paths and not new_paths:
            logger.warning(
                "openapi_drift_degenerate_spec_skipped",
                account_id=account_id,
                previous_path_count=len(previous_paths),
            )
            return {"status": "skipped_degenerate"}

        diff = self._diff.compare(previous.spec_json, new_spec)
        changes = diff["breaking_changes"]
        if not changes:
            # No breaking changes, but the spec did change (checked above) - e.g. a
            # purely additive change like a new endpoint. Keep the stored spec
            # current even though there's nothing alert-worthy to raise.
            await self._persist_spec_version(db, account_id, new_spec)
            return {"status": "unchanged"}

        await self._persist_spec_version(db, account_id, new_spec)
        await self._raise_drift_findings(db, account_id, changes)
        return {"status": "drifted", "change_count": len(changes), "changes": changes}

    @staticmethod
    async def _get_previous_spec(db, account_id: int):
        from server.models.core import OpenAPISpec

        result = await db.execute(
            select(OpenAPISpec)
            .where(OpenAPISpec.account_id == account_id)
            .order_by(OpenAPISpec.created_at.desc())
            .limit(1)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def _persist_spec_version(db, account_id: int, spec_json: dict):
        from server.models.core import OpenAPISpec

        record = OpenAPISpec(account_id=account_id, spec_json=spec_json)
        db.add(record)
        await db.flush()
        return record

    @staticmethod
    async def _accounts_with_endpoints() -> list[int]:
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(APIEndpoint.account_id).distinct())
            return [row for row in result.scalars().all() if row is not None]

    async def _raise_drift_findings(self, db, account_id: int, changes: list[dict]) -> None:
        from server.models.core import PolicyViolation, Alert, EvidenceRecord

        cap = settings.OPENAPI_DRIFT_MAX_FINDINGS_PER_SWEEP
        total_changes = len(changes)
        if total_changes > cap:
            logger.warning(
                "openapi_drift_findings_capped",
                account_id=account_id,
                total_changes=total_changes,
                cap=cap,
            )
        changes = changes[:cap]

        for change in changes:
            endpoint_id = await self._resolve_endpoint_id(
                db, account_id, change["path"], change["method"]
            )

            violation = PolicyViolation(
                account_id=account_id,
                endpoint_id=endpoint_id,
                rule_type="DRIFT",
                severity=change["severity"],
                status="OPEN",
                message=change["message"],
                violation_metadata={
                    "change_id": change["id"],
                    "component": change["component"],
                    "path": change["path"],
                    "method": change["method"],
                    "why_it_matters": change["why_it_matters"],
                    "recommended_action": change["recommended_action"],
                    "fingerprint": change["fingerprint"],
                },
            )
            db.add(violation)

            alert = Alert(
                account_id=account_id,
                title=f"API spec drift: {change['id']} on {change['path']}",
                message=change["message"],
                severity=change["severity"],
                category="API_DRIFT",
                endpoint=change["path"],
                status="OPEN",
            )
            db.add(alert)
            await db.flush()

            db.add(EvidenceRecord(
                account_id=account_id,
                evidence_type="drift",
                ref_id=alert.id,
                endpoint_id=endpoint_id,
                severity=change["severity"],
                summary=change["message"],
                details={
                    "change_id": change["id"],
                    "component": change["component"],
                    "path": change["path"],
                    "method": change["method"],
                    "why_it_matters": change["why_it_matters"],
                    "recommended_action": change["recommended_action"],
                },
            ))

    @staticmethod
    async def _resolve_endpoint_id(db, account_id: int, path: str, method: str | None) -> str | None:
        from server.models.core import APIEndpoint

        result = await db.execute(
            select(APIEndpoint).where(
                APIEndpoint.account_id == account_id,
                APIEndpoint.path == path,
            )
        )
        candidates = result.scalars().all()
        if not candidates:
            return None
        if method is None:
            return candidates[0].id
        for endpoint in candidates:
            if (endpoint.method or "").upper() == method.upper():
                return endpoint.id
        return candidates[0].id
