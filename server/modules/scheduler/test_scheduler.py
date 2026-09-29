"""
APScheduler-based test scheduler for automated security scans.
Stores schedule configs in the test_schedules SQLite table.
"""
import asyncio
import datetime
import uuid

try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.cron import CronTrigger
    APScheduler_AVAILABLE = True
except ImportError:
    APScheduler_AVAILABLE = False

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from server.config import settings
from server.models.core import APIEndpoint, TestRun, TestSchedule
from server.modules.auth.audit import log_action
from server.modules.persistence.database import AsyncSessionLocal
from server.modules.pentest.auth_preflight import (
    ActiveScanAuthError,
    active_scan_auth_audit_context,
    load_profile_and_auth_for_active_scan,
)
from server.modules.pentest.auth_scope import blocked_auth_profile_targets
from server.modules.pentest.target_policy import build_target_guard_policy
from server.modules.test_executor.kill_switch import KILL_SWITCH_REASON, kill_switch_enabled
from server.modules.test_executor.target_guard import blocked_endpoint_targets


class ScheduleValidationError(ValueError):
    """Raised when a scheduled active scan would be unsafe or unrunnable."""

    def __init__(self, reason: str, message: str, *, detail: dict | None = None):
        super().__init__(message)
        self.reason = reason
        self.detail = {"reason": reason, "message": message}
        if detail:
            self.detail.update(detail)


def _blocked_targets_with_policy(blocked_targets: list[dict]) -> list[dict]:
    enriched: list[dict] = []
    for target in blocked_targets:
        target_url = str(target.get("url") or "")
        reason = str(target.get("reason") or "target guard blocked endpoint")
        target_guard_policy = target.get("target_guard_policy")
        if not isinstance(target_guard_policy, dict):
            target_guard_policy = build_target_guard_policy(
                url=target_url,
                base_url=target_url,
                reason=reason,
            )
        enriched.append({**target, "target_guard_policy": target_guard_policy})
    return enriched


class TestScheduler:
    """
    Manages cron-based scheduling of security test runs.
    Falls back gracefully if APScheduler is not installed.
    """

    def __init__(self):
        self._scheduler = None
        if APScheduler_AVAILABLE:
            self._scheduler = AsyncIOScheduler()

    def start(self):
        if self._scheduler:
            self._scheduler.start()
            print("[Scheduler] APScheduler started.")

    def stop(self):
        if self._scheduler and self._scheduler.running:
            self._scheduler.shutdown()

    async def sync_persisted_schedules(self, db: AsyncSession | None = None) -> dict[str, int]:
        """Reconcile APScheduler jobs with the durable schedule table.

        The API may create or toggle schedules while the scheduler runs in a
        separate process.  Re-reading the tenant-scoped rows makes scheduling
        durable across restarts and keeps the API stateless; ``replace_existing``
        makes this safe to call periodically.
        """
        if not self._scheduler:
            return {"enabled": 0, "registered": 0, "removed": 0}

        owns_session = db is None
        session = db or AsyncSessionLocal()
        try:
            result = await session.execute(
                select(TestSchedule).where(TestSchedule.enabled == True)
            )
            enabled = result.scalars().all()
            enabled_ids = {str(row.id) for row in enabled}
            registered = 0
            for row in enabled:
                job = self._scheduler.get_job(str(row.id))
                expected_args = [
                    str(row.id), list(row.template_ids or []), list(row.endpoint_ids or []),
                    int(row.account_id), row.pentest_profile_id,
                ]
                expected_trigger = CronTrigger.from_crontab(str(row.cron_expression))
                if job is not None and list(job.args) == expected_args and str(job.trigger) == str(expected_trigger):
                    continue
                self._register_job(
                    str(row.id),
                    str(row.cron_expression),
                    list(row.template_ids or []),
                    list(row.endpoint_ids or []),
                    int(row.account_id),
                    row.pentest_profile_id,
                )
                registered += 1

            removed = 0
            for job in list(self._scheduler.get_jobs()):
                if str(job.id) not in enabled_ids:
                    self._scheduler.remove_job(job.id)
                    removed += 1
            return {"enabled": len(enabled), "registered": registered, "removed": removed}
        finally:
            if owns_session:
                await session.close()

    async def schedule(
        self,
        name: str,
        cron_expression: str,
        template_ids: list,
        endpoint_ids: list,
        account_id: int,
        db: AsyncSession,
        pentest_profile_id: str | None = None,
    ) -> str:
        """
        Persist a schedule and register with APScheduler.
        cron_expression: e.g. "0 0 * * *" (daily at midnight)
        Returns the schedule id.
        """
        self._validate_cron_expression(cron_expression)
        await self._validate_schedule_plan(
            db,
            template_ids=template_ids,
            endpoint_ids=endpoint_ids,
            account_id=account_id,
            pentest_profile_id=pentest_profile_id,
        )

        schedule_id = str(uuid.uuid4())
        record = TestSchedule(
            id=schedule_id,
            account_id=account_id,
            name=name,
            cron_expression=cron_expression,
            template_ids=template_ids,
            endpoint_ids=endpoint_ids,
            pentest_profile_id=pentest_profile_id,
            enabled=True,
            created_at=datetime.datetime.now(datetime.timezone.utc),
        )
        db.add(record)
        await db.commit()

        self._register_job(
            schedule_id,
            cron_expression,
            template_ids,
            endpoint_ids,
            account_id,
            pentest_profile_id,
        )
        return schedule_id

    def _validate_cron_expression(self, cron_expression: str) -> None:
        parts = str(cron_expression or "").split()
        if len(parts) != 5:
            raise ScheduleValidationError(
                "invalid_cron_expression",
                "Schedule cron expression must contain exactly five fields.",
            )
        if APScheduler_AVAILABLE:
            try:
                CronTrigger(
                    minute=parts[0],
                    hour=parts[1],
                    day=parts[2],
                    month=parts[3],
                    day_of_week=parts[4],
                )
            except Exception as exc:
                raise ScheduleValidationError(
                    "invalid_cron_expression",
                    "Schedule cron expression is not valid.",
                ) from exc

    async def _validate_schedule_plan(
        self,
        db: AsyncSession,
        *,
        template_ids: list,
        endpoint_ids: list,
        account_id: int,
        pentest_profile_id: str | None = None,
    ) -> None:
        planned_count = len(template_ids or []) * len(endpoint_ids or [])
        max_budget = max(1, int(settings.PENTEST_MAX_TESTS_PER_RUN))
        if planned_count > max_budget:
            raise ScheduleValidationError(
                "scan_budget_exceeded",
                (
                    f"Schedule plan has {planned_count} template/endpoint combinations; "
                    f"maximum budget is {max_budget}."
                ),
                detail={"planned_tests": planned_count, "max_tests_per_run": max_budget},
            )

        endpoint_result = await db.execute(
            select(APIEndpoint).where(
                APIEndpoint.id.in_(endpoint_ids),
                APIEndpoint.account_id == account_id,
            )
        )
        endpoints = endpoint_result.scalars().all()
        if len(endpoints) < len(endpoint_ids):
            raise ScheduleValidationError(
                "endpoint_scope_invalid",
                "One or more scheduled endpoints are unavailable for this account.",
            )

        blocked_targets = _blocked_targets_with_policy(blocked_endpoint_targets(endpoints))
        if blocked_targets:
            raise ScheduleValidationError(
                "target_guard_blocked",
                "Pentest target guard blocked one or more scheduled endpoints.",
                detail={"blocked_endpoints": blocked_targets},
            )

        try:
            _, auth_profile = await load_profile_and_auth_for_active_scan(
                db,
                account_id=account_id,
                pentest_profile_id=pentest_profile_id,
            )
        except ActiveScanAuthError as exc:
            raise ScheduleValidationError(
                exc.reason,
                "Scheduled active scans require an auth-ready pentest profile.",
                detail={"auth": exc.detail},
            ) from exc

        blocked_auth_targets = blocked_auth_profile_targets(auth_profile, endpoints)
        if blocked_auth_targets:
            raise ScheduleValidationError(
                "auth_profile_scope_blocked",
                "Auth profile scope blocked one or more scheduled endpoints.",
                detail={"blocked_endpoints": blocked_auth_targets},
            )

    def _register_job(
        self,
        schedule_id: str,
        cron_expr: str,
        template_ids: list,
        endpoint_ids: list,
        account_id: int,
        pentest_profile_id: str | None = None,
    ):
        if not self._scheduler:
            print(f"[Scheduler] APScheduler not available — schedule {schedule_id} not registered.")
            return
        parts = cron_expr.split()
        if len(parts) == 5:
            minute, hour, day, month, day_of_week = parts
        else:
            minute, hour, day, month, day_of_week = "0", "0", "*", "*", "*"

        trigger = CronTrigger(
            minute=minute, hour=hour, day=day,
            month=month, day_of_week=day_of_week,
        )
        self._scheduler.add_job(
            self._trigger_run,
            trigger=trigger,
            id=schedule_id,
            args=[schedule_id, template_ids, endpoint_ids, account_id, pentest_profile_id],
            replace_existing=True,
        )

    async def _trigger_run(
        self,
        schedule_id: str,
        template_ids: list,
        endpoint_ids: list,
        account_id: int,
        pentest_profile_id: str | None = None,
        trigger_source: str = "schedule",
    ):
        """Called by APScheduler — import here to avoid circular imports."""
        if kill_switch_enabled():
            return {
                "status": "blocked",
                "reason": KILL_SWITCH_REASON,
                "schedule_id": schedule_id,
            }

        run_id = str(uuid.uuid4())
        execution_mode = (settings.PENTEST_SCAN_EXECUTION_MODE or "background").strip().lower()
        async with AsyncSessionLocal() as db:
            endpoint_result = await db.execute(
                select(APIEndpoint).where(
                    APIEndpoint.id.in_(endpoint_ids),
                    APIEndpoint.account_id == account_id,
                )
            )
            endpoints = endpoint_result.scalars().all()
            if len(endpoints) < len(endpoint_ids):
                return {
                    "status": "blocked",
                    "reason": "endpoint_scope_invalid",
                    "schedule_id": schedule_id,
                }
            blocked_targets = _blocked_targets_with_policy(blocked_endpoint_targets(endpoints))
            if blocked_targets:
                return {
                    "status": "blocked",
                    "reason": "target_guard_blocked",
                    "schedule_id": schedule_id,
                    "blocked_endpoints": blocked_targets,
                }
            if pentest_profile_id is None:
                schedule = await db.get(TestSchedule, schedule_id)
                if schedule is not None and schedule.account_id == account_id:
                    pentest_profile_id = schedule.pentest_profile_id
            try:
                pentest_profile, auth_profile = await load_profile_and_auth_for_active_scan(
                    db,
                    account_id=account_id,
                    pentest_profile_id=pentest_profile_id,
                )
            except ActiveScanAuthError as exc:
                return {
                    "status": "blocked",
                    "reason": exc.reason,
                    "schedule_id": schedule_id,
                    "detail": exc.detail,
                }
            blocked_auth_targets = blocked_auth_profile_targets(auth_profile, endpoints)
            if blocked_auth_targets:
                return {
                    "status": "blocked",
                    "reason": "auth_profile_scope_blocked",
                    "schedule_id": schedule_id,
                    "blocked_endpoints": blocked_auth_targets,
                }

            is_schedule = trigger_source == "schedule"
            db.add(
                TestRun(
                    id=run_id,
                    account_id=account_id,
                    status="PENDING",
                    template_ids=template_ids,
                    endpoint_ids=endpoint_ids,
                    pentest_profile_id=pentest_profile.id if pentest_profile is not None else None,
                    trigger_source=trigger_source,
                    source_schedule_id=schedule_id if is_schedule else None,
                )
            )
            await log_action(
                db=db,
                account_id=account_id,
                action="SCAN_RUN_QUEUED",
                resource_type="test_run",
                resource_id=run_id,
                details={
                    "source": trigger_source,
                    "schedule_id": schedule_id if is_schedule else None,
                    "source_schedule_id": schedule_id if is_schedule else None,
                    "template_count": len(template_ids or []),
                    "endpoint_count": len(endpoint_ids or []),
                    "planned_tests": len(template_ids or []) * len(endpoint_ids or []),
                    "pentest_profile_id": pentest_profile.id if pentest_profile is not None else None,
                    **active_scan_auth_audit_context(pentest_profile, auth_profile),
                    "execution_mode": execution_mode,
                    "trigger_source": trigger_source,
                },
            )
            await db.commit()

        if execution_mode == "queued":
            return {"status": "queued", "run_id": run_id, "source_schedule_id": schedule_id}

        from server.api.routers.tests import _run_security_tasks

        await _run_security_tasks(
            run_id,
            template_ids,
            endpoint_ids,
            account_id,
            pentest_profile.id if pentest_profile is not None else pentest_profile_id,
        )
        return {"status": "started", "run_id": run_id, "source_schedule_id": schedule_id}

    async def trigger_continuous_discovery_scan(
        self,
        account_id: int,
        *,
        max_endpoints: int | None = None,
        pentest_profile_id: str | None = None,
    ) -> dict:
        """Auto-scan newly-discovered (never-tested) endpoints.

        Closes the Discovery -> Testing pipeline gap. Finds endpoints with no
        ``last_tested`` stamp and runs a scan over them, reusing the full safety
        path (target guard, auth scope, kill switch) via the standard run flow.
        Gated by ``CONTINUOUS_TESTING_ENABLED`` at the call site.
        """
        if kill_switch_enabled():
            return {"status": "blocked", "reason": KILL_SWITCH_REASON}

        limit = max_endpoints or settings.CONTINUOUS_TESTING_MAX_ENDPOINTS_PER_SWEEP
        profile_id = pentest_profile_id or (settings.CONTINUOUS_TESTING_PROFILE_ID or None)

        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(APIEndpoint)
                .where(
                    APIEndpoint.account_id == account_id,
                    APIEndpoint.last_tested.is_(None),
                )
                .order_by(APIEndpoint.last_seen.desc())
                .limit(limit)
            )
            endpoints = result.scalars().all()

        if not endpoints:
            return {"status": "noop", "reason": "no_untested_endpoints", "endpoint_count": 0}

        endpoint_ids = [ep.id for ep in endpoints]
        template_ids = self._all_active_template_ids()
        if not template_ids:
            return {"status": "noop", "reason": "no_templates", "endpoint_count": len(endpoint_ids)}

        return await self._trigger_run(
            schedule_id=f"continuous-discovery-{account_id}",
            template_ids=template_ids,
            endpoint_ids=endpoint_ids,
            account_id=account_id,
            pentest_profile_id=profile_id,
            trigger_source="continuous_discovery",
        )

    @staticmethod
    def _all_active_template_ids() -> list:
        from server.modules.test_executor.wordlist_manager import WordlistManager

        templates = WordlistManager.get_instance().templates
        return [
            str(t.get("id"))
            for t in templates
            if isinstance(t, dict) and t.get("id")
        ]

    async def cancel(self, schedule_id: str, db: AsyncSession) -> None:
        if self._scheduler:
            try:
                self._scheduler.remove_job(schedule_id)
            except Exception:
                pass
        record = await db.get(TestSchedule, schedule_id)
        if record:
            record.enabled = False
            await db.commit()

    async def list_schedules(self, db: AsyncSession) -> list:
        result = await db.execute(select(TestSchedule).where(TestSchedule.enabled == True))
        return result.scalars().all()


# Singleton
_scheduler_instance: TestScheduler = None


def get_scheduler() -> TestScheduler:
    global _scheduler_instance
    if _scheduler_instance is None:
        _scheduler_instance = TestScheduler()
    return _scheduler_instance
