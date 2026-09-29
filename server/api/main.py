from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Awaitable, Callable

import structlog
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.responses import JSONResponse
from sqlalchemy import text
from slowapi.errors import RateLimitExceeded

from server.api.rate_limiter import limiter
from server.api.routers import router
from server.config import settings
from server.models import Base
from server.models.core import User
from server.modules.analytics.processor import AnalyticsProcessor
from server.modules.api_inventory.lifecycle import EndpointLifecycleProcessor
from server.modules.auth.password_hasher import PasswordHasher
from server.modules.config.logging_config import configure_logging
from server.modules.enforcement.adaptive_rate_limiter import AdaptiveRequestGuard
from server.modules.ingestion.queue import ingestion_queue
from server.modules.persistence.database import AsyncSessionLocal, engine, get_db
from server.modules.recon.scheduler import ReconScheduler
from server.modules.response.default_playbooks import ensure_default_playbooks
from server.modules.scheduler.test_scheduler import TestScheduler
from server.modules.scheduler.continuous_testing import ContinuousTestingProcessor
from server.modules.scheduler.openapi_drift import OpenAPIDriftProcessor
from server.modules.storage.archiver import ArchiveProcessor
from server.modules.storage.warm_exporter import WarmStoreExporter
from server.modules.streaming.kafka_alert_consumer import KafkaAlertConsumer
from server.modules.streaming.pipeline import StreamPipeline
from server.modules.test_executor.wordlist_manager import WordlistManager

configure_logging()
logger = structlog.get_logger()


def _demo_users() -> list[dict[str, object]]:
    return [
        {
            "email": "admin@demo.sentinel",
            "password": "Admin123!@#Demo",
            "role": "ADMIN",
            "account_id": settings.STARTUP_DEMO_ACCOUNT_ID,
        },
        {
            "email": "analyst@demo.sentinel",
            "password": "Analyst123!@#Demo",
            "role": "SECURITY_ENGINEER",
            "account_id": settings.STARTUP_DEMO_ACCOUNT_ID,
        },
        {
            "email": "viewer@demo.sentinel",
            "password": "Viewer123!@#Demo",
            "role": "VIEWER",
            "account_id": settings.STARTUP_DEMO_ACCOUNT_ID,
        },
        {
            "email": "platform@demo.sentinel",
            "password": "Platform123!@#Demo",
            "role": "PLATFORM_ADMIN",
            "account_id": settings.STARTUP_PLATFORM_ACCOUNT_ID,
        },
    ]


async def _ensure_account(db, account_id: int, name: str, tier: str) -> bool:
    exists = await db.execute(text("SELECT id FROM accounts WHERE id = :id"), {"id": account_id})
    if exists.fetchone():
        return False

    await db.execute(
        text("INSERT INTO accounts (id, name, plan_tier) VALUES (:id, :name, :tier)"),
        {"id": account_id, "name": name, "tier": tier},
    )
    return True


async def _seed_demo_bootstrap() -> None:
    from sqlalchemy.future import select as sa_select

    async with AsyncSessionLocal() as db:
        demo_created = await _ensure_account(
            db,
            settings.STARTUP_DEMO_ACCOUNT_ID,
            "Demo Organization",
            "ENTERPRISE",
        )
        platform_created = await _ensure_account(
            db,
            settings.STARTUP_PLATFORM_ACCOUNT_ID,
            "Platform Operations",
            "PLATFORM",
        )
        if demo_created or platform_created:
            await db.commit()

        for user_data in _demo_users():
            existing = await db.execute(sa_select(User).where(User.email == user_data["email"]))
            if existing.scalar_one_or_none():
                continue
            db.add(
                User(
                    account_id=int(user_data["account_id"]),
                    email=str(user_data["email"]),
                    password_hash=PasswordHasher.hash_password(str(user_data["password"])),
                    role=str(user_data["role"]),
                )
            )
        await db.commit()

    logger.warning(
        "startup_demo_bootstrap_enabled",
        demo_account_id=settings.STARTUP_DEMO_ACCOUNT_ID,
        platform_account_id=settings.STARTUP_PLATFORM_ACCOUNT_ID,
    )


async def _refresh_template_library() -> int:
    manager = WordlistManager.get_instance(settings.TESTS_LIBRARY_PATH)
    manager.refresh_templates()
    return len(manager.templates)


def _build_runtime_components() -> list[tuple[str, Callable[[], Awaitable[None]], Callable[[], Awaitable[None]]]]:
    components: list[tuple[str, Callable[[], Awaitable[None]], Callable[[], Awaitable[None]]]] = []

    if settings.STARTUP_ENABLE_TEST_SCHEDULER:
        scheduler = TestScheduler()

        async def _start_scheduler() -> None:
            scheduler.start()

        async def _stop_scheduler() -> None:
            scheduler.stop()

        components.append(("test_scheduler", _start_scheduler, _stop_scheduler))

    if settings.STARTUP_ENABLE_INGESTION_QUEUE:
        components.append(("ingestion_queue", ingestion_queue.start, ingestion_queue.stop))

    if settings.STARTUP_ENABLE_ANALYTICS_PROCESSOR:
        analytics = AnalyticsProcessor(
            interval_sec=60,
            account_id=settings.STARTUP_ANALYTICS_ACCOUNT_ID,
        )
        components.append(("analytics_processor", analytics.start, analytics.stop))

    if settings.STARTUP_ENABLE_ARCHIVER:
        archiver = ArchiveProcessor(
            interval_sec=3600,
            account_id=settings.STARTUP_ARCHIVER_ACCOUNT_ID,
        )
        components.append(("archive_processor", archiver.start, archiver.stop))

    if settings.STARTUP_ENABLE_WARM_EXPORTER:
        warm_exporter = WarmStoreExporter(interval_sec=settings.WARM_EXPORT_INTERVAL_SECONDS)
        components.append(("warm_exporter", warm_exporter.start, warm_exporter.stop))

    if settings.STARTUP_ENABLE_ENDPOINT_LIFECYCLE:
        lifecycle = EndpointLifecycleProcessor(interval_sec=settings.LIFECYCLE_SWEEP_INTERVAL_SECONDS)
        components.append(("endpoint_lifecycle", lifecycle.start, lifecycle.stop))

    if settings.STARTUP_ENABLE_RECON_SCHEDULER and settings.RECON_SCHEDULER_ENABLED:
        recon_scheduler = ReconScheduler(interval_sec=settings.RECON_SCHEDULER_INTERVAL_SECONDS)
        components.append(("recon_scheduler", recon_scheduler.start, recon_scheduler.stop))

    if settings.STARTUP_ENABLE_CONTINUOUS_TESTING and settings.CONTINUOUS_TESTING_ENABLED:
        continuous_testing = ContinuousTestingProcessor(
            interval_sec=settings.CONTINUOUS_TESTING_SWEEP_INTERVAL_SECONDS
        )
        components.append(
            ("continuous_testing", continuous_testing.start, continuous_testing.stop)
        )

    if settings.STARTUP_ENABLE_OPENAPI_DRIFT and settings.OPENAPI_DRIFT_ENABLED:
        openapi_drift = OpenAPIDriftProcessor(
            interval_sec=settings.OPENAPI_DRIFT_SWEEP_INTERVAL_SECONDS
        )
        components.append(
            ("openapi_drift", openapi_drift.start, openapi_drift.stop)
        )

    if settings.STARTUP_ENABLE_STREAM_PIPELINE and settings.STREAM_PROCESSING_ENABLED:
        stream_pipeline = StreamPipeline()
        components.append(("stream_pipeline", stream_pipeline.start, stream_pipeline.stop))

    if settings.STREAM_ENGINE.upper() == "FLINK":
        kafka_alert_consumer = KafkaAlertConsumer()
        components.append(("kafka_alert_consumer", kafka_alert_consumer.start, kafka_alert_consumer.stop))

    return components


@asynccontextmanager
async def lifespan(app: FastAPI):
    started_components: list[tuple[str, Callable[[], Awaitable[None]], Callable[[], Awaitable[None]]]] = []
    templates_loaded = 0

    if settings.STARTUP_BOOTSTRAP_SCHEMA:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.warning("startup_schema_bootstrap_enabled", database_url=settings.DATABASE_URL)

    if settings.STARTUP_ENABLE_DEMO_BOOTSTRAP:
        await _seed_demo_bootstrap()

    if settings.STARTUP_REFRESH_TEMPLATE_LIBRARY:
        templates_loaded = await _refresh_template_library()

    if settings.STARTUP_ENSURE_DEFAULT_PLAYBOOKS:
        async with AsyncSessionLocal() as db:
            created = await ensure_default_playbooks(db, settings.STARTUP_PLAYBOOK_ACCOUNT_ID)
            await db.commit()
        logger.info(
            "startup_default_playbooks_ensured",
            account_id=settings.STARTUP_PLAYBOOK_ACCOUNT_ID,
            created=created,
        )

    for name, starter, stopper in _build_runtime_components():
        try:
            await starter()
            started_components.append((name, starter, stopper))
            logger.info("startup_component_started", component=name)
        except Exception as exc:
            logger.error("startup_component_failed", component=name, error=str(exc))
            raise

    app.state.runtime_components = [name for name, _, _ in started_components]
    logger.info("startup_complete", templates_loaded=templates_loaded, components=app.state.runtime_components)

    try:
        yield
    finally:
        for name, _, stopper in reversed(started_components):
            try:
                await stopper()
                logger.info("shutdown_component_stopped", component=name)
            except Exception as exc:
                logger.error("shutdown_component_failed", component=name, error=str(exc))
        await engine.dispose()
        logger.info("shutdown_complete")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="API Security Engine - deploy-safe backend",
    lifespan=lifespan,
)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def custom_rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"error": True, "message": "Too many requests. Please try again later."},
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": True, "message": exc.detail},
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error("unhandled_exception", path=request.url.path, error=str(exc))
    message = "Internal Server Error"
    if settings.DEBUG:
        message = f"Internal Server Error: {exc}"
    return JSONResponse(
        status_code=500,
        content={"error": True, "message": message},
    )


cors_origins = settings.CORS_ORIGINS
if settings.CORS_ORIGINS_OVERRIDE and not settings.DEBUG:
    cors_origins = [origin.strip() for origin in settings.CORS_ORIGINS_OVERRIDE.split(",") if origin.strip()]
    logger.info("startup_cors_override_active", origins=len(cors_origins))

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)
app.add_middleware(AdaptiveRequestGuard)
app.include_router(router, prefix="/api")


@app.post("/v1/events")
async def sensor_v1_events(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Argus / api-sentinel-sensor: POST JSON with events; Bearer token = sensor API key."""
    from server.api.routers.stream import handle_ebpf_ingest_request

    return await handle_ebpf_ingest_request(request, db)


# Legacy root path — same payload as POST /v1/events (no localhost hop).
@app.post("/")
async def root_ingest(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Accept eBPF sensor events at POST / (backward compatibility)."""
    from server.api.routers.stream import handle_ebpf_ingest_request

    return await handle_ebpf_ingest_request(request, db)
