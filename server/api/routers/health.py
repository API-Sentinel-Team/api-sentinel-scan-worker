"""System health and readiness endpoints."""

from __future__ import annotations

import datetime
import platform
import sys
from pathlib import Path

from fastapi import APIRouter, Depends, Response
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from server.config import settings
from server.models.core import APIEndpoint, MaliciousEventRecord, ThreatActor, Vulnerability
from server.modules.auth.rbac import require_admin
from server.modules.persistence.database import get_db
from server.modules.test_executor.wordlist_manager import WordlistManager

router = APIRouter()


def _database_type() -> str:
    url = settings.DATABASE_URL.lower()
    if "postgresql" in url:
        return "postgresql"
    if "sqlite" in url:
        return "sqlite"
    return "unknown"


def _component_status(enabled: bool) -> str:
    return "enabled" if enabled else "disabled"


def _utc_now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


async def _db_ready(db: AsyncSession) -> bool:
    try:
        await db.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def _tests_library_status() -> dict[str, object]:
    path = Path(settings.TESTS_LIBRARY_PATH)
    templates_loaded = 0
    try:
        templates_loaded = len(WordlistManager.get_instance(settings.TESTS_LIBRARY_PATH).templates)
    except Exception:
        templates_loaded = 0
    return {
        "status": "ready" if path.exists() else "missing",
        "path": str(path),
        "templates_loaded": templates_loaded,
    }


@router.get("")
@router.get("/")
async def health_check(db: AsyncSession = Depends(get_db)):
    """Returns deploy-oriented health information."""
    db_status = "connected" if await _db_ready(db) else "error"
    actors = await db.scalar(select(func.count(ThreatActor.id))) or 0
    events = await db.scalar(select(func.count(MaliciousEventRecord.id))) or 0
    endpoints = await db.scalar(select(func.count(APIEndpoint.id))) or 0
    vulns = await db.scalar(select(func.count(Vulnerability.id))) or 0
    tests_library = _tests_library_status()

    return {
        "status": "healthy" if db_status == "connected" else "degraded",
        "timestamp": _utc_now_iso(),
        "database": {"status": db_status, "type": _database_type()},
        "python_version": sys.version.split()[0],
        "platform": platform.system(),
        "components": {
            "detection_pipeline": {
                "status": settings.UNIFIED_PIPELINE_MODE,
                "mode": settings.UNIFIED_PIPELINE_MODE,
            },
            "redis": {
                "status": _component_status(bool(settings.REDIS_URL)),
                "configured": bool(settings.REDIS_URL),
            },
            "kafka": {
                "status": _component_status(settings.KAFKA_ENABLED and bool(settings.KAFKA_BOOTSTRAP_SERVERS)),
                "configured": bool(settings.KAFKA_BOOTSTRAP_SERVERS),
            },
            "ml_training": {
                "status": _component_status(settings.ML_TRAINING_ENABLED),
            },
            "tests_library": tests_library,
            "workers": {
                "scheduler": _component_status(settings.STARTUP_ENABLE_TEST_SCHEDULER),
                "ingestion_queue": _component_status(settings.STARTUP_ENABLE_INGESTION_QUEUE),
                "analytics_processor": _component_status(settings.STARTUP_ENABLE_ANALYTICS_PROCESSOR),
                "archive_processor": _component_status(settings.STARTUP_ENABLE_ARCHIVER),
                "stream_pipeline": _component_status(settings.STARTUP_ENABLE_STREAM_PIPELINE and settings.STREAM_PROCESSING_ENABLED),
            },
        },
        "stats": {
            "total_threat_actors": actors,
            "total_events": events,
            "total_endpoints": endpoints,
            "total_vulnerabilities": vulns,
        },
    }


@router.get("/live")
async def liveness():
    return {"status": "live", "timestamp": _utc_now_iso()}


@router.get("/ready")
async def readiness(response: Response, db: AsyncSession = Depends(get_db)):
    db_ok = await _db_ready(db)
    tests_library = _tests_library_status()
    ready = db_ok and tests_library["status"] == "ready"
    response.status_code = 200 if ready else 503
    return {
        "status": "ready" if ready else "not_ready",
        "checks": {
            "database": db_ok,
            "tests_library": tests_library["status"] == "ready",
        },
    }


@router.get("/config-check")
async def config_check(payload: dict = Depends(require_admin)):
    """
    Admin-only endpoint to validate all required production secrets are properly set.
    Returns detailed configuration status.
    """
    issues: list[str] = []
    warnings: list[str] = []

    if settings.DEBUG:
        warnings.append("DEBUG=True - application is in development mode")
    else:
        if settings.JWT_SECRET == "change-me-in-production-32-char-minimum":
            issues.append("JWT_SECRET: Still set to default value")
        elif len(settings.JWT_SECRET) < 32:
            issues.append("JWT_SECRET: Less than 32 characters (recommend 64+)")

        if settings.API_KEY == "dev-api-key-change-in-production":
            issues.append("API_KEY: Still set to default value")

        if not settings.ENCRYPTION_KEY:
            issues.append("ENCRYPTION_KEY: Not set (required for PAT rotation)")
        elif len(settings.ENCRYPTION_KEY) < 32:
            issues.append("ENCRYPTION_KEY: Weak key (should be 44+ chars for Fernet)")

        cors_origins = settings.CORS_ORIGINS
        if settings.CORS_ORIGINS_OVERRIDE:
            cors_origins = [o.strip() for o in settings.CORS_ORIGINS_OVERRIDE.split(",") if o.strip()]

        localhost_origins = [origin for origin in cors_origins if "localhost" in origin or "127.0.0.1" in origin]
        if localhost_origins:
            issues.append(f"CORS_ORIGINS: Contains localhost/127.0.0.1 in production ({len(localhost_origins)} origins)")

        if "sqlite" in settings.DATABASE_URL.lower():
            warnings.append("DATABASE_URL: Using SQLite (OK for dev, use PostgreSQL in production)")

        if settings.STARTUP_BOOTSTRAP_SCHEMA:
            issues.append("STARTUP_BOOTSTRAP_SCHEMA: Must be false in production")
        if settings.STARTUP_ENABLE_DEMO_BOOTSTRAP:
            issues.append("STARTUP_ENABLE_DEMO_BOOTSTRAP: Must be false in production")

    return {
        "status": "critical" if issues else ("warning" if warnings else "ok"),
        "timestamp": _utc_now_iso(),
        "environment": "production" if not settings.DEBUG else "development",
        "issues": issues,
        "warnings": warnings,
        "config": {
            "jwt_secret_set": settings.JWT_SECRET != "change-me-in-production-32-char-minimum",
            "api_key_set": settings.API_KEY != "dev-api-key-change-in-production",
            "encryption_key_set": bool(settings.ENCRYPTION_KEY),
            "cors_override_active": bool(settings.CORS_ORIGINS_OVERRIDE and not settings.DEBUG),
            "database_type": _database_type(),
            "rls_enabled": settings.TENANT_RLS_ENABLED,
            "ml_training_enabled": settings.ML_TRAINING_ENABLED,
            "kafka_enabled": settings.KAFKA_ENABLED,
            "startup_bootstrap_schema": settings.STARTUP_BOOTSTRAP_SCHEMA,
            "startup_demo_bootstrap": settings.STARTUP_ENABLE_DEMO_BOOTSTRAP,
        },
    }
