"""
Configuration — reads from environment variables or .env file.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, model_validator
from cryptography.fernet import Fernet
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(BASE_DIR / ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── App ──────────────────────────────────────────────────────────
    APP_NAME: str = "API Security Engine"
    VERSION: str = "1.0.0"
    DEBUG: bool = True
    DEFAULT_ACCOUNT_ID: int = 1000000
    API_KEY: str = "dev-api-key-change-in-production"
    JWT_SECRET: str = "change-me-in-production-32-char-minimum"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 60 * 24 * 7 # 1 week
    ENCRYPTION_KEY: str = "" # Set via .env for production
    SENSOR_KEY_HASH_PEPPER: str = "" # HMAC pepper for sensor API keys; required in production
    STARTUP_BOOTSTRAP_SCHEMA: bool = False
    STARTUP_ENABLE_DEMO_BOOTSTRAP: bool = False
    STARTUP_DEMO_ACCOUNT_ID: int = 1000000
    STARTUP_PLATFORM_ACCOUNT_ID: int = 999999
    STARTUP_REFRESH_TEMPLATE_LIBRARY: bool = True
    STARTUP_ENSURE_DEFAULT_PLAYBOOKS: bool = False
    STARTUP_PLAYBOOK_ACCOUNT_ID: int = 0
    STARTUP_ENABLE_TEST_SCHEDULER: bool = True
    SCHEDULER_SYNC_INTERVAL_SECONDS: int = 30
    STARTUP_ENABLE_INGESTION_QUEUE: bool = True
    STARTUP_ENABLE_ANALYTICS_PROCESSOR: bool = False
    STARTUP_ANALYTICS_ACCOUNT_ID: int = 0
    STARTUP_ENABLE_ARCHIVER: bool = False
    STARTUP_ARCHIVER_ACCOUNT_ID: int = 0
    STARTUP_ENABLE_WARM_EXPORTER: bool = True
    STARTUP_ENABLE_ENDPOINT_LIFECYCLE: bool = True
    STARTUP_ENABLE_RECON_SCHEDULER: bool = True
    STARTUP_ENABLE_STREAM_PIPELINE: bool = True

    # ── Database ─────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./api_security.db"
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 1800

    # ── Redis (optional) ─────────────────────────────────────────────
    REDIS_URL: str = ""

    # -- Read replica (optional) ---------------------------------------------------------------
    READ_REPLICA_URL: str = ""

    # ── Kafka (optional) ─────────────────────────────────────────────
    KAFKA_BOOTSTRAP_SERVERS: str = ""
    KAFKA_ENABLED: bool = False
    KAFKA_CLIENT_ID: str = "api-security-engine"
    KAFKA_SECURITY_PROTOCOL: str = "PLAINTEXT"
    KAFKA_SASL_MECHANISM: str = ""
    KAFKA_SASL_USERNAME: str = ""
    KAFKA_SASL_PASSWORD: str = ""
    KAFKA_ACKS: str = "all"
    KAFKA_LINGER_MS: int = 5
    KAFKA_TOPIC_PARTITIONS: int = 3
    KAFKA_TOPIC_REPLICATION: int = 1
    KAFKA_AUTO_CREATE_TOPICS: bool = True
    KAFKA_CONSUMER_GROUP_PREFIX: str = "api-sec"

    # ── Streaming Engine ─────────────────────────────────────────────
    STREAM_ENGINE: str = "IN_PROCESS"  # IN_PROCESS | FLINK

    # ── MCP Inline Enforcement ───────────────────────────────────────
    INLINE_MCP_ENFORCEMENT_ENABLED: bool = False

    # ── ML Training ──────────────────────────────────────────────────
    ML_TRAINING_ENABLED: bool = True
    ML_TRAINING_MAX_SAMPLES: int = 50000
    ML_TRAINING_MIN_SAMPLES: int = 500
    MODEL_ARTIFACT_DIR: str = str(BASE_DIR / "models")

    # ── Tests Library ────────────────────────────────────────────────
    TESTS_LIBRARY_PATH: str = str(BASE_DIR / "tests-library")


    # ── mitmproxy ────────────────────────────────────────────────────
    MITMPROXY_PORT: int = 8080
    MITMPROXY_HOST: str = "127.0.0.1"
    # Sensor API key the mitmproxy addon authenticates captured traffic with —
    # same key model as the eBPF sensor's /v1/events and /v2/events. Register
    # a Sensor row for this key and point it at the tenant account that owns
    # the traffic; captured flows are dropped (not attributed) when unset.
    MITMPROXY_SENSOR_API_KEY: str = ""

    # ── WAF / Coraza ─────────────────────────────────────────────────
    CORAZA_URL: str = ""

    # ── Security ─────────────────────────────────────────────────────
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://localhost:3000",
        "http://localhost:8080",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:8080",
    ]
    # CORS_ORIGINS_OVERRIDE: Can be set via env (comma-separated list, no spaces)
    # E.g., CORS_ORIGINS_OVERRIDE="https://app.example.com,https://api.example.com"
    CORS_ORIGINS_OVERRIDE: str = ""


    # ── Test Execution ───────────────────────────────────────────────
    MAX_CONCURRENT_TESTS: int = 20
    TEST_REQUEST_TIMEOUT: int = 15   # seconds
    PENTEST_DEFAULT_PROFILE_NAME: str = "Production Safe"
    PENTEST_DEFAULT_MODE: str = "SAFE"
    PENTEST_REQUIRE_AUTH_PROFILE_FOR_ACTIVE_SCANS: bool = True
    PENTEST_SAFE_MAX_CONCURRENCY: int = 5
    PENTEST_BALANCED_MAX_CONCURRENCY: int = 10
    PENTEST_AGGRESSIVE_MAX_CONCURRENCY: int = 20
    PENTEST_SAFE_TIMEOUT_SECONDS: int = 15
    PENTEST_ALLOW_STATE_CHANGE_DEFAULT: bool = False
    PENTEST_ENABLE_SCHEMATHESIS: bool = True
    PENTEST_ENABLE_NUCLEI_SECRET_FILES: bool = True
    PENTEST_ENFORCE_TARGET_GUARD: bool = True
    PENTEST_TARGET_ALLOWLIST: str = ""  # comma-separated hosts, host:port, URLs, or *.example.com
    PENTEST_ALLOW_PRIVATE_TARGETS: bool = False
    PENTEST_RESOLVE_TARGET_HOSTS: bool = False
    PENTEST_FAIL_CLOSED_ON_TARGET_DNS_ERROR: bool = True
    PENTEST_MAX_TESTS_PER_RUN: int = 5000
    PENTEST_MAX_ACTIVE_REQUESTS_PER_TEST: int = 50
    PENTEST_RESPONSE_BACKOFF_ENABLED: bool = True
    PENTEST_DEFAULT_RESPONSE_BACKOFF_SECONDS: float = 1.0
    PENTEST_MAX_RESPONSE_BACKOFF_SECONDS: float = 5.0
    PENTEST_SCHEMATHESIS_TIMEOUT_SECONDS: int = 300
    PENTEST_SCHEMATHESIS_REPORT_MAX_BYTES: int = 2 * 1024 * 1024
    PENTEST_ZAP_TIMEOUT_SECONDS: int = 900
    PENTEST_ZAP_REPORT_MAX_BYTES: int = 5 * 1024 * 1024
    PENTEST_SCAN_WORK_DIR: str = str(BASE_DIR / "data" / "pentest-runs")
    PENTEST_SCAN_EXECUTION_MODE: str = "background"  # background | queued
    PENTEST_SCAN_WORKER_ISOLATION_MODE: str = "background"  # background | kubernetes_job
    PENTEST_SCAN_WORKER_KUBERNETES_NAMESPACE: str = "api-sentinel"
    PENTEST_SCAN_WORKER_KUBERNETES_SERVICE_ACCOUNT: str = "api-sentinel-scan-worker"
    PENTEST_SCAN_WORKER_IMAGE: str = "api-sentinel-scan-worker:latest"
    PENTEST_SCAN_WORKER_JOB_TTL_SECONDS: int = 3600
    PENTEST_SCAN_WORKER_RESOURCE_CPU: str = "1000m"
    PENTEST_SCAN_WORKER_RESOURCE_MEMORY: str = "1Gi"
    PENTEST_SCAN_WORKER_RESOURCE_EPHEMERAL_STORAGE: str = "2Gi"
    PENTEST_SCAN_DISPATCH_LEASE_SECONDS: int = 900
    PENTEST_SCAN_WORKER_TIMEOUT_SECONDS: int = 0  # 0 = use lease seconds as run budget
    PENTEST_SCAN_MAX_CLAIMS: int = 3
    # P0-7: a worker heartbeat older than this window is not evidence of a live
    # worker. Readiness claims must not be backed by a stale heartbeat.
    PENTEST_SCAN_WORKER_HEARTBEAT_MAX_AGE_SECONDS: int = 300
    PENTEST_KILL_SWITCH_ENABLED: bool = False
    INTEGRATIONS_ENFORCE_DESTINATION_GUARD: bool = True
    INTEGRATIONS_ALLOW_PRIVATE_DESTINATIONS: bool = False
    INTEGRATIONS_RESOLVE_DESTINATION_HOSTS: bool = False
    INTEGRATIONS_FAIL_CLOSED_ON_DESTINATION_DNS_ERROR: bool = True

    # -- Ingestion / Backpressure --------------------------------------------------------------
    INGESTION_QUEUE_MAX_SIZE: int = 5000
    INGESTION_WORKERS: int = 4
    INGESTION_RATE_LIMIT_RPM: int = 6000  # per tenant
    INGESTION_MAX_LINES: int = 1000
    INGESTION_MAX_LINE_BYTES: int = 4096
    INGESTION_JOB_TTL_HOURS: int = 24
    INGESTION_MAX_EVENTS: int = 2000
    INGESTION_MIN_QUALITY_SCORE: float = 0.6
    INGESTION_DROP_LOW_QUALITY: bool = True
    # Comma-separated hosts whose traffic is this product (not a monitored API).
    # CORS_ORIGINS_OVERRIDE hosts are also excluded automatically.
    INGEST_EXCLUDE_HOSTS: str = ""
    DETECTION_WINDOW_SECONDS: int = 60
    DETECTION_BURST_THRESHOLD: int = 45
    DETECTION_ALERT_COOLDOWN_SECONDS: int = 120
    DETECTION_SLOW_RESPONSE_THRESHOLD_MS: int = 1500
    # Default to "shadow" so the unified detection pipeline runs on ingest and
    # operators can observe what it would catch before promoting to "active".
    # Shadow mode does not persist findings, alert, or enforce — it only
    # evaluates detectors and records health/metrics. Set to "active" once
    # you've reviewed shadow output; set to "off" to fall back to legacy regex.
    UNIFIED_PIPELINE_MODE: str = "shadow"  # off | shadow | active
    DETECTION_META_VERSION: str = "2026-03-29"
    DETECTION_ALERT_DEDUPE_SECONDS: int = 300
    DETECTION_IP_BLOCK_THRESHOLD: float = 0.8
    DETECTION_RATE_LIMIT_THRESHOLD: float = 0.65
    DETECTION_ENDPOINT_BLOCK_THRESHOLD: float = 0.9
    DETECTION_BATCH_LIMIT: int = 100
    DETECTION_MAX_QUERY_PAGE_SIZE: int = 500
    DETECTION_LARGE_RESPONSE_BYTES: int = 500000
    DETECTION_TIMING_WINDOW_SIZE: int = 20
    DETECTION_BASELINE_EWMA_ALPHA: float = 0.3
    DETECTION_BASELINE_ZSCORE_THRESHOLD: float = 2.5
    DETECTION_OBJECT_ENUM_THRESHOLD: int = 8
    DETECTION_EXFIL_PAGE_THRESHOLD: int = 10
    DETECTION_RULE_WEIGHT: float = 0.30
    DETECTION_BEHAVIORAL_WEIGHT: float = 0.25
    DETECTION_ML_WEIGHT: float = 0.20
    DETECTION_SEQUENCE_WEIGHT: float = 0.15
    DETECTION_REPUTATION_WEIGHT: float = 0.10

    # -- Caching ------------------------------------------------------------------------------
    ENDPOINTS_CACHE_TTL: int = 60     # seconds
    DASHBOARD_CACHE_TTL: int = 30     # seconds

    # -- Privacy / Redaction -----------------------------------------------------------------
    REDACT_PAYLOADS_BY_DEFAULT: bool = True

    # -- Archival / Cold Store ---------------------------------------------------------------
    ARCHIVE_ENABLED: bool = True
    ARCHIVE_INTERVAL_SECONDS: int = 3600
    ARCHIVE_DIR: str = str(BASE_DIR / "data" / "archives")
    ARCHIVE_BUCKET: str = ""
    ARCHIVE_REGION: str = ""
    ARCHIVE_AFTER_DAYS: int = 7
    ARCHIVE_BATCH_SIZE: int = 500
    RETENTION_DELETE_AFTER_DAYS: int = 365

    # -- Stream Processing ------------------------------------------------------------------
    STREAM_PROCESSING_ENABLED: bool = True
    STREAM_AUTH_FAILURE_THRESHOLD: int = 100
    STREAM_DISTINCT_ACTORS_THRESHOLD: int = 50
    STREAM_ALERT_SUPPRESS_SECONDS: int = 300
    STREAM_MIN_QUALITY_SCORE: float = 0.5

    # -- ML Shadow Mode ---------------------------------------------------------------------
    ML_SHADOW_MODE: bool = True
    ML_ALERT_THRESHOLD: float = 0.9

    # -- ClickHouse Warm Store --------------------------------------------------------------
    CLICKHOUSE_ENABLED: bool = False
    CLICKHOUSE_URL: str = "http://localhost:8123"
    CLICKHOUSE_USER: str = ""
    CLICKHOUSE_PASSWORD: str = ""
    CLICKHOUSE_DATABASE: str = "api_security"
    CLICKHOUSE_TIMEOUT_SECONDS: int = 10
    WARM_EXPORT_INTERVAL_SECONDS: int = 120
    WARM_EXPORT_BATCH_SIZE: int = 1000

    # ── Endpoint Lifecycle ────────────────────────────────────────────
    LIFECYCLE_SWEEP_INTERVAL_SECONDS: int = 3600
    ZOMBIE_ENDPOINT_DAYS: int = 30

    # ── Recon Scheduler ───────────────────────────────────────────────
    RECON_SCHEDULER_ENABLED: bool = True
    RECON_SCHEDULER_INTERVAL_SECONDS: int = 300
    RECON_DEFAULT_INTERVAL_SECONDS: int = 86400

    # ── Tenant Isolation (RLS) ───────────────────────────────────────
    TENANT_RLS_ENABLED: bool = False
    TENANT_RLS_SETTING_NAME: str = "app.current_account_id"

    # ── CI/CD Webhooks ───────────────────────────────────────────────────
    GITHUB_WEBHOOK_SECRET: str = ""
    GITLAB_WEBHOOK_SECRET: str = ""
    CICD_GATE_SIGNING_SECRET: str = ""
    CICD_GATE_RATE_LIMIT_RPM: int = 6000
    VULNERABILITY_SLA_POLICY: str = ""

    # ── Splunk ───────────────────────────────────────────────────────────
    SPLUNK_HEC_URL: str = ""
    SPLUNK_HEC_TOKEN: str = ""
    SPLUNK_INDEX: str = "main"

    # ── Datadog ──────────────────────────────────────────────────────────
    DATADOG_API_KEY: str = ""
    DATADOG_APP_KEY: str = ""
    DATADOG_SITE: str = "datadoghq.com"

    # ── Azure DevOps ─────────────────────────────────────────────────────
    AZURE_DEVOPS_ORG: str = ""
    AZURE_DEVOPS_PROJECT: str = ""
    AZURE_DEVOPS_PAT: str = ""

    # ── PagerDuty ────────────────────────────────────────────────────────
    PAGERDUTY_ROUTING_KEY: str = ""

    # ── BigQuery ─────────────────────────────────────────────────────────
    BIGQUERY_PROJECT_ID: str = ""
    BIGQUERY_DATASET_ID: str = ""

    # ── Source Code Scanning ─────────────────────────────────────────────
    SOURCE_CODE_ENFORCE_REPO_GUARD: bool = True
    SOURCE_CODE_ALLOW_PRIVATE_REPOS: bool = False
    SOURCE_CODE_RESOLVE_REPO_HOSTS: bool = False
    SOURCE_CODE_FAIL_CLOSED_ON_REPO_DNS_ERROR: bool = True
    SOURCE_CODE_ALLOW_LOCAL_PATHS: bool = False
    SOURCE_CODE_LOCAL_SCAN_ROOT: str = str(BASE_DIR / "source-repos")

    # ── Nuclei ───────────────────────────────────────────────────────────
    NUCLEI_TIMEOUT: int = 120
    NUCLEI_RATE_LIMIT: int = 150

    # ── Billing / Stripe ─────────────────────────────────────────────────
    STRIPE_SECRET_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""

    # ── Agent Guard ──────────────────────────────────────────────────────
    AGENT_GUARD_ENABLED: bool = True
    AGENT_GUARD_BLOCK_ON_CRITICAL: bool = True

    # ── MCP Shield ───────────────────────────────────────────────────────
    MCP_SHIELD_ENABLED: bool = True
    MCP_DEFAULT_RATE_LIMIT_RPM: int = 60

    # ── Agentic Reasoning (proposer-confirmer) ───────────────────────────
    # The LLM only PROPOSES tests; deterministic guards + judge dispose.
    # Disabled by default and degrades to deterministic selection when off.
    AGENTIC_LLM_ENABLED: bool = False
    AGENTIC_LLM_MODEL: str = ""          # e.g. "ollama/llama3", "gpt-4o-mini"
    AGENTIC_LLM_API_BASE: str = ""       # e.g. "http://localhost:11434" for Ollama
    AGENTIC_LLM_API_KEY: str = ""        # hosted-provider key; never logged
    AGENTIC_LLM_TIMEOUT_SECONDS: float = 30.0
    AGENTIC_LOOP_MAX_ROUNDS: int = 3

    # ── Continuous Testing (discovery -> auto-scan) ──────────────────────
    # When enabled, newly-discovered (never-tested) endpoints are automatically
    # enqueued for a scan, closing the Discovery -> Testing pipeline gap.
    # Off by default; requires a default pentest profile + allowlisted targets.
    CONTINUOUS_TESTING_ENABLED: bool = False
    CONTINUOUS_TESTING_PROFILE_ID: str = ""       # pentest profile to use; blank = default
    CONTINUOUS_TESTING_MAX_ENDPOINTS_PER_SWEEP: int = 25
    CONTINUOUS_TESTING_SWEEP_INTERVAL_SECONDS: int = 600
    STARTUP_ENABLE_CONTINUOUS_TESTING: bool = False

    # ── OpenAPI Auto-Doc + Drift Detection ────────────────────────────────
    # Periodically regenerates the OpenAPI spec from discovered endpoints and
    # diffs it against the last stored version, raising a finding when the
    # API surface changes in a way that matters (endpoint removed, auth
    # requirement dropped, etc). Off by default.
    OPENAPI_DRIFT_ENABLED: bool = False
    OPENAPI_DRIFT_SWEEP_INTERVAL_SECONDS: int = 3600
    OPENAPI_DRIFT_MAX_FINDINGS_PER_SWEEP: int = 100
    STARTUP_ENABLE_OPENAPI_DRIFT: bool = False

    @field_validator("DEBUG", mode="before")
    @classmethod
    def _coerce_debug_value(cls, value):
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"release", "prod", "production"}:
                return False
            if normalized in {"dev", "debug", "development"}:
                return True
        return value

    @field_validator("ENCRYPTION_KEY")
    @classmethod
    def _validate_encryption_key_format(cls, value):
        if not value:
            return value
        try:
            Fernet(value.encode())
        except Exception as exc:
            raise ValueError("ENCRYPTION_KEY must be a valid Fernet key generated by Fernet.generate_key()") from exc
        return value

    @model_validator(mode="after")
    def _validate_production_secrets(self) -> "Settings":
        if self.UNIFIED_PIPELINE_MODE not in {"off", "shadow", "active"}:
            raise ValueError("UNIFIED_PIPELINE_MODE must be one of: off, shadow, active")

        if self.STARTUP_ENSURE_DEFAULT_PLAYBOOKS and self.STARTUP_PLAYBOOK_ACCOUNT_ID <= 0:
            raise ValueError("STARTUP_PLAYBOOK_ACCOUNT_ID must be > 0 when STARTUP_ENSURE_DEFAULT_PLAYBOOKS=True")
        if self.STARTUP_ENABLE_ANALYTICS_PROCESSOR and self.STARTUP_ANALYTICS_ACCOUNT_ID < 0:
            raise ValueError("STARTUP_ANALYTICS_ACCOUNT_ID must be >= 0 when STARTUP_ENABLE_ANALYTICS_PROCESSOR=True")
        if self.STARTUP_ENABLE_ARCHIVER and self.STARTUP_ARCHIVER_ACCOUNT_ID < 0:
            raise ValueError("STARTUP_ARCHIVER_ACCOUNT_ID must be >= 0 when STARTUP_ENABLE_ARCHIVER=True")

        if not self.DEBUG:
            if self.STARTUP_BOOTSTRAP_SCHEMA:
                raise ValueError("STARTUP_BOOTSTRAP_SCHEMA must remain disabled when DEBUG=False; run Alembic migrations separately")
            if self.STARTUP_ENABLE_DEMO_BOOTSTRAP:
                raise ValueError("STARTUP_ENABLE_DEMO_BOOTSTRAP must remain disabled when DEBUG=False")

            # Critical secrets validation
            if self.JWT_SECRET == "change-me-in-production-32-char-minimum":
                raise ValueError("JWT_SECRET must be changed from the default when DEBUG=False")
            if self.API_KEY == "dev-api-key-change-in-production":
                raise ValueError("API_KEY must be changed from the default when DEBUG=False")
            if not self.ENCRYPTION_KEY:
                raise ValueError("ENCRYPTION_KEY must be set in production for PAT rotation and data encryption")
            if not self.SENSOR_KEY_HASH_PEPPER:
                raise ValueError("SENSOR_KEY_HASH_PEPPER must be set in production for sensor key hashing")
            if not self.CICD_GATE_SIGNING_SECRET:
                raise ValueError("CICD_GATE_SIGNING_SECRET must be set in production for signed CI/CD gate decisions")
            if not self.PENTEST_REQUIRE_AUTH_PROFILE_FOR_ACTIVE_SCANS:
                raise ValueError("PENTEST_REQUIRE_AUTH_PROFILE_FOR_ACTIVE_SCANS must remain enabled when DEBUG=False")
            if not self.PENTEST_ENFORCE_TARGET_GUARD:
                raise ValueError("PENTEST_ENFORCE_TARGET_GUARD must remain enabled when DEBUG=False")
            if self.PENTEST_ALLOW_PRIVATE_TARGETS:
                raise ValueError("PENTEST_ALLOW_PRIVATE_TARGETS must remain disabled when DEBUG=False")
            if not self.PENTEST_RESOLVE_TARGET_HOSTS:
                raise ValueError("PENTEST_RESOLVE_TARGET_HOSTS must be enabled when DEBUG=False for SSRF/DNS-rebinding protection")
            if not self.PENTEST_FAIL_CLOSED_ON_TARGET_DNS_ERROR:
                raise ValueError("PENTEST_FAIL_CLOSED_ON_TARGET_DNS_ERROR must remain enabled when DEBUG=False")
            target_allowlist = [
                item.strip()
                for item in (self.PENTEST_TARGET_ALLOWLIST or "").split(",")
                if item.strip()
            ]
            if not target_allowlist:
                raise ValueError("PENTEST_TARGET_ALLOWLIST must list owned API hosts when DEBUG=False")
            if any(item == "*" or item.endswith("://*") for item in target_allowlist):
                raise ValueError("PENTEST_TARGET_ALLOWLIST must not use a wildcard '*' when DEBUG=False")

            # CORS validation
            cors_origins = self.CORS_ORIGINS
            if self.CORS_ORIGINS_OVERRIDE:
                # Parse CORS_ORIGINS_OVERRIDE from comma-separated string
                cors_origins = [o.strip() for o in self.CORS_ORIGINS_OVERRIDE.split(",") if o.strip()]
                if not cors_origins:
                    raise ValueError("CORS_ORIGINS_OVERRIDE is set but empty after parsing")

            # Check for localhost/127.0.0.1 in production
            for origin in cors_origins:
                if "localhost" in origin or "127.0.0.1" in origin:
                    raise ValueError(f"CORS origin '{origin}' contains localhost/127.0.0.1 in production. Use CORS_ORIGINS_OVERRIDE for production URLs.")

        return self

settings = Settings()
