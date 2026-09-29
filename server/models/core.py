import uuid
from sqlalchemy.orm import declarative_base, Mapped, mapped_column
from sqlalchemy import String, Integer, DateTime, Float, Boolean, JSON, BigInteger, Text, func, UniqueConstraint

Base = declarative_base()


class APIEndpoint(Base):
    __tablename__ = "api_endpoints"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1000000, index=True)
    collection_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    method: Mapped[str] = mapped_column(String(10), nullable=True)
    path: Mapped[str] = mapped_column(String, nullable=True)
    path_pattern: Mapped[str] = mapped_column(String, nullable=True)
    host: Mapped[str] = mapped_column(String(255), nullable=True)
    port: Mapped[int] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(10), nullable=True)
    description: Mapped[str] = mapped_column(String, nullable=True)
    tags: Mapped[dict] = mapped_column(JSON, nullable=True)
    # Runtime data from captured traffic
    last_response_code: Mapped[int] = mapped_column(Integer, nullable=True, default=200)
    last_response_body: Mapped[str] = mapped_column(Text, nullable=True)
    last_request_body: Mapped[str] = mapped_column(Text, nullable=True)
    last_query_string: Mapped[str] = mapped_column(String, nullable=True)
    last_response_headers: Mapped[dict] = mapped_column(JSON, nullable=True)
    private_variable_count: Mapped[int] = mapped_column(Integer, nullable=True, default=0)
    # Security metadata
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    severity_score: Mapped[float] = mapped_column(Float, default=0.0)
    is_sensitive: Mapped[bool] = mapped_column(Boolean, default=False)
    api_type: Mapped[str] = mapped_column(String(20), default="REST")  # REST, GRAPHQL, GRPC, SOAP
    access_type: Mapped[str] = mapped_column(String(20), default="PRIVATE") # PUBLIC, PRIVATE, PARTNER
    auth_types_found: Mapped[list] = mapped_column(JSON, default=list) # ["JWT", "BASIC"]
    status: Mapped[str] = mapped_column(String(20), default="ACTIVE")  # ACTIVE|SHADOW|ROGUE|ZOMBIE|DEPRECATED
    
    last_seen = mapped_column(DateTime(timezone=True), nullable=True)
    last_tested = mapped_column(DateTime(timezone=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class YamlTemplate(Base):
    __tablename__ = "yaml_templates"

    id: Mapped[str] = mapped_column(String(100), primary_key=True)
    category: Mapped[str] = mapped_column(String(100), nullable=True)
    name: Mapped[str] = mapped_column(String(255), nullable=True)
    severity: Mapped[str] = mapped_column(String(50), nullable=True)
    description: Mapped[str] = mapped_column(String, nullable=True)
    remediation_plan: Mapped[str] = mapped_column(Text, nullable=True)
    yaml_content: Mapped[str] = mapped_column(String, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class TestAccount(Base):
    """Stores victim/attacker tokens for BOLA/BFLA tests."""
    __tablename__ = "test_accounts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=True)
    auth_headers: Mapped[dict] = mapped_column(JSON, nullable=True)   # {"Authorization": "Bearer xyz"}
    auth_token: Mapped[str] = mapped_column(String, nullable=True)    # legacy plain token
    role: Mapped[str] = mapped_column(String(50), nullable=True)      # ADMIN, MEMBER, ATTACKER
    status: Mapped[str] = mapped_column(String(20), nullable=False, server_default="ACTIVE")  # ACTIVE|EXPIRED|DISABLED
    expired_at = mapped_column(DateTime(timezone=True), nullable=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuthProfile(Base):
    """Reusable authentication profile for pentest orchestration and authenticated scans."""
    __tablename__ = "auth_profiles"
    __table_args__ = (
        UniqueConstraint("account_id", "name", name="uq_auth_profiles_account_name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=True)
    auth_mode: Mapped[str] = mapped_column(String(50), default="header")  # header|bearer|basic|cookie|dynamic_bearer
    header_name: Mapped[str] = mapped_column(String(100), nullable=True)
    header_value: Mapped[str] = mapped_column(Text, nullable=True)
    token: Mapped[str] = mapped_column(Text, nullable=True)
    username: Mapped[str] = mapped_column(String(255), nullable=True)
    password: Mapped[str] = mapped_column(String(255), nullable=True)
    cookie_name: Mapped[str] = mapped_column(String(100), nullable=True)
    cookie_value: Mapped[str] = mapped_column(Text, nullable=True)
    cookies: Mapped[list] = mapped_column(JSON, default=list)
    static_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    login_url: Mapped[str] = mapped_column(String, nullable=True)
    login_method: Mapped[str] = mapped_column(String(10), default="POST")
    login_payload: Mapped[dict] = mapped_column(JSON, nullable=True)
    login_headers: Mapped[dict] = mapped_column(JSON, default=dict)
    token_json_path: Mapped[str] = mapped_column(String(255), nullable=True)
    dynamic_template_path: Mapped[str] = mapped_column(String, nullable=True)
    openapi_security_scheme: Mapped[str] = mapped_column(String(100), nullable=True)
    scope_domains: Mapped[list] = mapped_column(JSON, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class PentestProfile(Base):
    """Policy bundle for production-safe pentest execution."""
    __tablename__ = "pentest_profiles"
    __table_args__ = (
        UniqueConstraint("account_id", "name", name="uq_pentest_profiles_account_name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(String, nullable=True)
    mode: Mapped[str] = mapped_column(String(20), default="SAFE")  # SAFE|BALANCED|AGGRESSIVE
    allow_state_change: Mapped[bool] = mapped_column(Boolean, default=False)
    allow_destructive_methods: Mapped[bool] = mapped_column(Boolean, default=False)
    follow_redirects: Mapped[bool] = mapped_column(Boolean, default=False)
    max_concurrency: Mapped[int] = mapped_column(Integer, default=5)
    request_timeout_seconds: Mapped[int] = mapped_column(Integer, default=15)
    auth_profile_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    attacker_role: Mapped[str] = mapped_column(String(50), default="ATTACKER")
    schemathesis_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    schemathesis_stateful: Mapped[bool] = mapped_column(Boolean, default=True)
    schemathesis_max_examples: Mapped[int] = mapped_column(Integer, default=25)
    schemathesis_workers: Mapped[int] = mapped_column(Integer, default=2)
    nuclei_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    nuclei_include_dast: Mapped[bool] = mapped_column(Boolean, default=False)
    nuclei_template_tags: Mapped[list] = mapped_column(JSON, default=list)
    zap_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class PentestArtifact(Base):
    """Generated pentest material such as configs, secret files, and run summaries."""
    __tablename__ = "pentest_artifacts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    run_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    pentest_profile_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    artifact_type: Mapped[str] = mapped_column(String(50), nullable=False)
    filename: Mapped[str] = mapped_column(String(255), nullable=True)
    content_text: Mapped[str] = mapped_column(Text, nullable=True)
    content_json: Mapped[dict] = mapped_column(JSON, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    template_id: Mapped[str] = mapped_column(String(100), nullable=True, index=True)
    endpoint_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    url: Mapped[str] = mapped_column(String, nullable=True)
    method: Mapped[str] = mapped_column(String(10), nullable=True)
    severity: Mapped[str] = mapped_column(String(50), nullable=True)
    type: Mapped[str] = mapped_column(String(100), nullable=True)
    description: Mapped[str] = mapped_column(String, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="OPEN")
    confidence: Mapped[str] = mapped_column(String(20), default="HIGH") # HIGH, MEDIUM, LOW
    remediation: Mapped[str] = mapped_column(Text, nullable=True)
    evidence: Mapped[dict] = mapped_column(JSON, nullable=True)
    false_positive: Mapped[bool] = mapped_column(Boolean, default=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=True, index=True)
    first_seen_at = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at = mapped_column(DateTime(timezone=True), nullable=True)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    sla_due_at = mapped_column(DateTime(timezone=True), nullable=True)
    ticket_url: Mapped[str] = mapped_column(String, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class TestRun(Base):
    """Tracks an execution of one or more templates against endpoints."""
    __tablename__ = "test_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    # Seven-state vocabulary (SHARED_CONTRACTS §1): PENDING, DISPATCHED, RUNNING,
    # CANCEL_REQUESTED, COMPLETED, FAILED, CANCELED. Terminal set: COMPLETED/FAILED/CANCELED.
    status: Mapped[str] = mapped_column(String(20), default="PENDING")
    template_ids: Mapped[list] = mapped_column(JSON, nullable=True)
    endpoint_ids: Mapped[list] = mapped_column(JSON, nullable=True)
    test_intensity: Mapped[str] = mapped_column(String(20), default="standard", server_default="standard", nullable=False)
    scan_plan: Mapped[dict] = mapped_column(JSON, nullable=True)
    pentest_profile_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    trigger_source: Mapped[str] = mapped_column(String(50), nullable=True, index=True)
    source_vulnerability_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    source_schedule_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    worker_id: Mapped[str] = mapped_column(String(100), nullable=True, index=True)
    dispatch_lease_expires_at = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    worker_heartbeat_at = mapped_column(DateTime(timezone=True), nullable=True)
    claim_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    total_tests: Mapped[int] = mapped_column(Integer, default=0)
    vulnerable_count: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    started_at = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at = mapped_column(DateTime(timezone=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class TestResult(Base):
    """Individual result for one template × endpoint combination."""
    __tablename__ = "test_results"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    run_id: Mapped[str] = mapped_column(String(36), nullable=True)
    endpoint_id: Mapped[str] = mapped_column(String(36), nullable=True)
    template_id: Mapped[str] = mapped_column(String(100), nullable=True)
    is_vulnerable: Mapped[bool] = mapped_column(Boolean, default=False)
    severity: Mapped[str] = mapped_column(String(50), nullable=True)
    sent_request: Mapped[dict] = mapped_column(JSON, nullable=True)
    received_response: Mapped[dict] = mapped_column(JSON, nullable=True)
    percentage_match: Mapped[float] = mapped_column(Float, default=0.0)
    evidence: Mapped[str] = mapped_column(Text, nullable=True)
    error: Mapped[str] = mapped_column(String, nullable=True)
    skip_reason: Mapped[str] = mapped_column(String, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class SampleData(Base):
    """Captured request/response pairs from traffic (feeds wordList fuzzing)."""
    __tablename__ = "sample_data"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    endpoint_id: Mapped[str] = mapped_column(String(36), nullable=True)
    request: Mapped[dict] = mapped_column(JSON, nullable=True)
    response: Mapped[dict] = mapped_column(JSON, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuthMechanism(Base):
    """Stores how auth tokens are sent for a given account/host."""
    __tablename__ = "auth_mechanisms"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000)
    name: Mapped[str] = mapped_column(String(100), nullable=True)
    header_key: Mapped[str] = mapped_column(String(100), nullable=True, default="Authorization")
    prefix: Mapped[str] = mapped_column(String(50), nullable=True, default="Bearer ")
    token_type: Mapped[str] = mapped_column(String(50), nullable=True, default="BEARER")
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class TestSchedule(Base):
    """Cron-based scheduled test runs."""
    __tablename__ = "test_schedules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=True)
    cron_expression: Mapped[str] = mapped_column(String(100), nullable=True)
    template_ids: Mapped[list] = mapped_column(JSON, nullable=True)
    endpoint_ids: Mapped[list] = mapped_column(JSON, nullable=True)
    pentest_profile_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class RequestLog(Base):
    """Lightweight request log for rate/anomaly detection."""
    __tablename__ = "request_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    endpoint_id: Mapped[str] = mapped_column(String(36), nullable=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    method: Mapped[str] = mapped_column(String(10), nullable=True)
    path: Mapped[str] = mapped_column(String, nullable=True)
    host: Mapped[str] = mapped_column(String(255), nullable=True)
    response_code: Mapped[int] = mapped_column(Integer, nullable=True)
    response_time_ms: Mapped[int] = mapped_column(Integer, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class WAFEvent(Base):
    """Security events blocked or flagged by the WAF layer."""
    __tablename__ = "waf_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    endpoint_id: Mapped[str] = mapped_column(String(36), nullable=True)
    rule_id: Mapped[str] = mapped_column(String(100), nullable=True)
    action: Mapped[str] = mapped_column(String(20), nullable=True, default="BLOCKED")  # BLOCKED/LOGGED/ALLOWED
    method: Mapped[str] = mapped_column(String(10), nullable=True)
    path: Mapped[str] = mapped_column(String, nullable=True)
    payload_snippet: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=True, default="MEDIUM")
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatActor(Base):
    __tablename__ = "threat_actors"
    __table_args__ = (
        UniqueConstraint("account_id", "source_ip", name="uq_threat_actors_account_source_ip"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    source_ip: Mapped[str] = mapped_column(String(45))
    status: Mapped[str] = mapped_column(String(20), default="MONITORING")
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    last_seen = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class MaliciousEvent(Base):
    __tablename__ = "malicious_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    actor_id: Mapped[str] = mapped_column(String(36), nullable=False)
    event_type: Mapped[str] = mapped_column(String(50))
    severity: Mapped[str] = mapped_column(String(20))
    detected_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class APICollection(Base):
    __tablename__ = "api_collections"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    name: Mapped[str] = mapped_column(String(255))
    host: Mapped[str] = mapped_column(String(255), nullable=True)
    type: Mapped[str] = mapped_column(String(50), default="MIRRORING")
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class Account(Base):
    """Represents a tenant (company/org)."""
    __tablename__ = "accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255))
    plan_tier: Mapped[str] = mapped_column(String(50), default="FREE")
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class AccountSetting(Base):
    """Persistent organization-level onboarding, identity, and license settings."""
    __tablename__ = "account_settings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True, unique=True)
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class User(Base):
    """System user belonging to an account."""
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(50), default="MEMBER", index=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class ApiToken(Base):
    """Long-lived tokens for CI/CD or integration access."""
    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    account_id: Mapped[int] = mapped_column(BigInteger, nullable=False)
    name: Mapped[str] = mapped_column(String(100))
    token_hash: Mapped[str] = mapped_column(String(255), unique=True)
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    expires_at = mapped_column(DateTime(timezone=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class Integration(Base):
    """Third-party integration configuration (Slack, Jira, PagerDuty, etc.)."""
    __tablename__ = "integrations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000)
    type: Mapped[str] = mapped_column(String(50), nullable=False)   # slack | jira | pagerduty | webhook
    name: Mapped[str] = mapped_column(String(100), nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config: Mapped[dict] = mapped_column(JSON, nullable=True)        # webhook_url, api_token, etc.
    events: Mapped[list] = mapped_column(JSON, nullable=True)        # ["vulnerability_found", "test_complete"]
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    """Immutable trail of user/system actions for security & compliance."""
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=True, index=True)
    resource_id: Mapped[str] = mapped_column(String(100), nullable=True, index=True)
    details: Mapped[dict] = mapped_column(JSON, nullable=True)
    details_encrypted: Mapped[str] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True)
    ip_address_encrypted: Mapped[str] = mapped_column(String(100), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class IngestionJob(Base):
    """Tracks async ingestion job status for backpressure + observability."""
    __tablename__ = "ingestion_jobs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    job_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    status: Mapped[str] = mapped_column(String(20), default="QUEUED", index=True)
    accepted_count: Mapped[int] = mapped_column(Integer, default=0)
    processed_count: Mapped[int] = mapped_column(Integer, default=0)
    threats_detected: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    job_metadata: Mapped[dict] = mapped_column("metadata", JSON, nullable=True)
    started_at = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at = mapped_column(DateTime(timezone=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class IngestionDeadLetter(Base):
    """Stores failed ingestion payloads for inspection/replay."""
    __tablename__ = "ingestion_dead_letters"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    job_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    payload: Mapped[dict] = mapped_column(JSON, nullable=True)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class EndpointRevision(Base):
    """Tracks endpoint schema revisions for drift detection."""
    __tablename__ = "endpoint_revisions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    endpoint_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    version_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    schema_json: Mapped[dict] = mapped_column(JSON, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class OpenAPISpec(Base):
    """Stored OpenAPI spec per account for posture validation."""
    __tablename__ = "openapi_specs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    version: Mapped[str] = mapped_column(String(50), default="1.0.0")
    spec_json: Mapped[dict] = mapped_column(JSON, nullable=False)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class PolicyViolation(Base):
    """Violation raised by governance/policy checks."""
    __tablename__ = "policy_violations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    rule_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    endpoint_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    rule_type: Mapped[str] = mapped_column(String(50), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM")
    status: Mapped[str] = mapped_column(String(20), default="OPEN")
    message: Mapped[str] = mapped_column(Text, nullable=True)
    violation_metadata: Mapped[dict] = mapped_column("metadata", JSON, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class TenantRetentionPolicy(Base):
    """Per-tenant payload retention and redaction configuration."""
    __tablename__ = "tenant_retention_policies"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True, unique=True)
    full_payload_retention: Mapped[bool] = mapped_column(Boolean, default=False)
    retain_request_headers: Mapped[bool] = mapped_column(Boolean, default=False)
    retain_response_bodies: Mapped[bool] = mapped_column(Boolean, default=False)
    retention_encryption_key_id: Mapped[str] = mapped_column(String(255), nullable=True)
    retention_period_days: Mapped[int] = mapped_column(Integer, default=90)
    pii_categories_to_retain: Mapped[list] = mapped_column(JSON, default=list)
    pii_vault_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class ResponsePlaybook(Base):
    """Automated response playbooks executed on alert creation."""
    __tablename__ = "response_playbooks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    trigger: Mapped[str] = mapped_column(String(100), nullable=False, default="alert.created")
    severity_threshold: Mapped[str] = mapped_column(String(20), default="MEDIUM")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    actions: Mapped[list] = mapped_column(JSON, default=list)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class ResponseActionLog(Base):
    """Execution log for response playbook actions."""
    __tablename__ = "response_action_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    playbook_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    alert_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    action_type: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="SUCCESS")  # SUCCESS | FAILED | SKIPPED
    details: Mapped[dict] = mapped_column(JSON, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class SensitiveDataFinding(Base):
    """Persisted PII/sensitive data finding for inventory."""
    __tablename__ = "sensitive_data_findings"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    endpoint_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    entity_type: Mapped[str] = mapped_column(String(50), nullable=True, index=True)
    sample_value: Mapped[str] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(20), nullable=True)  # request|response|header
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class EvidenceRecord(Base):
    """Evidence artifacts linked to violations, findings, or threats."""
    __tablename__ = "evidence_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    evidence_type: Mapped[str] = mapped_column(String(50), nullable=False)  # policy|pii|threat
    ref_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    endpoint_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM")
    summary: Mapped[str] = mapped_column(Text, nullable=True)
    details: Mapped[dict] = mapped_column(JSON, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class EvidencePackage(Base):
    """Replayable archive for alert/evidence events."""
    __tablename__ = "evidence_packages"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    detection_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    detection_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    path: Mapped[str] = mapped_column(String, nullable=False)
    metadata_blob: Mapped[dict] = mapped_column("metadata", JSON, nullable=True)
    digest: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class GovernanceRule(Base):
    """API governance policy rules (naming, security, schema enforcement)."""
    __tablename__ = "governance_rules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    rule_type: Mapped[str] = mapped_column(String(50), nullable=True)  # NAMING | SECURITY | SCHEMA | RATE_LIMIT
    condition: Mapped[dict] = mapped_column(JSON, nullable=True)
    action: Mapped[str] = mapped_column(String(20), default="WARN")    # WARN | BLOCK | ALERT
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    violation_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class MaliciousEventRecord(Base):
    """
    Full-fidelity malicious event — mirrors MaliciousEventMessage + SampleMaliciousRequest protos.
    Replaces the lightweight MaliciousEvent model for threat_detection dashboard ops.
    """
    __tablename__ = "malicious_event_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    # Actor / source
    actor: Mapped[str] = mapped_column(String(255), nullable=True, index=True)    # IP or actor identifier
    filter_id: Mapped[str] = mapped_column(String(100), nullable=True, index=True)
    detected_at: Mapped[int] = mapped_column(BigInteger, default=0)                # unix ms
    # Request details
    ip: Mapped[str] = mapped_column(String(45), nullable=True, index=True)
    url: Mapped[str] = mapped_column(String, nullable=True)
    method: Mapped[str] = mapped_column(String(10), nullable=True)
    host: Mapped[str] = mapped_column(String(255), nullable=True)
    api_collection_id: Mapped[int] = mapped_column(Integer, default=0, index=True)
    payload: Mapped[str] = mapped_column(Text, nullable=True)
    # Classification
    event_type: Mapped[str] = mapped_column(String(50), default="EVENT_TYPE_SINGLE")
    category: Mapped[str] = mapped_column(String(100), nullable=True, index=True)
    sub_category: Mapped[str] = mapped_column(String(100), nullable=True, index=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=True, index=True)
    type: Mapped[str] = mapped_column(String(100), nullable=True)
    label: Mapped[str] = mapped_column(String(20), nullable=True)          # threat | guardrail
    context_source: Mapped[str] = mapped_column(String(50), nullable=True)  # API | MCP | GEN_AI | AGENTIC
    session_id: Mapped[str] = mapped_column(String(100), nullable=True)
    # Status & triage
    status: Mapped[str] = mapped_column(String(30), default="OPEN")         # OPEN | IGNORED | RESOLVED
    successful_exploit: Mapped[bool] = mapped_column(Boolean, default=False)
    jira_ticket_url: Mapped[str] = mapped_column(String, nullable=True)
    country_code: Mapped[str] = mapped_column(String(10), nullable=True)
    dest_country_code: Mapped[str] = mapped_column(String(10), nullable=True)
    # Raw metadata blob (schema errors, policy info, etc.)
    event_metadata: Mapped[dict] = mapped_column(JSON, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class AgenticSession(Base):
    """
    Stores agentic session documents — mirrors SessionDocumentMessage proto.
    Tracks multi-turn LLM/agent conversations for threat analysis.
    """
    __tablename__ = "agentic_sessions"
    __table_args__ = (
        UniqueConstraint("account_id", "session_identifier", name="uq_agentic_sessions_account_session_identifier"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    session_identifier: Mapped[str] = mapped_column(String(255))
    session_summary: Mapped[str] = mapped_column(Text, nullable=True)
    conversation_info: Mapped[list] = mapped_column(JSON, default=list)   # List[ConversationEntry]
    is_malicious: Mapped[bool] = mapped_column(Boolean, default=False)
    blocked_reason: Mapped[str] = mapped_column(String, nullable=True)
    created_at_ts: Mapped[int] = mapped_column(BigInteger, default=0)     # unix ms from proto
    updated_at_ts: Mapped[int] = mapped_column(BigInteger, default=0)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class EndpointMetricHourly(Base):
    """Hourly aggregates per endpoint for analytics."""
    __tablename__ = "endpoint_metrics_hourly"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    endpoint_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    hour_ts: Mapped[int] = mapped_column(BigInteger, default=0, index=True)  # epoch hour start
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    avg_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    p95_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class ActorMetricHourly(Base):
    """Hourly aggregates per actor for analytics."""
    __tablename__ = "actor_metrics_hourly"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    hour_ts: Mapped[int] = mapped_column(BigInteger, default=0, index=True)
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    error_count: Mapped[int] = mapped_column(Integer, default=0)
    avg_latency_ms: Mapped[float] = mapped_column(Float, default=0.0)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class AlertMetricDaily(Base):
    """Daily alert counts by severity."""
    __tablename__ = "alert_metrics_daily"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    day: Mapped[str] = mapped_column(String(10), nullable=False, index=True)  # YYYY-MM-DD
    total: Mapped[int] = mapped_column(Integer, default=0)
    critical: Mapped[int] = mapped_column(Integer, default=0)
    high: Mapped[int] = mapped_column(Integer, default=0)
    medium: Mapped[int] = mapped_column(Integer, default=0)
    low: Mapped[int] = mapped_column(Integer, default=0)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class WarmExportCursor(Base):
    """Tracks last exported rows for warm store exports."""
    __tablename__ = "warm_export_cursors"
    __table_args__ = (
        UniqueConstraint("account_id", "table_name", name="uq_warm_export_cursor"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    table_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_created_at = mapped_column(DateTime(timezone=True), nullable=True)
    last_id: Mapped[str] = mapped_column(String(36), nullable=True)
    updated_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class ExternalReconFinding(Base):
    """External recon-discovered endpoint candidate."""
    __tablename__ = "external_recon_findings"
    __table_args__ = (
        UniqueConstraint("account_id", "source", "method", "host", "path_pattern", name="uq_recon_finding"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    method: Mapped[str] = mapped_column(String(10), default="GET")
    url: Mapped[str] = mapped_column(String, nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    path: Mapped[str] = mapped_column(String, nullable=False)
    path_pattern: Mapped[str] = mapped_column(String, nullable=False, index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    status: Mapped[str] = mapped_column(String(20), default="NEW")  # NEW|CONFIRMED|IGNORED
    endpoint_id: Mapped[str] = mapped_column(String(36), nullable=True)
    first_seen_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class ReconSourceConfig(Base):
    """External recon source configuration."""
    __tablename__ = "recon_sources"
    __table_args__ = (
        UniqueConstraint("account_id", "name", name="uq_recon_source_name"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    interval_seconds: Mapped[int] = mapped_column(Integer, default=86400)
    config: Mapped[dict] = mapped_column(JSON, default=dict)
    last_run_at = mapped_column(DateTime(timezone=True), nullable=True)
    next_run_at = mapped_column(DateTime(timezone=True), nullable=True)
    last_status: Mapped[str] = mapped_column(String(20), default="NEVER")
    last_error: Mapped[str] = mapped_column(Text, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class AgentIdentity(Base):
    """Tracks agent identity and trust chain metadata."""
    __tablename__ = "agent_identities"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    agent_type: Mapped[str] = mapped_column(String(50), default="ORCHESTRATOR")
    parent_agent_id: Mapped[str] = mapped_column(String(255), nullable=True)
    declared_scope: Mapped[list] = mapped_column(JSON, default=list)
    effective_scope: Mapped[list] = mapped_column(JSON, default=list)
    human_principal: Mapped[str] = mapped_column(String(255), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class MCPToolInvocation(Base):
    """Records MCP tool calls for agentic analysis."""
    __tablename__ = "mcp_tool_invocations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    tool_name: Mapped[str] = mapped_column(String(255), nullable=True)
    parameters: Mapped[dict] = mapped_column(JSON, nullable=True)
    result_excerpt: Mapped[str] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="OK")
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class AgenticViolation(Base):
    """Agentic security violations (prompt injection, trust chain, etc.)."""
    __tablename__ = "agentic_violations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    agent_id: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    violation_type: Mapped[str] = mapped_column(String(100), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM")
    details: Mapped[dict] = mapped_column(JSON, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class ThreatConfig(Base):
    """
    Singleton-per-account threat detection configuration — mirrors ThreatConfiguration proto.
    Stores actor identification rules, rate-limit config, archival settings, and ML models.
    """
    __tablename__ = "threat_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, unique=True, default=1000000)
    actor_config: Mapped[dict] = mapped_column(JSON, nullable=True)          # Actor proto serialized
    ratelimit_config: Mapped[dict] = mapped_column(JSON, nullable=True)      # RatelimitConfig proto
    param_enumeration_config: Mapped[dict] = mapped_column(JSON, nullable=True)
    archival_days: Mapped[int] = mapped_column(Integer, default=30)
    archival_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    model_store: Mapped[dict] = mapped_column(JSON, nullable=True)          # ML models storage
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


# ── New feature models ─────────────────────────────────────────────────────────

class SourceCodeRepo(Base):
    """Registered source code repository for scanning."""
    __tablename__ = "source_code_repos"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000)
    name: Mapped[str] = mapped_column(String(255))
    repo_type: Mapped[str] = mapped_column(String(50), default="LOCAL")  # LOCAL | GITHUB | GITLAB
    repo_url: Mapped[str] = mapped_column(String, nullable=True)
    local_path: Mapped[str] = mapped_column(String, nullable=True)
    branch: Mapped[str] = mapped_column(String(100), default="main")
    languages: Mapped[list] = mapped_column(JSON, default=list)
    access_token: Mapped[str] = mapped_column(String(512), nullable=True)  # GitHub/GitLab PAT
    last_scanned_at = mapped_column(DateTime(timezone=True), nullable=True)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class SourceCodeFinding(Base):
    """Static source code analysis finding."""
    __tablename__ = "source_code_findings"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000)
    repo_id: Mapped[str] = mapped_column(String(36), nullable=True)
    file_path: Mapped[str] = mapped_column(String, nullable=True)
    line_number: Mapped[int] = mapped_column(Integer, nullable=True)
    finding_type: Mapped[str] = mapped_column(String(100), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM")
    title: Mapped[str] = mapped_column(String(255), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    code_snippet: Mapped[str] = mapped_column(Text, nullable=True)
    remediation: Mapped[str] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="OPEN")
    endpoint_id: Mapped[str] = mapped_column(String(36), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class NucleiScan(Base):
    """Nuclei vulnerability scanner run."""
    __tablename__ = "nuclei_scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000)
    target: Mapped[str] = mapped_column(String, nullable=False)
    template_ids: Mapped[list] = mapped_column(JSON, default=list)
    tags: Mapped[list] = mapped_column(JSON, default=list)
    severity_filter: Mapped[list] = mapped_column(JSON, default=list)
    custom_template_ids: Mapped[list] = mapped_column(JSON, default=list)
    status: Mapped[str] = mapped_column(String(20), default="PENDING")
    findings: Mapped[list] = mapped_column(JSON, default=list)
    total_found: Mapped[int] = mapped_column(Integer, default=0)
    started_at = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at = mapped_column(DateTime(timezone=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class NucleiTemplate(Base):
    """Custom Nuclei YAML template managed by user."""
    __tablename__ = "nuclei_templates"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000)
    name: Mapped[str] = mapped_column(String(255))
    template_id: Mapped[str] = mapped_column(String(255), nullable=True)  # id field from YAML
    description: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="medium")
    tags: Mapped[list] = mapped_column(JSON, default=list)
    yaml_content: Mapped[str] = mapped_column(Text, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class APIWorkflow(Base):
    """Multi-step API sequence for chained testing."""
    __tablename__ = "api_workflows"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, nullable=True)
    steps: Mapped[list] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class APIWorkflowRun(Base):
    """Execution record for an API workflow."""
    __tablename__ = "api_workflow_runs"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    workflow_id: Mapped[str] = mapped_column(String(36), nullable=False)
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000)
    status: Mapped[str] = mapped_column(String(20), default="PENDING")
    step_results: Mapped[list] = mapped_column(JSON, default=list)
    variables: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str] = mapped_column(Text, nullable=True)
    started_at = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at = mapped_column(DateTime(timezone=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class CICDTrigger(Base):
    """CI/CD pipeline test trigger record."""
    __tablename__ = "cicd_triggers"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000)
    source: Mapped[str] = mapped_column(String(50), nullable=True)
    pipeline_id: Mapped[str] = mapped_column(String(255), nullable=True)
    commit_sha: Mapped[str] = mapped_column(String(100), nullable=True)
    branch: Mapped[str] = mapped_column(String(100), nullable=True)
    repo: Mapped[str] = mapped_column(String(255), nullable=True)
    test_run_id: Mapped[str] = mapped_column(String(36), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="PENDING")
    webhook_payload: Mapped[dict] = mapped_column(JSON, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class BillingPlan(Base):
    """Subscription billing plan definition."""
    __tablename__ = "billing_plans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(100), unique=True)
    tier: Mapped[str] = mapped_column(String(50))
    max_endpoints: Mapped[int] = mapped_column(Integer, default=100)
    max_users: Mapped[int] = mapped_column(Integer, default=5)
    max_scans_per_month: Mapped[int] = mapped_column(Integer, default=10)
    features: Mapped[list] = mapped_column(JSON, default=list)
    price_monthly_usd: Mapped[float] = mapped_column(Float, default=0.0)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class BillingSubscription(Base):
    """Account billing subscription."""
    __tablename__ = "billing_subscriptions"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, unique=True, nullable=False)
    plan_id: Mapped[str] = mapped_column(String(36), nullable=False)
    status: Mapped[str] = mapped_column(String(30), default="ACTIVE")
    scans_used_this_month: Mapped[int] = mapped_column(Integer, default=0)
    current_period_start = mapped_column(DateTime(timezone=True), nullable=True)
    current_period_end = mapped_column(DateTime(timezone=True), nullable=True)
    stripe_subscription_id: Mapped[str] = mapped_column(String(255), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class MCPEndpoint(Base):
    """MCP (Model Context Protocol) endpoint registered for shielding."""
    __tablename__ = "mcp_endpoints"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000)
    name: Mapped[str] = mapped_column(String(255))
    url: Mapped[str] = mapped_column(String, nullable=False)
    shield_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    allowed_tools: Mapped[list] = mapped_column(JSON, default=list)
    blocked_patterns: Mapped[list] = mapped_column(JSON, default=list)
    rate_limit_rpm: Mapped[int] = mapped_column(Integer, default=60)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class OAuthProvider(Base):
    """SSO / OAuth2 provider configuration."""
    __tablename__ = "oauth_providers"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000)
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    client_id: Mapped[str] = mapped_column(String(255), nullable=True)
    client_secret_enc: Mapped[str] = mapped_column(String(512), nullable=True)
    scopes: Mapped[list] = mapped_column(JSON, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    allowed_domains: Mapped[list] = mapped_column(JSON, default=list)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class BlockedIP(Base):
    """IPs blocked by the WAF/sensor layer."""
    __tablename__ = "blocked_ips"
    __table_args__ = (
        UniqueConstraint("account_id", "ip", name="uq_blocked_ips_account_ip"),
    )
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(255), nullable=True)
    blocked_by: Mapped[str] = mapped_column(String(50), default="MANUAL")  # MANUAL | AUTO | SENSOR
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    expires_at = mapped_column(DateTime(timezone=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class EndpointBlock(Base):
    """Endpoint-level circuit breaker blocks."""
    __tablename__ = "endpoint_blocks"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    endpoint_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    reason: Mapped[str] = mapped_column(String(255), nullable=True)
    blocked_by: Mapped[str] = mapped_column(String(50), default="AUTO")
    expires_at = mapped_column(DateTime(timezone=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class RateLimitOverride(Base):
    """Dynamic rate-limit overrides for endpoints."""
    __tablename__ = "rate_limit_overrides"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    endpoint_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    limit_rpm: Mapped[int] = mapped_column(Integer, default=60)
    duration_minutes: Mapped[int] = mapped_column(Integer, default=60)
    reason: Mapped[str] = mapped_column(String(255), nullable=True)
    expires_at = mapped_column(DateTime(timezone=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class Alert(Base):
    """Security alerts generated by the threat engine."""
    __tablename__ = "alerts"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), default="MEDIUM")
    category: Mapped[str] = mapped_column(String(100), nullable=True)
    source_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    endpoint: Mapped[str] = mapped_column(String(512), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="OPEN")
    acknowledged_by: Mapped[str] = mapped_column(String(100), nullable=True)
    resolved_at = mapped_column(DateTime(timezone=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class MLModel(Base):
    """Registered ML model per account."""
    __tablename__ = "ml_models"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    version: Mapped[str] = mapped_column(String(50), default="1.0.0")
    status: Mapped[str] = mapped_column(String(20), default="SHADOW")  # SHADOW | ACTIVE | DEPRECATED
    metrics: Mapped[dict] = mapped_column(JSON, nullable=True)
    artifact_path: Mapped[str] = mapped_column(String, nullable=True)
    feature_keys: Mapped[list] = mapped_column(JSON, default=list)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class MLModelRun(Base):
    """Stores inference runs for model monitoring and evaluation."""
    __tablename__ = "ml_model_runs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    model_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=True)
    endpoint_id: Mapped[str] = mapped_column(String(36), nullable=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    features: Mapped[dict] = mapped_column(JSON, nullable=True)
    is_alert: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class MLModelEvaluation(Base):
    """Offline evaluation metrics for ML models."""
    __tablename__ = "ml_model_evaluations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    model_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    sample_count: Mapped[int] = mapped_column(Integer, default=0)
    metrics: Mapped[dict] = mapped_column(JSON, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class FeatureVector(Base):
    """Feature vectors computed per actor/endpoint/time window."""
    __tablename__ = "feature_vectors"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    endpoint_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    window_start: Mapped[int] = mapped_column(BigInteger, default=0, index=True)
    features: Mapped[dict] = mapped_column(JSON, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class ActorProfile(Base):
    """Stores behavioral telemetry per actor for detection baseline."""
    __tablename__ = "actor_profiles"

    actor_id: Mapped[str] = mapped_column(String(255), primary_key=True)
    account_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, default=1000000, index=True)
    endpoint_id: Mapped[str] = mapped_column(String(36), nullable=True)
    first_seen = mapped_column(DateTime(timezone=True), nullable=True, server_default=func.now())
    last_seen = mapped_column(DateTime(timezone=True), nullable=True)
    total_events: Mapped[int] = mapped_column(Integer, default=0)
    recent_events: Mapped[int] = mapped_column(Integer, default=0)
    window_start = mapped_column(DateTime(timezone=True), nullable=True)
    avg_response_ms: Mapped[float] = mapped_column(Float, default=0.0)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    last_alert_at = mapped_column(DateTime(timezone=True), nullable=True)


class ActorBaseline(Base):
    """Baseline statistics for each actor to detect drift."""
    __tablename__ = "actor_baselines"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    endpoint_history: Mapped[list] = mapped_column(JSON, default=list)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    metadata_blob: Mapped[dict] = mapped_column("metadata", JSON, nullable=True)
    last_seen = mapped_column(DateTime(timezone=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class DetectionObjectState(Base):
    """Durable object ownership/state used by BOLA-style detectors."""
    __tablename__ = "detection_object_states"
    __table_args__ = (
        UniqueConstraint("account_id", "object_key_hash", name="uq_detection_object_state"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    object_key_hash: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    object_key_hint: Mapped[str] = mapped_column(String(255), nullable=True)
    endpoint_scope: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    last_known_owner_actor: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    last_seen_actor: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    metadata_blob: Mapped[dict] = mapped_column("metadata", JSON, nullable=True)
    first_seen = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen = mapped_column(DateTime(timezone=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class BusinessLogicGraph(Base):
    """Auto-constructed business logic graph from traffic sequences."""
    __tablename__ = "business_logic_graphs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    version: Mapped[int] = mapped_column(Integer, default=1)
    nodes_json: Mapped[list] = mapped_column(JSON, default=list)
    edges_json: Mapped[list] = mapped_column(JSON, default=list)
    built_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class BusinessLogicViolation(Base):
    """Detected workflow anomaly compared to the learned graph."""
    __tablename__ = "business_logic_violations"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    actor_id: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    from_path: Mapped[str] = mapped_column(String, nullable=True)
    to_path: Mapped[str] = mapped_column(String, nullable=True)
    violation_type: Mapped[str] = mapped_column(String(100), nullable=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.5)
    details: Mapped[dict] = mapped_column(JSON, nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())



class Sensor(Base):
    """Registered nginx log-shipper agents."""
    __tablename__ = "sensors"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=True)
    sensor_key: Mapped[str] = mapped_column(String(96), unique=True, nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(20), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="OFFLINE")
    log_path: Mapped[str] = mapped_column(String(512), nullable=True)
    lines_shipped: Mapped[int] = mapped_column(Integer, default=0)
    events_detected: Mapped[int] = mapped_column(Integer, default=0)
    last_heartbeat = mapped_column(DateTime(timezone=True), nullable=True)
    created_at = mapped_column(DateTime(timezone=True), server_default=func.now())


class JWTRevokedToken(Base):
    """Stores invalidated JWT tokens for revocation (logout/password change)."""
    __tablename__ = "jwt_revoked_tokens"
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    token_jti: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    account_id: Mapped[int] = mapped_column(BigInteger, default=1000000, index=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=True, index=True)
    revoked_at = mapped_column(DateTime(timezone=True), server_default=func.now())
    expires_at = mapped_column(DateTime(timezone=True), nullable=False)
