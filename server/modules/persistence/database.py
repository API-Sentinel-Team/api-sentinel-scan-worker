from sqlalchemy import event, inspect, text
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy.orm import Session
from server.config import settings
from server.modules.tenancy.context import get_current_account_id

_engine_kwargs = {
    "echo": False,
    "future": True,
    "pool_pre_ping": True,
}

if not settings.DATABASE_URL.startswith("sqlite"):
    _engine_kwargs.update({
        "pool_size": settings.DB_POOL_SIZE,
        "max_overflow": settings.DB_MAX_OVERFLOW,
        "pool_timeout": settings.DB_POOL_TIMEOUT,
        "pool_recycle": settings.DB_POOL_RECYCLE,
    })

engine = create_async_engine(settings.DATABASE_URL, **_engine_kwargs)

_read_engine = None
if settings.READ_REPLICA_URL:
    _read_engine = create_async_engine(settings.READ_REPLICA_URL, **_engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)

ReadOnlySessionLocal = async_sessionmaker(
    bind=_read_engine or engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
)


def _validate_account_scoped_models(session: Session, flush_context, instances) -> None:
    for obj in list(session.new) + list(session.dirty):
        if obj in session.deleted:
            continue

        mapper = inspect(obj).mapper
        if "account_id" not in mapper.columns:
            continue

        account_id = getattr(obj, "account_id", None)
        cls_name = obj.__class__.__name__

        if cls_name == "WarmExportCursor":
            if account_id is None or int(account_id) < 0:
                raise ValueError(f"{cls_name}.account_id must be >= 0")
            continue

        if account_id is None:
            raise ValueError(f"{cls_name}.account_id is required")
        if int(account_id) <= 0:
            raise ValueError(f"{cls_name}.account_id must be > 0")


event.listen(Session, "before_flush", _validate_account_scoped_models)

async def get_db():
    async with AsyncSessionLocal() as session:
        await apply_tenant_context(session)
        yield session

async def get_read_db():
    async with ReadOnlySessionLocal() as session:
        await apply_tenant_context(session)
        yield session


async def apply_tenant_context(session) -> None:
    if not settings.TENANT_RLS_ENABLED:
        return
    if "postgres" not in settings.DATABASE_URL:
        return
    account_id = get_current_account_id()
    if account_id is None:
        return
    await session.execute(
        text(f"SET LOCAL {settings.TENANT_RLS_SETTING_NAME} = :account_id"),
        {"account_id": str(account_id)},
    )
