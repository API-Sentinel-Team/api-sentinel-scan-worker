import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_core.config import settings
from sentinel_core.models import Base

TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(autouse=True)
def allow_private_targets_in_tests(monkeypatch):
    """Suites often use localhost/127.0.0.1; production still requires an explicit allow."""
    monkeypatch.setattr(settings, "PENTEST_ALLOW_PRIVATE_TARGETS", True)


@pytest_asyncio.fixture
async def test_engine():
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(test_engine):
    Session = async_sessionmaker(bind=test_engine, expire_on_commit=False)
    async with Session() as session:
        yield session
        await session.rollback()


@pytest_asyncio.fixture
async def db(db_session):
    return db_session


@pytest.fixture
def account_id():
    return 1000000


@pytest_asyncio.fixture
async def cache():
    class MockCache:
        async def get(self, key):
            return None

        async def set(self, key, value, ttl=None):
            pass

        async def delete(self, key):
            pass

    return MockCache()
