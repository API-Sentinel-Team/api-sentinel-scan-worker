import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from sentinel_core.config import settings
from sentinel_core.models import Base
from sentinel_core.modules.persistence import database as _database  # registers the account_id ORM guard

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
    # Code under test opens its own sessions through these factories rather than taking a session
    # argument. Point them at the test database so no test depends on (or writes to) the default
    # on-disk SQLite file.
    factories = (_database.AsyncSessionLocal, _database.ReadOnlySessionLocal)
    previous = {factory: factory.kw.get("bind") for factory in factories}
    for factory in factories:
        factory.configure(bind=engine)
    yield engine
    for factory, bind in previous.items():
        factory.configure(bind=bind)
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
