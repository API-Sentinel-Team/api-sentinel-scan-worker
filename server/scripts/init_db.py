import asyncio
from server.modules.persistence.database import engine
from server.models import Base
import server.models.core # Ensure models are loaded

async def init_db():
    print("Initializing SQLite database and creating tables...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Database initialized successfully.")

if __name__ == "__main__":
    asyncio.run(init_db())
