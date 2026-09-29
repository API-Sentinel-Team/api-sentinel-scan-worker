import asyncio
import datetime
from server.modules.persistence.database import AsyncSessionLocal
from server.models.core import APIEndpoint

async def seed():
    print("Seeding SQLite with test data...")
    async with AsyncSessionLocal() as db:
        # Create a few test endpoints
        eps = [
            APIEndpoint(
                method="GET",
                host="api.ecommerce.com",
                path="/api/v1/orders/123",
                path_pattern="/api/v1/orders/{id}",
                last_seen=datetime.datetime.now()
            ),
            APIEndpoint(
                method="POST",
                host="api.auth.io",
                path="/auth/login",
                path_pattern="/auth/login",
                last_seen=datetime.datetime.now()
            )
        ]
        db.add_all(eps)
        await db.commit()
    print("Database seeded with endpoints.")

if __name__ == "__main__":
    asyncio.run(seed())
