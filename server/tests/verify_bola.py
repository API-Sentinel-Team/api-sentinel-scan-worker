import asyncio
import json
from server.modules.persistence.database import engine, get_db
from server.models.core import APIEndpoint, SampleData, TestAccount, Vulnerability
from sqlalchemy import select
from server.api.routers.bola import scan_endpoint_for_bola

async def test_bola():
    print("--- BOLA Verification ---")
    async with AsyncSession(engine) as session:
        async with session.begin():
            # Ensure we have an endpoint
            ep_id = "test-bola-endpoint"
            # Delete existing records if any
            await session.execute(delete(SampleData).where(SampleData.endpoint_id == ep_id))
            await session.execute(delete(APIEndpoint).where(APIEndpoint.id == ep_id))

            ep = APIEndpoint(
                id=ep_id,
                method="GET",
                path="http://httpbin.org/get",
                host="httpbin.org"
            )
            sample = SampleData(
                endpoint_id=ep_id,
                request={
                    "method": "GET",
                    "url": "http://httpbin.org/get",
                    "headers": {"Authorization": "Bearer VICTIM_TOKEN"},
                    "body": ""
                }
            )
            attacker = TestAccount(
                id="attacker-123",
                name="Evil Alice",
                role="ATTACKER",
                auth_headers={"Authorization": "Bearer ATTACKER_TOKEN"}
            )
            session.add_all([ep, sample, attacker])
            print("Inserted test data.")

    # 2. Run Scan
    # We need a session, so we'll use a local sessionmaker or just manual session
    from sqlalchemy.ext.asyncio import AsyncSession
    async with AsyncSession(engine) as session:
        print(f"Scanning endpoint {ep_id} with attacker {attacker.id}...")
        result = await scan_endpoint_for_bola(ep_id, attacker.id, db=session)
        print(f"Result: {result}")
        
        # Verify vulnerability was created
        vuln_res = await session.execute(select(Vulnerability).where(Vulnerability.endpoint_id == ep_id))
        vuln = vuln_res.scalar_one_or_none()
        if vuln:
            print(f"SUCCESS: Vulnerability logged: {vuln.description}")
        else:
            print("FAILED: Vulnerability not logged.")

if __name__ == "__main__":
    asyncio.run(test_bola())
