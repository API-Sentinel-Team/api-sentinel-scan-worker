"""Auth Roles — manage test accounts (victim/attacker/admin tokens) for BOLA/BFLA."""
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.future import select
from sqlalchemy import and_
from sqlalchemy.ext.asyncio import AsyncSession
from server.modules.persistence.database import get_db
from server.modules.auth.rbac import Permission, RBAC
from server.models.core import TestAccount
from server.modules.identity.test_account_secrets import TestAccountSecretCodec

router = APIRouter()


@router.get("/")
async def list_auth_roles(
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ)),
    db: AsyncSession = Depends(get_db),
):
    """List all configured test accounts (Attacker, Victim, Admin)."""
    account_id = payload.get("account_id")
    result = await db.execute(
        select(TestAccount).where(TestAccount.account_id == account_id)
    )
    accounts = result.scalars().all()
    return {
        "total": len(accounts),
        "roles": [
            {
                "id": a.id,
                "name": a.name,
                "role": a.role,
                "has_token": TestAccountSecretCodec.has_secret(a),
                "created_at": str(a.created_at),
            }
            for a in accounts
        ],
    }


@router.post("/")
async def create_auth_role(
    name: str = Body(...),
    role: str = Body(..., description="ADMIN | MEMBER | ATTACKER | VICTIM"),
    auth_token: str = Body(None, description="Plain bearer token"),
    auth_headers: dict = Body(None, description='e.g. {"Authorization": "Bearer xyz"}'),
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Add a new test account with specific authorization headers."""
    account_id = payload.get("account_id")
    headers = auth_headers
    if not headers and auth_token:
        headers = {"Authorization": f"Bearer {auth_token}"}

    acct = TestAccount(
        account_id=account_id,
        name=name,
        role=role.upper(),
        **TestAccountSecretCodec.encrypt_payload(
            {
                "auth_token": auth_token,
                "auth_headers": headers,
            }
        ),
    )
    db.add(acct)
    await db.commit()
    return {
        "status": "created",
        "id": acct.id,
        "name": acct.name,
        "role": acct.role,
    }


@router.delete("/{role_id}")
async def delete_auth_role(
    role_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Remove a test account from the security engine."""
    account_id = payload.get("account_id")
    result = await db.execute(
        select(TestAccount).where(
            and_(TestAccount.id == role_id, TestAccount.account_id == account_id)
        )
    )
    acct = result.scalar_one_or_none()
    if not acct:
        raise HTTPException(status_code=404, detail="Role not found")
    await db.delete(acct)
    await db.commit()
    return {"status": "deleted", "id": role_id}


@router.get("/summary")
async def roles_summary(
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ)),
    db: AsyncSession = Depends(get_db),
):
    """Show count of each role type configured."""
    from sqlalchemy import func
    account_id = payload.get("account_id")
    result = await db.execute(
        select(TestAccount.role, func.count(TestAccount.id))
        .where(TestAccount.account_id == account_id)
        .group_by(TestAccount.role)
    )
    return {"roles": [{"role": row[0], "count": row[1]} for row in result.all()]}
