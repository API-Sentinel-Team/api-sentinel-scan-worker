"""TestAccount CRUD — manage victim/attacker tokens for BOLA/BFLA tests."""
from fastapi import APIRouter, Depends, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, and_
from server.modules.persistence.database import get_db
from server.modules.auth.rbac import Permission, RBAC
from server.models.core import TestAccount
from server.modules.identity.test_account_secrets import TestAccountSecretCodec

router = APIRouter()


@router.get("/")
async def list_accounts(
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    result = await db.execute(
        select(TestAccount).where(TestAccount.account_id == account_id)
    )
    accounts = result.scalars().all()
    return {
        "total": len(accounts),
        "accounts": [
            {"id": a.id, "name": a.name, "role": a.role,
             "has_token": TestAccountSecretCodec.has_secret(a),
             "created_at": str(a.created_at)}
            for a in accounts
        ],
    }


@router.post("/")
async def create_account(
    name: str = Body(...),
    role: str = Body(..., description="ADMIN | MEMBER | ATTACKER"),
    auth_headers: dict = Body(None, description='e.g. {"Authorization": "Bearer xyz"}'),
    auth_token: str = Body(None, description="Plain token (used if auth_headers not provided)"),
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    """Create a test account for use in BOLA/BFLA auth rotation."""
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
                "auth_headers": headers,
                "auth_token": auth_token,
            }
        ),
    )
    db.add(acct)
    await db.commit()
    return {"status": "created", "id": acct.id, "role": acct.role, "name": acct.name}


@router.delete("/{account_id_param}")
async def delete_account(
    account_id_param: str,
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    await db.execute(
        delete(TestAccount).where(
            and_(TestAccount.id == account_id_param, TestAccount.account_id == account_id)
        )
    )
    await db.commit()
    return {"status": "deleted", "id": account_id_param}


@router.get("/roles")
async def list_roles(payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ))):
    return {"roles": ["ADMIN", "MEMBER", "ATTACKER", "VIEWER"]}
