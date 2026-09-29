"""AuthMechanism CRUD - configure how auth tokens are sent per host."""
import re

from fastapi import APIRouter, Depends, Body, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, update, and_
from server.modules.persistence.database import get_db
from server.modules.auth.rbac import Permission, RBAC
from server.modules.validation.input_validator import InputValidator, ValidationError
from server.models.core import AuthMechanism

router = APIRouter()

_HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
_ALLOWED_TOKEN_TYPES = {"BEARER", "API_KEY", "BASIC", "JWT", "TOKEN", "AUTH_TOKEN"}


def _validate_header_key(value: str) -> str:
    return InputValidator.validate_string(
        value,
        "header_key",
        max_length=100,
        allow_empty=False,
        pattern=_HEADER_NAME_RE.pattern,
    )


def _validate_prefix(value: str | None) -> str:
    validated = InputValidator.validate_string(
        value or "",
        "prefix",
        max_length=50,
        allow_empty=True,
    )
    if "\r" in validated or "\n" in validated:
        raise ValidationError("prefix: Must not contain newline characters")
    return validated


def _validate_token_type(value: str) -> str:
    validated = InputValidator.validate_string(
        value,
        "token_type",
        max_length=50,
        allow_empty=False,
    ).upper()
    if validated not in _ALLOWED_TOKEN_TYPES:
        allowed = ", ".join(sorted(_ALLOWED_TOKEN_TYPES))
        raise ValidationError(f"token_type: Must be one of {allowed}")
    return validated


@router.get("/")
async def list_auth_mechanisms(
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_READ)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    result = await db.execute(
        select(AuthMechanism).where(AuthMechanism.account_id == account_id)
    )
    mechs = result.scalars().all()
    return {
        "total": len(mechs),
        "mechanisms": [
            {"id": m.id, "name": m.name, "header_key": m.header_key,
             "prefix": m.prefix, "token_type": m.token_type,
             "created_at": str(m.created_at)}
            for m in mechs
        ],
    }


@router.post("/")
async def create_auth_mechanism(
    name: str = Body(...),
    header_key: str = Body("Authorization"),
    prefix: str = Body("Bearer "),
    token_type: str = Body("BEARER", description="BEARER | API_KEY | BASIC"),
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    try:
        validated_name = InputValidator.validate_string(name, "name", max_length=100, allow_empty=False)
        validated_header_key = _validate_header_key(header_key)
        validated_prefix = _validate_prefix(prefix)
        validated_token_type = _validate_token_type(token_type)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    mech = AuthMechanism(
        account_id=account_id,
        name=validated_name,
        header_key=validated_header_key,
        prefix=validated_prefix,
        token_type=validated_token_type,
    )
    db.add(mech)
    await db.commit()
    return {"status": "created", "id": mech.id, "name": mech.name}


@router.patch("/{mech_id}")
async def update_auth_mechanism(
    mech_id: str,
    header_key: str = Body(None),
    prefix: str = Body(None),
    token_type: str = Body(None),
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    try:
        validated_mech_id = InputValidator.validate_uuid(mech_id, "mech_id")
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    values = {}
    try:
        if header_key is not None:
            values["header_key"] = _validate_header_key(header_key)
        if prefix is not None:
            values["prefix"] = _validate_prefix(prefix)
        if token_type is not None:
            values["token_type"] = _validate_token_type(token_type)
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not values:
        exists = await db.scalar(
            select(AuthMechanism.id).where(
                and_(AuthMechanism.id == validated_mech_id, AuthMechanism.account_id == account_id)
            )
        )
        if not exists:
            raise HTTPException(status_code=404, detail="Auth mechanism not found")
    else:
        result = await db.execute(
            update(AuthMechanism).where(
                and_(AuthMechanism.id == validated_mech_id, AuthMechanism.account_id == account_id)
            ).values(**values)
        )
        if not result.rowcount:
            raise HTTPException(status_code=404, detail="Auth mechanism not found")
        await db.commit()
    return {"status": "updated", "id": validated_mech_id}


@router.delete("/{mech_id}")
async def delete_auth_mechanism(
    mech_id: str,
    payload: dict = Depends(RBAC.require_permission(Permission.TESTS_MANAGE)),
    db: AsyncSession = Depends(get_db),
):
    account_id = payload.get("account_id")
    try:
        validated_mech_id = InputValidator.validate_uuid(mech_id, "mech_id")
    except ValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    result = await db.execute(
        delete(AuthMechanism).where(
            and_(AuthMechanism.id == validated_mech_id, AuthMechanism.account_id == account_id)
        )
    )
    if not result.rowcount:
        raise HTTPException(status_code=404, detail="Auth mechanism not found")
    await db.commit()
    return {"status": "deleted", "id": validated_mech_id}
