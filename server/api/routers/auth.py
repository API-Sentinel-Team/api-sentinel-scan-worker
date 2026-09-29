"""Authentication — signup, login, token refresh, current user, user management."""
import secrets
import string
from fastapi import APIRouter, Depends, HTTPException, Body, Query, Response, Request
from sqlalchemy.future import select
from sqlalchemy import delete, func
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr, field_validator

from server.config import settings
from server.modules.persistence.database import get_db
from server.models.core import User, Account
from server.modules.auth.password_hasher import PasswordHasher
from server.modules.auth.jwt_issuer import JWTIssuer
from server.modules.auth.rbac import RBAC, require_admin
from server.modules.auth.audit import log_action
from server.modules.auth.auth_rate_limiter import AuthRateLimiter
from server.modules.auth.client_ip import get_client_ip
from server.modules.validation.input_validator import InputValidator, ValidationError
from server.api.rate_limiter import limiter

_VALID_ROLES = {"ADMIN", "SECURITY_ENGINEER", "DEVELOPER", "MEMBER", "AUDITOR", "VIEWER"}
_ALL_ROLES = _VALID_ROLES | {"PLATFORM_ADMIN"}


def _generate_temp_password(length: int = 16) -> str:
    """Generate a secure temporary password meeting the password policy."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.isdigit() for c in pwd) and any(c.isalpha() for c in pwd)
                and any(c in "!@#$%^&*" for c in pwd)):
            return pwd

class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    account_name: str

    @field_validator("password")
    @classmethod
    def strong_password(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters long")
        if len(v) > 72:
            raise ValueError("Password is too long (max 72 characters for bcrypt compatibility)")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(c.isalpha() for c in v):
            raise ValueError("Password must contain at least one letter")
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v):
            raise ValueError("Password must contain at least one special character")
        return v

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

router = APIRouter()

@router.post("/signup")
@limiter.limit("5/minute")
async def signup(
    req: SignupRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Create a new user and a new account for multi-tenancy."""
    try:
        # Validate account name
        validated_account_name = InputValidator.validate_string(
            req.account_name,
            "account_name",
            max_length=256,
            allow_empty=False
        )
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Check email uniqueness
    existing = await db.execute(select(User).where(User.email == req.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    # Create a new account for this user (Multi-tenancy)
    new_account = Account(name=validated_account_name, plan_tier="FREE")
    db.add(new_account)
    await db.flush() 

    pwd_hash = PasswordHasher.hash_password(req.password)
    user = User(account_id=new_account.id, email=req.email, password_hash=pwd_hash, role="ADMIN")
    db.add(user)
    await db.flush() 

    await log_action(
        db=db,
        account_id=new_account.id,
        user_id=user.id,
        action="USER_SIGNUP",
        resource_type="USER",
        resource_id=user.id,
        details={"email": user.email, "account_name": req.account_name}
    )

    await db.commit()

    token = JWTIssuer.create_access_token({
        "sub": user.id, "email": user.email,
        "account_id": new_account.id, "role": user.role,
    })
    
    # Set httpOnly cookie for security (XSS protection)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=not settings.DEBUG, # True in production
        samesite="lax",
        max_age=settings.JWT_EXPIRE_MINUTES * 60
    )

    return {
        "status": "created",
        "account_id": new_account.id,
        "user_id": user.id,
        "token_type": "bearer",
        "role": user.role,
        "message": "User registered successfully."
    }


@router.post("/login")
@limiter.limit("5/minute")
async def login(
    req: LoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate a user and return a JWT access token in cookie."""
    try:
        # Validate email format
        validated_email = InputValidator.validate_email(req.email)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Extract client IP for rate limiting (trusted proxy headers only)
    client_ip = get_client_ip(request)

    # Check brute-force rate limit
    is_allowed, rate_limit_context = await AuthRateLimiter.check_rate_limit(client_ip)
    if not is_allowed:
        retry_after = AuthRateLimiter.get_retry_after_header(rate_limit_context)
        raise HTTPException(
            status_code=429,
            detail=rate_limit_context.get("message", "Too many login attempts"),
            headers={"Retry-After": str(retry_after)}
        )

    result = await db.execute(select(User).where(User.email == validated_email))
    user = result.scalar_one_or_none()

    if not user or not PasswordHasher.verify_password(req.password, user.password_hash):
        # Record failed attempt
        await AuthRateLimiter.record_failed_attempt(client_ip)
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = JWTIssuer.create_access_token({
        "sub": user.id, "email": user.email,
        "account_id": user.account_id, "role": user.role,
    })

    # Record successful login (clears failed attempts)
    await AuthRateLimiter.record_success(client_ip)

    await log_action(
        db=db,
        account_id=user.account_id,
        user_id=user.id,
        action="USER_LOGIN",
        resource_type="USER",
        resource_id=user.id
    )
    await db.commit()

    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=not settings.DEBUG,
        samesite="lax",
        max_age=settings.JWT_EXPIRE_MINUTES * 60
    )

    return {
        "status": "authenticated",
        "token_type": "bearer",
        "role": user.role,
    }


@router.get("/me")
async def get_me(payload: dict = Depends(RBAC.require_auth)):
    """Return the current authenticated user's profile from JWT claims."""
    return {
        "user_id": payload.get("sub"),
        "email": payload.get("email"),
        "account_id": payload.get("account_id"),
        "role": payload.get("role"),
    }


@router.post("/refresh")
async def refresh_token(
    response: Response,
    payload: dict = Depends(RBAC.require_auth),
):
    """Issue a fresh token for an authenticated user (httpOnly cookie)."""
    new_token = JWTIssuer.create_access_token({
        "sub": payload["sub"], "email": payload["email"],
        "account_id": payload["account_id"], "role": payload["role"],
    })
    response.set_cookie(
        key="access_token",
        value=new_token,
        httponly=True,
        secure=not settings.DEBUG,
        samesite="lax",
        max_age=settings.JWT_EXPIRE_MINUTES * 60,
    )
    return {"status": "refreshed", "token_type": "bearer"}


@router.get("/ws-token")
async def websocket_token(payload: dict = Depends(RBAC.require_auth)):
    """
    Issue a short-lived token for WebSocket authentication.

    The session JWT lives in an httpOnly cookie, which JavaScript cannot read,
    but the /api/ws routes authenticate via the `?token=` query parameter. This
    endpoint mints a 5-minute token so the browser can open live connections
    without ever exposing the long-lived session token.
    """
    token = JWTIssuer.create_access_token(
        {
            "sub": payload["sub"],
            "email": payload["email"],
            "account_id": payload["account_id"],
            "role": payload["role"],
        },
        expires_in=300,
    )
    return {"token": token, "token_type": "bearer", "expires_in": 300}


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    payload: dict = Depends(RBAC.require_auth)
):
    """Revoke the JWT token and clear the cookie."""
    token_str = request.cookies.get("access_token")
    
    if token_str:
        await JWTIssuer.revoke_token(
            token_str,
            account_id=payload.get("account_id"),
            user_id=payload.get("sub")
        )
    
    response.delete_cookie("access_token", httponly=True, secure=not settings.DEBUG, samesite="lax")
    return {"status": "logged_out", "message": "Token has been revoked"}


# ── User Management (Admin) ───────────────────────────────────────────────────

@router.get("/users")
async def list_users(
    payload: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """List all users within the caller's own account."""
    stmt = select(User).where(User.account_id == payload["account_id"])
    result = await db.execute(stmt)
    users = result.scalars().all()
    return {
        "total": len(users),
        "users": [
            {"id": u.id, "email": u.email, "role": u.role,
             "account_id": u.account_id, "created_at": str(u.created_at)}
            for u in users
        ],
    }


class InviteUserRequest(BaseModel):
    email: EmailStr
    role: str
    name: str = ""


@router.post("/users/invite")
async def invite_user(
    req: InviteUserRequest,
    payload: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Invite a new user to the caller's account with a temporary password."""
    role_upper = req.role.upper()
    if role_upper not in _VALID_ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role '{req.role}'. Must be one of: {sorted(_VALID_ROLES)}")

    existing = await db.execute(select(User).where(User.email == req.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A user with this email already exists")

    temp_password = _generate_temp_password()
    pwd_hash = PasswordHasher.hash_password(temp_password)

    user = User(
        account_id=payload["account_id"],
        email=req.email,
        password_hash=pwd_hash,
        role=role_upper,
    )
    db.add(user)
    await db.flush()

    await log_action(
        db=db,
        account_id=payload["account_id"],
        user_id=payload.get("sub"),
        action="USER_INVITED",
        resource_type="USER",
        resource_id=user.id,
        details={"email": req.email, "role": role_upper, "invited_by": payload.get("email")},
    )
    await db.commit()

    return {
        "status": "invited",
        "user_id": user.id,
        "email": req.email,
        "role": role_upper,
        "temp_password": temp_password,
    }


@router.patch("/users/{user_id}/role")
async def update_user_role(
    user_id: str,
    role: str = Body(..., description="ADMIN | SECURITY_ENGINEER | DEVELOPER | MEMBER | AUDITOR | VIEWER"),
    payload: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update a user's role. PLATFORM_ADMIN can only be assigned by another PLATFORM_ADMIN."""
    role_upper = role.upper()
    caller_role = payload.get("role", "")

    if role_upper == "PLATFORM_ADMIN":
        if caller_role != "PLATFORM_ADMIN":
            raise HTTPException(status_code=403, detail="Only PLATFORM_ADMIN can assign PLATFORM_ADMIN role")
        allowed = _ALL_ROLES
    else:
        allowed = _VALID_ROLES

    if role_upper not in allowed:
        raise HTTPException(status_code=400, detail=f"Invalid role '{role}'. Must be one of: {sorted(allowed)}")

    result = await db.execute(select(User).where(User.id == user_id, User.account_id == payload["account_id"]))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.role = role_upper
    await log_action(
        db=db,
        account_id=payload["account_id"],
        user_id=payload.get("sub"),
        action="USER_ROLE_CHANGED",
        resource_type="USER",
        resource_id=user_id,
        details={"new_role": role_upper, "changed_by": payload.get("email")},
    )
    await db.commit()
    return {"status": "updated", "user_id": user_id, "role": user.role}


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    payload: dict = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """Delete a user account."""
    result = await db.execute(
        select(User).where(User.id == user_id, User.account_id == payload["account_id"])
    )
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    await db.delete(user)
    await db.commit()
    return {"status": "deleted", "user_id": user_id}
