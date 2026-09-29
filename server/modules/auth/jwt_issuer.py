import jwt
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional
import logging
import uuid

class JWTError(Exception): pass
class TokenExpiredError(JWTError): pass
class InvalidTokenError(JWTError): pass
class TokenRevokedError(JWTError): pass

logger = logging.getLogger(__name__)

from server.config import settings
SECRET_KEY = settings.JWT_SECRET
ALGORITHM = settings.JWT_ALGORITHM

from server.modules.cache.redis_cache import set_json, get_json, delete

class JWTIssuer:
    """
    Handles generation and verification of JWTs for user sessions.
    Features:
    - Token revocation using Redis
    - Refresh token rotation with family tracking (detects token reuse attacks)
    - JTI claim for uniqueness
    """
    @staticmethod
    def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None, expires_in: Optional[int] = None) -> str:
        to_encode = data.copy()
        if expires_in is not None:
            expire = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        elif expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)

        jti = str(uuid.uuid4())
        to_encode.update({
            "exp": expire,
            "jti": jti,
            "iat": datetime.now(timezone.utc),
            "token_type": "access"
        })
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    @staticmethod
    def create_refresh_token(data: Dict[str, Any], family_id: Optional[str] = None) -> str:
        """
        Create a refresh token with family tracking.
        Family ID tracks a chain of token rotations for replay attack detection.
        """
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + timedelta(days=7)  # Longer lived

        jti = str(uuid.uuid4())
        family_id = family_id or str(uuid.uuid4())  # Generate new family if not rotating

        to_encode.update({
            "exp": expire,
            "jti": jti,
            "iat": datetime.now(timezone.utc),
            "token_type": "refresh",
            "family_id": family_id
        })
        encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
        return encoded_jwt

    @staticmethod
    async def verify_token(token: str, db_session=None) -> Dict[str, Any]:
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            jti = payload.get("jti")
            if jti:
                revoked_at = await get_json(f"revoked_token:{jti}")
                if revoked_at:
                    logger.warning(f"JWT revoked: {jti}")
                    raise TokenRevokedError("Token has been revoked")
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("JWT expired")
            raise TokenExpiredError("Token has expired")
        except TokenRevokedError:
            raise
        except jwt.PyJWTError as e:
            logger.warning(f"JWT decode error: {e}")
            raise InvalidTokenError(str(e))

    @staticmethod
    async def rotate_refresh_token(refresh_token: str, account_id: int, user_id: str) -> tuple[str, str]:
        """
        Rotate a refresh token and track the token family to detect reuse attacks.
        Returns (new_access_token, new_refresh_token).
        Raises TokenRevokedError if the token family has been compromised (reuse detected).
        """
        try:
            payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})

            # Verify this is a refresh token
            if payload.get("token_type") != "refresh":
                raise InvalidTokenError("Token is not a refresh token")

            jti = payload.get("jti")
            family_id = payload.get("family_id")

            # Check if this token family has already been rotated (reuse attack)
            if jti and family_id:
                rotation_record = await get_json(f"token_family:{family_id}:last_jti")
                if rotation_record and rotation_record != jti:
                    # Family has been rotated already — this is a reuse attack
                    logger.error(
                        "refresh_token_reuse_attack_detected",
                        extra={"family_id": family_id, "account_id": account_id, "user_id": user_id}
                    )
                    # Revoke entire family
                    await JWTIssuer.revoke_token_family(family_id)
                    raise TokenRevokedError("Token family compromised — refresh token reused")

            # Generate new tokens with same family ID
            access_token = JWTIssuer.create_access_token({
                "sub": payload.get("sub"),
                "email": payload.get("email"),
                "account_id": account_id,
                "role": payload.get("role")
            })

            new_refresh_token = JWTIssuer.create_refresh_token({
                "sub": payload.get("sub"),
                "email": payload.get("email"),
                "account_id": account_id,
                "role": payload.get("role")
            }, family_id=family_id)

            # Update the last used JTI in the family
            new_payload = jwt.decode(new_refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
            new_jti = new_payload.get("jti")
            await set_json(f"token_family:{family_id}:last_jti", new_jti, ttl_seconds=7*24*3600)

            logger.info("refresh_token_rotated", extra={
                "family_id": family_id, "account_id": account_id, "user_id": user_id
            })
            return access_token, new_refresh_token

        except (jwt.ExpiredSignatureError, jwt.PyJWTError) as e:
            logger.warning(f"Failed to rotate refresh token: {e}")
            raise InvalidTokenError(str(e))

    @staticmethod
    async def revoke_token_family(family_id: str) -> bool:
        """Revoke an entire token family (used when reuse attack is detected)."""
        try:
            key = f"token_family:{family_id}:last_jti"
            await delete(key)
            await set_json(f"token_family:{family_id}:revoked", True, ttl_seconds=7*24*3600)
            logger.warning(f"token_family_revoked: {family_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to revoke token family: {e}")
            return False

    @staticmethod
    async def revoke_token(token: str, account_id: int = None, user_id: str = None) -> bool:
        """Revoke a token by adding its JTI to Redis with an expiration matching the token's lifetime."""
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM], options={"verify_exp": False})
            jti = payload.get("jti")
            exp = payload.get("exp")
            if jti and exp:
                now = datetime.now(timezone.utc).timestamp()
                ttl = int(exp - now)
                if ttl > 0:
                    await set_json(f"revoked_token:{jti}", datetime.now(timezone.utc).isoformat(), ttl_seconds=ttl)
                logger.info("token_revoked", extra={"jti": jti, "account_id": account_id, "user_id": user_id})
                return True
            return False
        except jwt.PyJWTError as e:
            logger.error(f"Failed to revoke token: {e}")
            return False

    @staticmethod
    def cleanup_expired_revoked():
        """No-op as Redis handles TTL automatically."""
        pass
