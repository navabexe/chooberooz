import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Union, Tuple
from uuid import uuid4

from bson import ObjectId
from fastapi import Request, HTTPException, Depends
from jose import jwt, ExpiredSignatureError, JWTError as JoseJWTError
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import ValidationError
from redis.asyncio import Redis, ConnectionError

from src.infrastructure.storage.nosql.client import get_nosql_db
from src.infrastructure.storage.nosql.repositories.user_repository import UserRepository
from src.shared.config.settings import settings
from src.shared.utilities.logging import log_info, log_error, log_warning
from src.domain.authentication.models.token import TokenPayload
from src.infrastructure.storage.cache.client import get_cache_client
from src.shared.security.payload_builder import build_jwt_payload


# Constants
VALID_ROLES = {"user", "vendor", "admin"}
VALID_SCOPES = {"read", "write", "admin", "*"}
DEFAULT_TTL_FALLBACK = 86400
RETRY_ATTEMPTS = 3
RETRY_DELAY = 1


# Error Classes
class JWTError(Exception):
    def __init__(self, message: str, status_code: int = 401):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class TokenRevokedError(JWTError):
    def __init__(self, jti: str):
        super().__init__(f"Token with jti '{jti}' has been revoked", status_code=401)


class TokenTypeMismatchError(JWTError):
    def __init__(self, expected: str, actual: str):
        super().__init__(f"Token type mismatch: expected '{expected}', got '{actual}'", status_code=401)


class InvalidInputError(JWTError):
    def __init__(self, field: str, message: str):
        super().__init__(f"Invalid input for {field}: {message}", status_code=400)


# Token Utility Functions
def generate_jti() -> str:
    jti = str(uuid4())
    log_info("Generated JTI", extra={"jti": jti})
    return jti


def get_timestamps(expires_in_minutes: int = 0, expires_in_days: int = 0) -> Tuple[int, int]:
    now = datetime.now(timezone.utc)
    iat = int(now.timestamp())
    exp = int((now + timedelta(minutes=expires_in_minutes, days=expires_in_days)).timestamp())
    log_info("Calculated timestamps", extra={"iat": iat, "exp": exp})
    return iat, exp


# Token Generators
async def generate_access_token(
    user_id: str,
    role: str,
    session_id: str,
    user_profile: Optional[dict] = None,
    vendor_profile: Optional[dict] = None,
    scopes: Optional[List[str]] = None,
    language: str = "fa",
    vendor_id: Optional[str] = None,
    amr: Optional[List[str]] = None,
    status: Optional[str] = None,
    phone_verified: Optional[bool] = None
) -> str:
    log_info("Starting generate_access_token", extra={
        "user_id": user_id, "role": role, "session_id": session_id,
        "scopes": scopes, "language": language, "status": status,
        "phone_verified": phone_verified, "user_profile": user_profile,
        "vendor_profile": vendor_profile, "vendor_id": vendor_id, "amr": amr
    })

    if not user_id or not isinstance(user_id, str):
        raise InvalidInputError("user_id", "Must be a non-empty string")
    if not session_id or not isinstance(session_id, str):
        raise InvalidInputError("session_id", "Must be a non-empty string")
    if role not in VALID_ROLES:
        raise InvalidInputError("role", f"Must be one of {VALID_ROLES}")
    if scopes:
        invalid_scopes = set(scopes) - VALID_SCOPES
        if invalid_scopes:
            raise InvalidInputError("scopes", f"Invalid scopes: {invalid_scopes}")

    base_profile = user_profile if role == "user" else vendor_profile if role == "vendor" else None
    status = status or (base_profile.get("status") if base_profile else None)
    phone = base_profile.get("phone") if base_profile else None
    phone_verified = phone_verified if phone_verified is not None else (base_profile.get("phone_verified") if base_profile else None)

    payload = build_jwt_payload(
        token_type="access",
        role=role,
        subject_id=user_id,
        session_id=session_id,
        scopes=scopes,
        language=language,
        status=status,
        phone=phone,
        phone_verified=phone_verified,
        user_data=user_profile if role == "user" else None,
        vendor_data=vendor_profile if role == "vendor" else None,
        vendor_id=vendor_id,
        amr=amr,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    try:
        token = jwt.encode(payload, settings.ACCESS_SECRET, algorithm=settings.ALGORITHM)
        log_info("Access token generated successfully", extra={"jti": payload["jti"], "user_id": user_id})
        return token
    except Exception as e:
        log_error("Failed to generate access token", extra={"error": str(e), "user_id": user_id})
        raise JWTError(f"Failed to generate access token: {str(e)}", status_code=500)


async def generate_temp_token(
    phone: str,
    role: str,
    jti: str,
    status: str = "incomplete",
    phone_verified: bool = False,
    language: str = "fa"
) -> str:
    log_info("Starting generate_temp_token", extra={"phone": phone, "role": role, "jti": jti})

    if not phone or not isinstance(phone, str):
        raise InvalidInputError("phone", "Must be a non-empty string")
    if role not in VALID_ROLES:
        raise InvalidInputError("role", f"Must be one of {VALID_ROLES}")
    if not jti or not isinstance(jti, str):
        raise InvalidInputError("jti", "Must be a non-empty string")

    payload = build_jwt_payload(
        token_type="temp",
        role=role,
        subject_id=phone,
        phone=phone,
        jti=jti,
        language=language,
        status=status,
        phone_verified=phone_verified,
        expires_in=settings.TEMP_TOKEN_EXPIRE_MINUTES * 60,
    )

    try:
        token = jwt.encode(payload, settings.ACCESS_SECRET, algorithm=settings.ALGORITHM)
        log_info("Temporary token generated successfully", extra={"jti": jti, "phone": phone})
        return token
    except Exception as e:
        log_error("Failed to generate temp token", extra={"error": str(e), "phone": phone})
        raise JWTError(f"Failed to generate temp token: {str(e)}", status_code=500)


async def generate_refresh_token(
    user_id: str,
    role: str,
    session_id: str,
    status: Optional[str] = None,
    language: str = "fa",
    return_jti: bool = False
) -> Union[str, Tuple[str, str]]:
    log_info("Starting generate_refresh_token", extra={"user_id": user_id, "role": role, "session_id": session_id})

    if not user_id or not isinstance(user_id, str):
        raise InvalidInputError("user_id", "Must be a non-empty string")
    if not session_id or not isinstance(session_id, str):
        raise InvalidInputError("session_id", "Must be a non-empty string")
    if role not in VALID_ROLES:
        raise InvalidInputError("role", f"Must be one of {VALID_ROLES}")

    payload = build_jwt_payload(
        token_type="refresh",
        role=role,
        subject_id=user_id,
        session_id=session_id,
        status=status,
        language=language,
        expires_in=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
    )

    try:
        token = jwt.encode(payload, settings.REFRESH_SECRET, algorithm=settings.ALGORITHM)
        log_info("Refresh token generated successfully", extra={"jti": payload["jti"], "user_id": user_id})
        return (token, payload["jti"]) if return_jti else token
    except Exception as e:
        log_error("Failed to generate refresh token", extra={"error": str(e), "user_id": user_id})
        raise JWTError(f"Failed to generate refresh token: {str(e)}", status_code=500)


# Revoke Token
async def revoke_token(
    token: str,
    token_type: str = "access",
    redis: Redis = Depends(get_cache_client)
) -> None:
    """Revoke a specific token by adding it to the Redis blacklist after validation."""
    log_info("Starting token revocation", extra={"token_type": token_type, "token_prefix": token[:10] + "..."})

    try:
        payload = await decode_token(token, token_type, redis)
        jti = payload["jti"]
        exp = payload["exp"]
        current_time = int(datetime.now(timezone.utc).timestamp())
        ttl = max(exp - current_time, settings.ACCESS_TTL if token_type == "access" else settings.REFRESH_TTL)

        blacklist_key = f"blacklist:{jti}"
        for attempt in range(RETRY_ATTEMPTS):
            try:
                await redis.setex(blacklist_key, ttl, "revoked")
                log_info("Token revoked successfully", extra={"jti": jti, "ttl": ttl, "attempt": attempt + 1})
                return
            except ConnectionError as e:
                log_warning("Redis connection failed during revoke", extra={"jti": jti, "attempt": attempt + 1, "error": str(e)})
                if attempt < RETRY_ATTEMPTS - 1:
                    await asyncio.sleep(RETRY_DELAY)
                else:
                    log_error("All attempts to revoke token failed, using fallback TTL", extra={"jti": jti, "error": str(e)})
                    ttl = DEFAULT_TTL_FALLBACK

        log_warning("Token revocation completed with fallback", extra={"jti": jti, "ttl": ttl})
    except JWTError as e:
        log_error("Token validation failed before revocation", extra={"error": str(e)})
        raise e
    except Exception as e:
        log_error("Unexpected error in token revocation", extra={"token_type": token_type, "error": str(e)})
        raise JWTError(f"Failed to revoke token: {str(e)}", status_code=500)


async def revoke_all_user_tokens(
    user_id: str,
    redis: Redis = Depends(get_cache_client)
) -> None:
    """Revoke all tokens and sessions associated with a user with retry mechanism."""
    log_info("Starting revoke_all_user_tokens", extra={"user_id": user_id})

    if not user_id or not isinstance(user_id, str):
        raise InvalidInputError("user_id", "Must be a non-empty string")

    try:
        refresh_pattern = f"refresh_tokens:{user_id}:*"
        refresh_keys_list = await redis.keys(refresh_pattern)
        log_info("Retrieved refresh token keys", extra={"user_id": user_id, "keys": refresh_keys_list})

        for key in refresh_keys_list:
            jti = key.split(":")[-1]
            for attempt in range(RETRY_ATTEMPTS):
                try:
                    await redis.delete(key)
                    await redis.setex(f"blacklist:{jti}", settings.REFRESH_TTL, "revoked")
                    log_info("Refresh token revoked", extra={"user_id": user_id, "jti": jti, "attempt": attempt + 1})
                    break
                except ConnectionError as e:
                    log_warning("Redis failure during refresh token revoke", extra={"jti": jti, "attempt": attempt + 1, "error": str(e)})
                    if attempt < RETRY_ATTEMPTS - 1:
                        await asyncio.sleep(RETRY_DELAY)
                    else:
                        log_error("Failed to revoke refresh token after retries", extra={"jti": jti, "error": str(e)})

        session_pattern = f"sessions:{user_id}:*"
        session_keys_list = await redis.keys(session_pattern)
        log_info("Retrieved session keys", extra={"user_id": user_id, "keys": session_keys_list})

        for key in session_keys_list:
            for attempt in range(RETRY_ATTEMPTS):
                try:
                    await redis.delete(key)
                    log_info("Session removed", extra={"user_id": user_id, "key": key, "attempt": attempt + 1})
                    break
                except ConnectionError as e:
                    log_warning("Redis failure during session removal", extra={"key": key, "attempt": attempt + 1, "error": str(e)})
                    if attempt < RETRY_ATTEMPTS - 1:
                        await asyncio.sleep(RETRY_DELAY)
                    else:
                        log_error("Failed to remove session after retries", extra={"key": key, "error": str(e)})

        log_info("All user tokens revoked successfully", extra={"user_id": user_id})
    except Exception as e:
        log_error("Failed to revoke all user tokens", extra={"user_id": user_id, "error": str(e)})
        raise JWTError(f"Failed to revoke all tokens: {str(e)}", status_code=500)


# Decode Token
AUDIENCE_MAP = {
    "access": "api",
    "refresh": "auth-service",
    "temp": "auth-temp",
}


async def validate_token_blacklist(jti: str, redis: Redis) -> None:
    """Check if the token is blacklisted in Redis with retry."""
    blacklist_key = f"blacklist:{jti}"
    for attempt in range(RETRY_ATTEMPTS):
        try:
            blacklist_value = await redis.get(blacklist_key)
            log_info("Checked token blacklist", extra={"key": blacklist_key, "value": blacklist_value, "attempt": attempt + 1})
            if blacklist_value:
                raise TokenRevokedError(jti)
            return
        except ConnectionError as e:
            log_warning("Redis connection failed during blacklist check", extra={"jti": jti, "attempt": attempt + 1, "error": str(e)})
            if attempt < RETRY_ATTEMPTS - 1:
                await asyncio.sleep(RETRY_DELAY)
            else:
                log_error("Failed to check blacklist after retries, assuming not revoked", extra={"jti": jti, "error": str(e)})
                return


async def check_refresh_token_reuse(user_id: str, jti: str, redis: Redis) -> None:
    """Detect reuse of refresh tokens with retry."""
    redis_key = f"refresh_tokens:{user_id}:{jti}"
    for attempt in range(RETRY_ATTEMPTS):
        try:
            redis_value = await redis.get(redis_key)
            log_info("Checked refresh token reuse", extra={"key": redis_key, "value": redis_value, "attempt": attempt + 1})
            if not redis_value:
                log_error("Refresh token reuse detected", extra={"user_id": user_id, "jti": jti})
                await revoke_all_user_tokens(user_id, redis)
                raise HTTPException(status_code=401, detail="Refresh token reuse detected")
            return
        except ConnectionError as e:
            log_warning("Redis failure during reuse check", extra={"jti": jti, "attempt": attempt + 1, "error": str(e)})
            if attempt < RETRY_ATTEMPTS - 1:
                await asyncio.sleep(RETRY_DELAY)
            else:
                log_error("Failed to check refresh token reuse, assuming valid", extra={"jti": jti, "error": str(e)})
                return

async def decode_token(
    token: str,
    token_type: str = "access",
    redis: Redis = Depends(get_cache_client),
) -> dict:
    """Decode and validate a JWT token based on its type and blacklist status."""
    log_info("Starting token decode", extra={"token_type": token_type, "token_prefix": token[:10] + "..."})

    try:
        secret = settings.ACCESS_SECRET if token_type in ["access", "temp"] else settings.REFRESH_SECRET
        expected_aud = AUDIENCE_MAP.get(token_type)
        if not expected_aud:
            raise InvalidInputError("token_type", f"Invalid token type: {token_type}")
        log_info("Using secret and audience", extra={"secret": secret[:10] + "...", "audience": expected_aud})

        payload = jwt.decode(
            token,
            secret,
            algorithms=[settings.ALGORITHM],
            audience=expected_aud,
        )
        log_info("JWT decoded", extra={"payload": payload})

        TokenPayload(**payload)
        log_info("Token payload validated with TokenPayload model")

        actual_type = payload.get("token_type")
        if actual_type != token_type:
            log_error("Token type mismatch", extra={"expected": token_type, "actual": actual_type})
            raise TokenTypeMismatchError(expected=token_type, actual=actual_type)

        jti = payload.get("jti")
        if not jti:
            log_error("Missing JTI in token")
            raise JWTError("Token missing required 'jti' claim")

        await validate_token_blacklist(jti, redis)

        if token_type == "refresh":
            user_id = payload.get("sub")
            log_info("Checking refresh token reuse for user", extra={"user_id": user_id})
            await check_refresh_token_reuse(user_id, jti, redis)

        log_info("Token decoded successfully", extra={"jti": jti, "type": token_type})
        return payload

    except ExpiredSignatureError:
        log_error("Token expired", extra={"token_type": token_type})
        raise HTTPException(status_code=401, detail="Token expired")
    except JoseJWTError as e:
        log_error("Invalid token", extra={"token_type": token_type, "error": str(e)})
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except ValidationError as ve:
        log_error("Invalid JWT payload structure", extra={"errors": ve.errors()})
        raise HTTPException(status_code=401, detail="Invalid token payload structure")
    except Exception as e:
        log_error("Unexpected error in decode", extra={"token_type": token_type, "error": str(e)})
        raise HTTPException(status_code=500, detail=f"Failed to decode token: {str(e)}")


# Auth
def get_token_from_header(request: Request) -> str:
    """Extract and validate the Bearer token from the Authorization header."""
    auth_header = request.headers.get("Authorization")
    log_info("Extracting token from header", extra={"auth_header": auth_header[:20] + "..." if auth_header else None})

    if not auth_header or not auth_header.startswith("Bearer "):
        log_error("Invalid or missing Authorization header")
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    token = auth_header.split(" ")[1].strip()
    if not token:
        log_error("Empty token provided in Authorization header")
        raise HTTPException(status_code=401, detail="Empty token provided")

    log_info("Token extracted successfully", extra={"token_prefix": token[:10] + "..."})
    return token


async def fetch_user_from_db(collection: str, user_id: str, db: AsyncIOMotorDatabase = Depends(get_nosql_db)) -> dict:
    """Fetch user data from MongoDB based on collection and user ID."""
    log_info("Fetching user from database", extra={"collection": collection, "user_id": user_id})

    try:
        repo = UserRepository(db)
        query_id = ObjectId(user_id) if ObjectId.is_valid(user_id) else user_id
        user = await repo.find_one(collection, {"_id": query_id})
        if not user:
            log_error("User not found in database", extra={"collection": collection, "user_id": user_id})
            raise HTTPException(status_code=401, detail="User not found")
        if user.get("status") != "active":
            log_error("User account not active", extra={"user_id": user_id, "status": user.get("status")})
            raise HTTPException(
                status_code=403,
                detail=f"Account not active (status: {user.get('status')})"
            )
        log_info("User fetched successfully", extra={"user_id": user_id})
        return user
    except Exception as e:
        log_error("Failed to fetch user from database", extra={"collection": collection, "user_id": user_id, "error": str(e)})
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")

async def get_current_user(
    request: Request,
    redis: Redis = Depends(get_cache_client),
) -> dict:
    """Authenticate and return the current user based on the provided token."""
    log_info("Starting get_current_user", extra={"request_method": request.method, "request_url": str(request.url)})

    try:
        token = get_token_from_header(request)
        payload_dict = await decode_token(token, token_type="access", redis=redis)
        token_data = TokenPayload(**payload_dict)

        collection_map = {
            "admin": "admins",
            "vendor": "vendors",
        }
        collection = collection_map.get(token_data.role, "users")

        await fetch_user_from_db(collection, token_data.sub)

        result = {
            "user_id": token_data.sub,
            "role": token_data.role,
            "session_id": token_data.session_id,
        }
        log_info("User authorized successfully", extra=result)
        return result

    except HTTPException as e:
        log_error("Authentication failed with HTTP exception", extra={"status_code": e.status_code, "detail": e.detail})
        raise e
    except Exception as e:
        log_error("Unexpected error in authentication", extra={"error": str(e)})
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")