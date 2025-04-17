# Path: src/infrastructure/security/token.py
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Union, Tuple
from uuid import uuid4
from bson import ObjectId
from fastapi import Request, Depends
from jose import jwt, ExpiredSignatureError, JWTError as JoseJWTError
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import ValidationError
from redis.asyncio import Redis, ConnectionError
from src.infrastructure.storage.nosql.client import get_nosql_db
from src.infrastructure.storage.nosql.repositories.user_repository import UserRepository
from src.shared.config.settings import settings
from src.infrastructure.storage.cache.client import get_cache_client
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.errors.domain.security import InvalidCredentialsError, InvalidTokenError, UnauthorizedAccessError
from src.shared.errors.base import BaseError
from src.shared.security.payload_builder import build_jwt_payload
from src.shared.utilities.constants import HttpStatus, DomainErrorCode

logger = LoggingService(LogConfig())

# Constants
VALID_ROLES = {"user", "vendor", "admin"}
VALID_SCOPES = {"read", "write", "admin", "*"}
DEFAULT_TTL_FALLBACK = 86400
RETRY_ATTEMPTS = 3
RETRY_DELAY = 1


# Token Utility Functions
def generate_jti() -> str:
    """Generate a unique JTI."""
    jti = str(uuid4())
    logger.info("Generated JTI", context={"jti": jti})
    return jti


def get_timestamps(expires_in_minutes: int = 0, expires_in_days: int = 0) -> Tuple[int, int]:
    """Calculate issued-at and expiration timestamps."""
    now = datetime.now(timezone.utc)
    iat = int(now.timestamp())
    exp = int((now + timedelta(minutes=expires_in_minutes, days=expires_in_days)).timestamp())
    logger.info("Calculated timestamps", context={"iat": iat, "exp": exp})
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
    """Generate an access token."""
    logger.info("Starting generate_access_token", context={
        "user_id": user_id, "role": role, "session_id": session_id,
        "scopes": scopes, "language": language, "status": status,
        "phone_verified": phone_verified, "user_profile": user_profile,
        "vendor_profile": vendor_profile, "vendor_id": vendor_id, "amr": amr
    })

    if not user_id or not isinstance(user_id, str):
        raise InvalidCredentialsError(
            error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
            message="Invalid user_id: Must be a non-empty string",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"field": "user_id"},
            language="en"
        )
    if not session_id or not isinstance(session_id, str):
        raise InvalidCredentialsError(
            error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
            message="Invalid session_id: Must be a non-empty string",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"field": "session_id"},
            language="en"
        )
    if role not in VALID_ROLES:
        raise InvalidCredentialsError(
            error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
            message=f"Invalid role: Must be one of {VALID_ROLES}",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"field": "role", "valid_roles": VALID_ROLES},
            language="en"
        )
    if scopes:
        invalid_scopes = set(scopes) - VALID_SCOPES
        if invalid_scopes:
            raise InvalidCredentialsError(
                error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
                message=f"Invalid scopes: {invalid_scopes}",
                status_code=HttpStatus.BAD_REQUEST.value,
                trace_id=logger.tracer.get_trace_id(),
                details={"field": "scopes", "invalid_scopes": list(invalid_scopes)},
                language="en"
            )

    base_profile = user_profile if role == "user" else vendor_profile if role == "vendor" else None
    status = status or (base_profile.get("status") if base_profile else None)
    phone = base_profile.get("phone") if base_profile else None
    phone_verified = phone_verified if phone_verified is not None else (
        base_profile.get("phone_verified") if base_profile else None)

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
        logger.info("Access token generated successfully", context={"jti": payload["jti"], "user_id": user_id})
        return token
    except Exception as e:
        logger.error("Failed to generate access token", context={"error": str(e), "user_id": user_id})
        raise BaseError(
            error_code="TOKEN_GENERATION_FAILED",
            message=f"Failed to generate access token: {str(e)}",
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"error": str(e)},
            language="en"
        )


async def generate_temp_token(
        phone: str,
        role: str,
        jti: str,
        status: str = "incomplete",
        phone_verified: bool = False,
        language: str = "fa"
) -> str:
    """Generate a temporary token."""
    logger.info("Starting generate_temp_token", context={"phone": phone, "role": role, "jti": jti})

    if not phone or not isinstance(phone, str):
        raise InvalidCredentialsError(
            error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
            message="Invalid phone: Must be a non-empty string",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"field": "phone"},
            language="en"
        )
    if role not in VALID_ROLES:
        raise InvalidCredentialsError(
            error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
            message=f"Invalid role: Must be one of {VALID_ROLES}",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"field": "role", "valid_roles": VALID_ROLES},
            language="en"
        )
    if not jti or not isinstance(jti, str):
        raise InvalidCredentialsError(
            error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
            message="Invalid jti: Must be a non-empty string",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"field": "jti"},
            language="en"
        )

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
        logger.info("Temporary token generated successfully", context={"jti": jti, "phone": phone})
        return token
    except Exception as e:
        logger.error("Failed to generate temp token", context={"error": str(e), "phone": phone})
        raise BaseError(
            error_code="TOKEN_GENERATION_FAILED",
            message=f"Failed to generate temp token: {str(e)}",
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"error": str(e)},
            language="en"
        )


async def generate_refresh_token(
        user_id: str,
        role: str,
        session_id: str,
        status: Optional[str] = None,
        language: str = "fa",
        return_jti: bool = False
) -> Union[str, Tuple[str, str]]:
    """Generate a refresh token."""
    logger.info("Starting generate_refresh_token", context={"user_id": user_id, "role": role, "session_id": session_id})

    if not user_id or not isinstance(user_id, str):
        raise InvalidCredentialsError(
            error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
            message="Invalid user_id: Must be a non-empty string",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"field": "user_id"},
            language="en"
        )
    if not session_id or not isinstance(session_id, str):
        raise InvalidCredentialsError(
            error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
            message="Invalid session_id: Must be a non-empty string",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"field": "session_id"},
            language="en"
        )
    if role not in VALID_ROLES:
        raise InvalidCredentialsError(
            error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
            message=f"Invalid role: Must be one of {VALID_ROLES}",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"field": "role", "valid_roles": VALID_ROLES},
            language="en"
        )

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
        logger.info("Refresh token generated successfully", context={"jti": payload["jti"], "user_id": user_id})
        return (token, payload["jti"]) if return_jti else token
    except Exception as e:
        logger.error("Failed to generate refresh token", context={"error": str(e), "user_id": user_id})
        raise BaseError(
            error_code="TOKEN_GENERATION_FAILED",
            message=f"Failed to generate refresh token: {str(e)}",
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"error": str(e)},
            language="en"
        )


# Revoke Token
async def revoke_token(
        token: str,
        token_type: str = "access",
        redis: Redis = Depends(get_cache_client)
) -> None:
    """Revoke a specific token by adding it to the Redis blacklist."""
    logger.info("Starting token revocation", context={"token_type": token_type, "token_prefix": token[:10] + "..."})

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
                logger.info("Token revoked successfully", context={"jti": jti, "ttl": ttl, "attempt": attempt + 1})
                return
            except ConnectionError as e:
                logger.warning("Redis connection failed during revoke",
                               context={"jti": jti, "attempt": attempt + 1, "error": str(e)})
                if attempt < RETRY_ATTEMPTS - 1:
                    await asyncio.sleep(RETRY_DELAY)
                else:
                    logger.error("All attempts to revoke token failed, using fallback TTL",
                                 context={"jti": jti, "error": str(e)})
                    ttl = DEFAULT_TTL_FALLBACK

        logger.warning("Token revocation completed with fallback", context={"jti": jti, "ttl": ttl})
    except InvalidTokenError as e:
        logger.error("Token validation failed before revocation", context={"error": str(e)})
        raise e
    except Exception as e:
        logger.error("Unexpected error in token revocation", context={"token_type": token_type, "error": str(e)})
        raise BaseError(
            error_code="TOKEN_REVOCATION_FAILED",
            message=f"Failed to revoke token: {str(e)}",
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"error": str(e)},
            language="en"
        )


async def revoke_all_user_tokens(
        user_id: str,
        redis: Redis = Depends(get_cache_client)
) -> None:
    """Revoke all tokens and sessions associated with a user."""
    logger.info("Starting revoke_all_user_tokens", context={"user_id": user_id})

    if not user_id or not isinstance(user_id, str):
        raise InvalidCredentialsError(
            error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
            message="Invalid user_id: Must be a non-empty string",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"field": "user_id"},
            language="en"
        )

    try:
        refresh_pattern = f"refresh_tokens:{user_id}:*"
        refresh_keys_list = await redis.keys(refresh_pattern)
        logger.info("Retrieved refresh token keys", context={"user_id": user_id, "keys": refresh_keys_list})

        for key in refresh_keys_list:
            jti = key.split(":")[-1]
            for attempt in range(RETRY_ATTEMPTS):
                try:
                    await redis.delete(key)
                    await redis.setex(f"blacklist:{jti}", settings.REFRESH_TTL, "revoked")
                    logger.info("Refresh token revoked",
                                context={"user_id": user_id, "jti": jti, "attempt": attempt + 1})
                    break
                except ConnectionError as e:
                    logger.warning("Redis failure during refresh token revoke",
                                   context={"jti": jti, "attempt": attempt + 1, "error": str(e)})
                    if attempt < RETRY_ATTEMPTS - 1:
                        await asyncio.sleep(RETRY_DELAY)
                    else:
                        logger.error("Failed to revoke refresh token after retries",
                                     context={"jti": jti, "error": str(e)})

        session_pattern = f"sessions:{user_id}:*"
        session_keys_list = await redis.keys(session_pattern)
        logger.info("Retrieved session keys", context={"user_id": user_id, "keys": session_keys_list})

        for key in session_keys_list:
            for attempt in range(RETRY_ATTEMPTS):
                try:
                    await redis.delete(key)
                    logger.info("Session removed", context={"user_id": user_id, "key": key, "attempt": attempt + 1})
                    break
                except ConnectionError as e:
                    logger.warning("Redis failure during session removal",
                                   context={"key": key, "attempt": attempt + 1, "error": str(e)})
                    if attempt < RETRY_ATTEMPTS - 1:
                        await asyncio.sleep(RETRY_DELAY)
                    else:
                        logger.error("Failed to remove session after retries", context={"key": key, "error": str(e)})

        logger.info("All user tokens revoked successfully", context={"user_id": user_id})
    except Exception as e:
        logger.error("Failed to revoke all user tokens", context={"user_id": user_id, "error": str(e)})
        raise BaseError(
            error_code="TOKEN_REVOCATION_FAILED",
            message=f"Failed to revoke all tokens: {str(e)}",
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"error": str(e)},
            language="en"
        )


# Decode Token
AUDIENCE_MAP = {
    "access": "api",
    "refresh": "auth-service",
    "temp": "auth-temp",
}


async def validate_token_blacklist(jti: str, redis: Redis) -> None:
    """Check if the token is blacklisted in Redis."""
    blacklist_key = f"blacklist:{jti}"
    for attempt in range(RETRY_ATTEMPTS):
        try:
            blacklist_value = await redis.get(blacklist_key)
            logger.info("Checked token blacklist",
                        context={"key": blacklist_key, "value": blacklist_value, "attempt": attempt + 1})
            if blacklist_value:
                raise InvalidTokenError(
                    error_code="TOKEN_REVOKED",
                    message=f"Token with jti '{jti}' has been revoked",
                    status_code=HttpStatus.UNAUTHORIZED.value,
                    trace_id=logger.tracer.get_trace_id(),
                    details={"jti": jti},
                    language="en"
                )
            return
        except ConnectionError as e:
            logger.warning("Redis connection failed during blacklist check",
                           context={"jti": jti, "attempt": attempt + 1, "error": str(e)})
            if attempt < RETRY_ATTEMPTS - 1:
                await asyncio.sleep(RETRY_DELAY)
            else:
                logger.error("Failed to check blacklist after retries, assuming not revoked",
                             context={"jti": jti, "error": str(e)})
                return


async def check_refresh_token_reuse(user_id: str, jti: str, redis: Redis) -> None:
    """Detect reuse of refresh tokens."""
    redis_key = f"refresh_tokens:{user_id}:{jti}"
    for attempt in range(RETRY_ATTEMPTS):
        try:
            redis_value = await redis.get(redis_key)
            logger.info("Checked refresh token reuse",
                        context={"key": redis_key, "value": redis_value, "attempt": attempt + 1})
            if not redis_value:
                logger.error("Refresh token reuse detected", context={"user_id": user_id, "jti": jti})
                await revoke_all_user_tokens(user_id, redis)
                raise UnauthorizedAccessError(
                    resource="refresh_token",
                    error_code=DomainErrorCode.UNAUTHORIZED_ACCESS.value,
                    message="Refresh token reuse detected",
                    status_code=HttpStatus.UNAUTHORIZED.value,
                    trace_id=logger.tracer.get_trace_id(),
                    details={"jti": jti},
                    language="en"
                )
            return
        except ConnectionError as e:
            logger.warning("Redis failure during reuse check",
                           context={"jti": jti, "attempt": attempt + 1, "error": str(e)})
            if attempt < RETRY_ATTEMPTS - 1:
                await asyncio.sleep(RETRY_DELAY)
            else:
                logger.error("Failed to check refresh token reuse, assuming valid",
                             context={"jti": jti, "error": str(e)})
                return


async def decode_token(
        token: str,
        token_type: str = "access",
        redis: Redis = Depends(get_cache_client),
) -> dict:
    """Decode and validate a JWT token."""
    logger.info("Starting token decode", context={"token_type": token_type, "token_prefix": token[:10] + "..."})

    try:
        secret = settings.ACCESS_SECRET if token_type in ["access", "temp"] else settings.REFRESH_SECRET
        expected_aud = AUDIENCE_MAP.get(token_type)
        if not expected_aud:
            raise InvalidCredentialsError(
                error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
                message=f"Invalid token type: {token_type}",
                status_code=HttpStatus.BAD_REQUEST.value,
                trace_id=logger.tracer.get_trace_id(),
                details={"token_type": token_type},
                language="en"
            )
        logger.info("Using secret and audience", context={"secret": secret[:10] + "...", "audience": expected_aud})

        payload = jwt.decode(
            token,
            secret,
            algorithms=[settings.ALGORITHM],
            audience=expected_aud,
        )
        logger.info("JWT decoded", context={"payload": payload})

        actual_type = payload.get("token_type")
        if actual_type != token_type:
            logger.error("Token type mismatch", context={"expected": token_type, "actual": actual_type})
            raise InvalidTokenError(
                error_code="TOKEN_TYPE_MISMATCH",
                message=f"Token type mismatch: expected '{token_type}', got '{actual_type}'",
                status_code=HttpStatus.UNAUTHORIZED.value,
                trace_id=logger.tracer.get_trace_id(),
                details={"expected": token_type, "actual": actual_type},
                language="en"
            )

        jti = payload.get("jti")
        if not jti:
            logger.error("Missing JTI in token")
            raise InvalidTokenError(
                error_code="MISSING_JTI",
                message="Token missing required 'jti' claim",
                status_code=HttpStatus.UNAUTHORIZED.value,
                trace_id=logger.tracer.get_trace_id(),
                details={},
                language="en"
            )

        await validate_token_blacklist(jti, redis)

        if token_type == "refresh":
            user_id = payload.get("sub")
            logger.info("Checking refresh token reuse for user", context={"user_id": user_id})
            await check_refresh_token_reuse(user_id, jti, redis)

        logger.info("Token decoded successfully", context={"jti": jti, "type": token_type})
        return payload

    except ExpiredSignatureError:
        logger.error("Token expired", context={"token_type": token_type})
        raise InvalidTokenError(
            error_code="TOKEN_EXPIRED",
            message="Token expired",
            status_code=HttpStatus.UNAUTHORIZED.value,
            trace_id=logger.tracer.get_trace_id(),
            details={},
            language="en"
        )
    except JoseJWTError as e:
        logger.error("Invalid token", context={"token_type": token_type, "error": str(e)})
        raise InvalidTokenError(
            error_code="INVALID_TOKEN",
            message=f"Invalid token: {str(e)}",
            status_code=HttpStatus.UNAUTHORIZED.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"error": str(e)},
            language="en"
        )
    except ValidationError as ve:
        logger.error("Invalid JWT payload structure", context={"errors": ve.errors()})
        raise InvalidTokenError(
            error_code="INVALID_TOKEN_PAYLOAD",
            message="Invalid token payload structure",
            status_code=HttpStatus.UNAUTHORIZED.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"errors": ve.errors()},
            language="en"
        )
    except Exception as e:
        logger.error("Unexpected error in decode", context={"token_type": token_type, "error": str(e)})
        raise BaseError(
            error_code="TOKEN_DECODE_FAILED",
            message=f"Failed to decode token: {str(e)}",
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"error": str(e)},
            language="en"
        )


# Auth
async def get_token_from_header(request: Request) -> str:
    """Extract and validate the Bearer token from the Authorization header."""
    auth_header = request.headers.get("Authorization")
    logger.info("Extracting token from header",
                context={"auth_header": auth_header[:20] + "..." if auth_header else None})

    if not auth_header or not auth_header.startswith("Bearer "):
        logger.error("Invalid or missing Authorization header")
        raise UnauthorizedAccessError(
            resource="token",
            error_code=DomainErrorCode.UNAUTHORIZED_ACCESS.value,
            message="Missing or invalid Authorization header",
            status_code=HttpStatus.UNAUTHORIZED.value,
            trace_id=logger.tracer.get_trace_id(),
            details={},
            language="en"
        )

    token = auth_header.split(" ")[1].strip()
    if not token:
        logger.error("Empty token provided in Authorization header")
        raise UnauthorizedAccessError(
            resource="token",
            error_code=DomainErrorCode.UNAUTHORIZED_ACCESS.value,
            message="Empty token provided",
            status_code=HttpStatus.UNAUTHORIZED.value,
            trace_id=logger.tracer.get_trace_id(),
            details={},
            language="en"
        )

    logger.info("Token extracted successfully", context={"token_prefix": token[:10] + "..."})
    return token


async def fetch_user_from_db(collection: str, user_id: str, db: AsyncIOMotorDatabase = Depends(get_nosql_db)) -> dict:
    """Fetch user data from MongoDB."""
    logger.info("Fetching user from database", context={"collection": collection, "user_id": user_id})

    try:
        repo = UserRepository(db)
        query_id = ObjectId(user_id) if ObjectId.is_valid(user_id) else user_id
        user = await repo.find_one(collection, {"_id": query_id})
        if not user:
            logger.error("User not found in database", context={"collection": collection, "user_id": user_id})
            raise UnauthorizedAccessError(
                resource="user",
                error_code=DomainErrorCode.UNAUTHORIZED_ACCESS.value,
                message="User not found",
                status_code=HttpStatus.UNAUTHORIZED.value,
                trace_id=logger.tracer.get_trace_id(),
                details={"collection": collection, "user_id": user_id},
                language="en"
            )
        if user.get("status") != "active":
            logger.error("User account not active", context={"user_id": user_id, "status": user.get("status")})
            raise UnauthorizedAccessError(
                resource="user",
                error_code=DomainErrorCode.UNAUTHORIZED_ACCESS.value,
                message=f"Account not active (status: {user.get('status')})",
                status_code=HttpStatus.FORBIDDEN.value,
                trace_id=logger.tracer.get_trace_id(),
                details={"user_id": user_id, "status": user.get("status")},
                language="en"
            )
        logger.info("User fetched successfully", context={"user_id": user_id})
        return user
    except Exception as e:
        logger.error("Failed to fetch user from database",
                     context={"collection": collection, "user_id": user_id, "error": str(e)})
        raise BaseError(
            error_code="DATABASE_ERROR",
            message=f"Database error: {str(e)}",
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"error": str(e)},
            language="en"
        )


async def get_current_user(
        request: Request,
        redis: Redis = Depends(get_cache_client),
) -> dict:
    """Authenticate and return the current user."""
    logger.info("Starting get_current_user",
                context={"request_method": request.method, "request_url": str(request.url)})

    try:
        token = await get_token_from_header(request)
        payload_dict = await decode_token(token, token_type="access", redis=redis)

        collection_map = {
            "admin": "admins",
            "vendor": "vendors",
        }
        collection = collection_map.get(payload_dict["role"], "users")

        await fetch_user_from_db(collection, payload_dict["sub"])

        result = {
            "user_id": payload_dict["sub"],
            "role": payload_dict["role"],
            "session_id": payload_dict["session_id"],
        }
        logger.info("User authorized successfully", context=result)
        return result

    except UnauthorizedAccessError as e:
        logger.error("Authentication failed", context={"error": e.message, "status_code": e.status_code})
        raise e
    except Exception as e:
        logger.error("Unexpected error in authentication", context={"error": str(e)})
        raise UnauthorizedAccessError(
            resource="authentication",
            error_code=DomainErrorCode.UNAUTHORIZED_ACCESS.value,
            message=f"Authentication failed: {str(e)}",
            status_code=HttpStatus.UNAUTHORIZED.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"error": str(e)},
            language="en"
        )