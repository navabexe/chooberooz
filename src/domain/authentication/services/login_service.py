from typing import Optional, Dict
import traceback
from uuid import uuid4
from redis.asyncio import Redis
from motor.motor_asyncio import AsyncIOMotorDatabase
from src.shared.config.settings import settings
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.errors.domain.security import InvalidCredentialsError, RateLimitExceededError
from src.shared.i18n.messages import get_message
from src.shared.utilities.constants import HttpStatus, DomainErrorCode
from src.shared.utilities.password import verify_password
from src.shared.security.permissions_loader import get_scopes_for_role
from src.infrastructure.storage.nosql.repositories.user_repository import UserRepository
from src.domain.authentication.services.session_service import create_user_session
from src.shared.utilities.time import utc_now

logger = LoggingService(LogConfig())

MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 600  # 10 minutes


class LoginService:
    """Service for handling user login operations."""

    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo

    async def check_login_attempts(
            self,
            identifier: str,
            client_ip: str,
            redis: Redis,
            language: str
    ) -> None:
        """Check and enforce login attempt limits."""
        login_key = f"login:attempt:{client_ip}:{identifier}"
        attempts = int(await redis.get(login_key) or 0)
        if attempts >= MAX_ATTEMPTS:
            await redis.setex(login_key, LOCKOUT_SECONDS, str(attempts))
            raise RateLimitExceededError(
                endpoint="login",
                limit=MAX_ATTEMPTS,
                error_code=DomainErrorCode.RATE_LIMIT_EXCEEDED.value,
                message=get_message("auth.login.too_many_attempts", language=language),
                status_code=HttpStatus.TOO_MANY_REQUESTS.value,
                trace_id=logger.tracer.get_trace_id(),
                details={"remaining_attempts": 0},
                language=language
            )

    async def increment_attempts(
            self,
            identifier: str,
            client_ip: str,
            redis: Redis
    ) -> None:
        """Increment login attempt counter."""
        login_key = f"login:attempt:{client_ip}:{identifier}"
        await redis.incr(login_key)
        await redis.expire(login_key, LOCKOUT_SECONDS)

    async def login(
            self,
            phone: Optional[str],
            username: Optional[str],
            password: str,
            client_ip: str,
            language: str = settings.DEFAULT_LANGUAGE,
            redis: Redis = None,
            db: AsyncIOMotorDatabase = None,
            request_id: Optional[str] = None,
            client_version: Optional[str] = None,
            device_fingerprint: Optional[str] = None,
            user_agent: str = "Unknown"
    ) -> Dict:
        """Authenticate user/vendor/admin and return tokens."""
        context = {
            "endpoint": "/api/v1/login",
            "request_id": request_id,
            "client_ip": client_ip,
            "user": phone or username,
            "device_fingerprint": device_fingerprint
        }
        logger.info("Starting login process", context=context)

        try:
            if not phone and not username:
                raise InvalidCredentialsError(
                    error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
                    message=get_message("auth.login.missing_credentials", language=language),
                    status_code=HttpStatus.BAD_REQUEST.value,
                    trace_id=logger.tracer.get_trace_id(),
                    language=language
                )
            if phone and username:
                raise InvalidCredentialsError(
                    error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
                    message=get_message("auth.login.too_many_credentials", language=language),
                    status_code=HttpStatus.BAD_REQUEST.value,
                    trace_id=logger.tracer.get_trace_id(),
                    language=language
                )

            identifier = (phone or username).strip().lower()
            await self.check_login_attempts(identifier, client_ip, redis, language)

            user = None
            collection = None
            if phone:
                user = await self.user_repo.find_user("users", phone) or await self.user_repo.find_user("vendors", phone)
                collection = "vendors" if (user and user.get("type") == "vendor") else "users"
            else:
                user = await self.user_repo.find_one("admins", {"username": identifier})
                collection = "admins"

            if not user:
                await self.increment_attempts(identifier, client_ip, redis)
                logger.error("User not found", context={**context, "collection": collection})
                raise InvalidCredentialsError(
                    error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
                    message=get_message("auth.login.invalid", language=language),
                    status_code=HttpStatus.UNAUTHORIZED.value,
                    trace_id=logger.tracer.get_trace_id(),
                    language=language
                )

            if not user.get("password"):
                await self.increment_attempts(identifier, client_ip, redis)
                logger.error("No password set for user", context={**context, "collection": collection})
                raise InvalidCredentialsError(
                    error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
                    message=get_message("auth.login.no_password", language=language),
                    status_code=HttpStatus.UNAUTHORIZED.value,
                    trace_id=logger.tracer.get_trace_id(),
                    language=language
                )

            try:
                if not verify_password(password, user["password"]):
                    await self.increment_attempts(identifier, client_ip, redis)
                    logger.error("Password verification failed", context={**context, "collection": collection})
                    raise InvalidCredentialsError(
                        error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
                        message=get_message("auth.login.invalid", language=language),
                        status_code=HttpStatus.UNAUTHORIZED.value,
                        trace_id=logger.tracer.get_trace_id(),
                        language=language
                    )
            except Exception as e:
                logger.error("Password verification error", context={
                    "error": str(e),
                    "trace": traceback.format_exc(),
                    **context
                })
                raise

            if user.get("status") != "active":
                logger.error("User account not active", context={
                    **context,
                    "status": user.get("status"),
                    "collection": collection
                })
                raise InvalidCredentialsError(
                    error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
                    message=get_message("auth.login.not_active", language=language),
                    status_code=HttpStatus.FORBIDDEN.value,
                    trace_id=logger.tracer.get_trace_id(),
                    language=language
                )

            await redis.delete(f"login:attempt:{client_ip}:{identifier}")

            user_id = str(user["_id"])
            role = user.get("role", "admin" if collection == "admins" else "vendor" if collection == "vendors" else "user")
            try:
                scopes = get_scopes_for_role(role, user.get("status"))
            except Exception as e:
                logger.error("Failed to get scopes", context={
                    "error": str(e),
                    "trace": traceback.format_exc(),
                    "role": role,
                    "status": user.get("status")
                })
                raise

            user_profile = {
                "first_name": user.get("first_name"),
                "last_name": user.get("last_name"),
                "email": user.get("email"),
                "phone": user.get("phone"),
                "business_name": user.get("business_name"),
                "location": user.get("location"),
                "address": user.get("address"),
                "status": user.get("status"),
                "business_category_ids": user.get("business_category_ids", []),
                "profile_picture": user.get("profile_picture"),
                "preferred_languages": user.get("preferred_languages", [])
            }

            try:
                session_result = await create_user_session(
                    user_id=user_id,
                    phone=user.get("phone"),
                    role=role,
                    user=user,
                    redis=redis,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    language=language,
                    now=utc_now()
                )
            except Exception as e:
                logger.error("Failed to create user session", context={
                    "error": str(e),
                    "trace": traceback.format_exc(),
                    **context
                })
                raise

            result = {
                "access_token": session_result["access_token"],
                "refresh_token": session_result["refresh_token"],
                "token_type": "bearer",
                "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                "role": role
            }

            logger.info("Login completed successfully", context={
                "user_id": user_id,
                "role": role,
                "client_ip": client_ip,
                "request_id": request_id
            })
            return result

        except Exception as e:
            logger.error("Login failed", context={
                "error": str(e),
                "type": str(type(e)),
                "trace": traceback.format_exc(),
                **context
            })
            raise