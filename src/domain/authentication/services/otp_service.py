# Path: src/domain/authentication/services/otp_service.py
import hashlib
from datetime import datetime
from uuid import uuid4
from typing import Optional
from fastapi import Request
from enum import Enum
from motor.motor_asyncio import AsyncIOMotorDatabase
from redis.asyncio import Redis
from redis.exceptions import ConnectionError

from src.domain.authentication.services.rate_limiter import check_rate_limits, store_rate_limit_keys
from src.shared.base_service.base_service import BaseService
from src.shared.config.settings import settings
from src.shared.i18n.messages import get_message
from src.shared.logging.config import LogConfig
from src.shared.logging.service import LoggingService
from src.shared.security.token import decode_token, generate_temp_token
from src.shared.utilities.network import extract_client_ip, parse_user_agent, get_location_from_ip
from src.shared.utilities.text import generate_otp_code
from src.shared.utilities.time import utc_now
from src.shared.utilities.device_fingerprint import manage_device_fingerprint
from src.domain.notification.services.notification_service import NotificationService
from src.domain.authentication.services.session_service import SessionService, create_user_session
from src.infrastructure.storage.cache.repositories.otp_repository import OTPRepository
from src.infrastructure.storage.nosql.repositories.user_repository import UserRepository
from src.shared.errors.domain.security import InvalidCredentialsError, RateLimitExceededError
from src.shared.errors.infrastructure.database import CacheError
from src.shared.utilities.types import LanguageCode
from src.shared.utilities.constants import HttpStatus, DomainErrorCode


class UserStatus(str, Enum):
    """Enum for user status."""
    INCOMPLETE = "incomplete"
    PENDING = "pending"
    ACTIVE = "active"


def hash_otp(otp: str) -> str:
    """Hash OTP with salt for secure storage."""
    salted = f"{settings.OTP_SALT}:{otp}"
    return hashlib.sha256(salted.encode()).hexdigest()


def get_otp_keys(role: str, phone: str, jti: str) -> dict:
    """Generate Redis keys for OTP storage."""
    return {
        "otp_key": f"otp:{role}:{phone}",
        "temp_token_key": f"temp_token:{jti}",
        "used_token_key": f"temp_token_used:{phone}",
        "attempt_key": f"otp-attempts:{role}:{phone}",
        "expired_attempt_key": f"otp-expired-attempts:{role}:{phone}",
        "token_expired_attempt_key": f"token-expired-attempts:{role}:{phone}",
        "block_key": f"otp-blocked:{role}:{phone}"
    }


class OTPNotifier:
    """Handles OTP notifications."""

    def __init__(self, notification_service: NotificationService):
        self.notification_service = notification_service

    async def send_otp(self, phone: str, role: str, otp_code: str, purpose: str, language: LanguageCode,
                       db: AsyncIOMotorDatabase) -> bool:
        """Send OTP notification to user."""
        try:
            result = await self.notification_service.send(
                receiver_id=phone,
                receiver_type=role,
                template_key="otp_requested",
                variables={"phone": phone, "otp": otp_code, "purpose": purpose},
                reference_type="otp",
                reference_id=phone,
                language=language,
                return_bool=True,
                additional_receivers=[{"id": "admin", "type": "admin"}],
                db=db
            )
            self.notification_service.logger.info("OTP notification sent",
                                                  context={"phone": phone, "role": role, "purpose": purpose})
            return result
        except Exception as e:
            self.notification_service.logger.error("Failed to send OTP notification",
                                                   context={"error": str(e), "phone": phone})
            return False

    async def send_verified(self, phone: str, role: str, language: LanguageCode, db: AsyncIOMotorDatabase) -> bool:
        """Send notification after OTP verification."""
        try:
            result = await self.notification_service.send_otp_verified(phone, role, language, db=db)
            self.notification_service.logger.info("OTP verified notification sent",
                                                  context={"phone": phone, "role": role})
            return result
        except Exception as e:
            self.notification_service.logger.error("Failed to send verified notification",
                                                   context={"error": str(e), "phone": phone})
            return False


class OTPStorageHandler:
    """Handles OTP storage and validation."""

    def __init__(self, otp_repo: OTPRepository, notifier: OTPNotifier):
        self.otp_repo = otp_repo
        self.notifier = notifier
        self.logger = LoggingService(LogConfig())

    async def store(self, phone: str, role: str, otp_hash: str, jti: str, language: LanguageCode):
        """Store OTP-related data in Redis."""
        try:
            keys = get_otp_keys(role, phone, jti)
            await self.otp_repo.setex(keys["otp_key"], settings.OTP_EXPIRY, otp_hash)
            await self.otp_repo.setex(keys["temp_token_key"], settings.OTP_EXPIRY, phone)
            await self.otp_repo.setex(keys["used_token_key"], settings.OTP_EXPIRY, "generated")
            await store_rate_limit_keys(phone, role, self.otp_repo)
            self.logger.info("Stored OTP keys", context={
                "otp_key": keys["otp_key"],
                "temp_token_key": keys["temp_token_key"],
                "phone": phone,
                "role": role,
                "jti": jti,
                "expiry": settings.OTP_EXPIRY
            })
            stored_otp = await self.otp_repo.get(keys["otp_key"])
            stored_phone = await self.otp_repo.get(keys["temp_token_key"])
            if not stored_otp or not stored_phone:
                self.logger.error("Failed to verify OTP storage", context={
                    "otp_key": keys["otp_key"],
                    "temp_token_key": keys["temp_token_key"]
                })
                raise InvalidCredentialsError(
                    error_code=DomainErrorCode.STORAGE_ERROR.value,
                    message=get_message("server.error", language=language),
                    status_code=HttpStatus.BAD_REQUEST.value,
                    trace_id=self.logger.tracer.get_trace_id(),
                    details={"otp_key": keys["otp_key"], "temp_token_key": keys["temp_token_key"]},
                    language=language
                )
        except ConnectionError as e:
            self.logger.error("Redis connection failed during OTP storage", context={"error": str(e)})
            raise CacheError(
                operation="store",
                error_code=DomainErrorCode.REDIS_ERROR.value,
                message=get_message("server.error", language=language),
                status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"error": str(e)},
                language=language
            )

    async def validate(
            self,
            otp: str,
            jti: str,
            phone: str,
            role: str,
            language: LanguageCode,
            db: AsyncIOMotorDatabase,
            client_ip: str = "unknown",
            request_id: str = "unknown",
            client_version: str = "unknown",
            device_fingerprint: Optional[str] = None,
            user_agent: str = "unknown"
    ) -> bool:
        """Validate OTP against stored data."""
        try:
            keys = get_otp_keys(role, phone, jti)
            stored_otp = await self.otp_repo.get(keys["otp_key"])
            stored_phone = await self.otp_repo.get(keys["temp_token_key"])
            self.logger.info("Attempting OTP validation", context={
                "otp_key": keys["otp_key"],
                "temp_token_key": keys["temp_token_key"],
                "phone": phone,
                "role": role,
                "jti": jti,
                "client_ip": client_ip
            })

            if not stored_otp or not stored_phone:
                attempts = await self.otp_repo.incr(keys["expired_attempt_key"])
                await self.otp_repo.expire(keys["expired_attempt_key"], settings.OTP_ATTEMPT_EXPIRY or 3600)
                self.logger.error("OTP expired or missing", context={**keys, "expired_attempts": attempts})

                await OTPLogger(self.otp_repo).log_failed_attempt(
                    phone=phone,
                    role=role,
                    reason="OTP_EXPIRED",
                    client_ip=client_ip,
                    request_id=request_id,
                    client_version=client_version,
                    device_fingerprint=device_fingerprint,
                    user_agent=user_agent
                )

                if attempts >= settings.MAX_OTP_EXPIRED_ATTEMPTS:
                    await self.otp_repo.setex(keys["block_key"], settings.BLOCK_DURATION_OTP, "1")
                    self.logger.error("Blocked due to too many expired OTP attempts",
                                      context={"phone": phone, "attempts": attempts})
                    await self.notifier.notification_service.send(
                        receiver_id="admin",
                        receiver_type="admin",
                        template_key="notification_failed",
                        variables={"receiver_id": phone, "error": "Too many expired OTP attempts", "type": "security"},
                        reference_type="otp",
                        reference_id=phone,
                        language=language,
                        db=db
                    )
                    raise RateLimitExceededError(
                        endpoint="otp_verify",
                        limit=settings.MAX_OTP_EXPIRED_ATTEMPTS,
                        error_code=DomainErrorCode.OTP_EXPIRED_RATE_LIMIT.value,
                        message=get_message("otp.too_many.attempts", language=language),
                        status_code=HttpStatus.TOO_MANY_REQUESTS.value,
                        trace_id=self.logger.tracer.get_trace_id(),
                        details={"phone": phone, "attempts": attempts},
                        language=language
                    )

                raise InvalidCredentialsError(
                    error_code=DomainErrorCode.OTP_EXPIRED.value,
                    message=get_message("otp.expired", language=language),
                    status_code=HttpStatus.BAD_REQUEST.value,
                    trace_id=self.logger.tracer.get_trace_id(),
                    details={"phone": phone, "remaining_attempts": settings.MAX_OTP_EXPIRED_ATTEMPTS - attempts},
                    language=language
                )

            if stored_phone != phone or hash_otp(otp) != stored_otp:
                self.logger.error("OTP mismatch", context={
                    "expected_phone": stored_phone,
                    "input_phone": phone,
                    "expected_hash": stored_otp[:10],
                    "computed_hash": hash_otp(otp)[:10]
                })
                return False
            return True
        except ConnectionError as e:
            self.logger.error("Redis connection failed during OTP validation", context={"error": str(e)})
            raise CacheError(
                operation="validate",
                error_code=DomainErrorCode.REDIS_ERROR.value,
                message=get_message("server.error", language=language),
                status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"error": str(e)},
                language=language
            )

    async def clear(self, phone: str, role: str, jti: str, language: LanguageCode):
        """Clear OTP-related data from Redis."""
        try:
            keys = get_otp_keys(role, phone, jti)
            await self.otp_repo.delete(keys["otp_key"])
            await self.otp_repo.delete(keys["temp_token_key"])
            await self.otp_repo.delete(keys["attempt_key"])
            await self.otp_repo.delete(keys["expired_attempt_key"])
            await self.otp_repo.delete(keys["token_expired_attempt_key"])
            self.logger.info("Cleared OTP keys", context={"otp_key": keys["otp_key"], "phone": phone, "role": role})
        except ConnectionError as e:
            self.logger.error("Redis connection failed during OTP clear", context={"error": str(e)})
            raise CacheError(
                operation="clear",
                error_code=DomainErrorCode.REDIS_ERROR.value,
                message=get_message("server.error", language=language),
                status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"error": str(e)},
                language=language
            )


class OTPLogger:
    """Handles OTP logging."""

    def __init__(self, user_repo: UserRepository):
        self.user_repo = user_repo
        self.logger = LoggingService(LogConfig())

    async def log_request(
            self,
            phone: str,
            role: str,
            purpose: str,
            request: Request,
            request_id: str,
            client_version: str,
            device_fingerprint: Optional[str],
            jti: str,
            otp_code: str
    ):
        """Log OTP request event."""
        client_ip = await extract_client_ip(request)
        location = await get_location_from_ip(client_ip)
        agent = parse_user_agent(request.headers.get("User-Agent", "Unknown"))
        log_data = {
            "entity_type": "otp",
            "entity_id": phone,
            "action": "requested",
            "client_ip": client_ip,
            "request_id": request_id,
            "client_version": client_version,
            "device_fingerprint": device_fingerprint,
            "role": role,
            "purpose": purpose,
            "jti": jti,
            "otp": otp_code if settings.ENVIRONMENT == "development" else None,
            "location": location,
            **agent
        }
        await self.user_repo.log_audit("otp_requested", log_data)
        self.logger.info("OTP request logged", context=log_data)

    async def log_verified(
            self,
            phone: str,
            role: str,
            status: str,
            user_id: str,
            client_ip: str,
            request_id: str,
            client_version: str,
            device_fingerprint: Optional[str]
    ):
        """Log OTP verification event."""
        location = await get_location_from_ip(client_ip)
        log_data = {
            "entity_type": "otp",
            "entity_id": phone,
            "action": "verified",
            "client_ip": client_ip,
            "request_id": request_id,
            "client_version": client_version,
            "device_fingerprint": device_fingerprint,
            "role": role,
            "status": status,
            "user_id": user_id,
            "location": location
        }
        await self.user_repo.log_audit("otp_verified", log_data)
        self.logger.info("OTP verification logged", context=log_data)

    async def log_failed_attempt(
            self,
            phone: str,
            role: str,
            reason: str,
            client_ip: str,
            request_id: str,
            client_version: str,
            device_fingerprint: Optional[str],
            user_agent: str
    ):
        """Log failed OTP attempt."""
        location = await get_location_from_ip(client_ip)
        agent = parse_user_agent(user_agent)
        log_data = {
            "entity_type": "otp",
            "entity_id": phone,
            "action": "failed",
            "client_ip": client_ip,
            "request_id": request_id,
            "client_version": client_version,
            "device_fingerprint": device_fingerprint,
            "role": role,
            "reason": reason,
            "location": location,
            **agent
        }
        await self.user_repo.log_audit("otp_failed", log_data)
        self.logger.info("Failed OTP attempt logged", context=log_data)


class OTPService(BaseService):
    """Service for handling OTP operations."""

    def __init__(
            self,
            otp_repo: OTPRepository,
            user_repo: UserRepository,
            notification_service: NotificationService,
            session_service: SessionService
    ):
        super().__init__()
        self.otp_repo = otp_repo
        self.user_repo = user_repo
        self.notifier = OTPNotifier(notification_service)
        self.logger = OTPLogger(user_repo)
        self.storage = OTPStorageHandler(otp_repo, self.notifier)
        self.session_service = session_service

    async def generate_otp_and_token(self, phone: str, role: str, language: LanguageCode) -> tuple[str, str, str]:
        """Generate OTP and temporary token."""
        otp_code = generate_otp_code()
        jti = str(uuid4())
        temp_token = await generate_temp_token(
            phone=phone,
            role=role,
            jti=jti,
            status=UserStatus.INCOMPLETE,
            phone_verified=False,
            language=language
        )
        self.logger.logger.info("Generated OTP and temp token", context={"phone": phone, "jti": jti})
        return otp_code, temp_token, jti

    async def request_otp(
            self,
            phone: str,
            role: str,
            purpose: str,
            request: Request,
            language: LanguageCode = settings.DEFAULT_LANGUAGE,
            redis: Redis = None,
            db: AsyncIOMotorDatabase = None,
            request_id: str = None,
            client_version: str = None,
            device_fingerprint: Optional[str] = None,
            user_agent: str = "Unknown"
    ) -> dict:
        """Request an OTP and send it to user."""
        context = {
            "entity_type": "otp",
            "entity_id": phone,
            "action": "requested",
            "endpoint": "/api/v1/request-otp",
            "request_id": request_id
        }

        async def operation():
            await check_rate_limits(phone, role, self.otp_repo, language)

            # Handle device fingerprint
            await manage_device_fingerprint(redis, role, phone, device_fingerprint, language)

            otp_code, temp_token, jti = await self.generate_otp_and_token(phone, role, language)
            await self.storage.store(phone, role, hash_otp(otp_code), jti, language)
            await self.logger.log_request(phone, role, purpose, request, request_id, client_version, device_fingerprint,
                                          jti, otp_code)
            notification_sent = await self.notifier.send_otp(phone, role, otp_code, purpose, language, db)
            return {
                "temporary_token": temp_token,
                "expires_in": settings.OTP_EXPIRY,
                "notification_sent": notification_sent,
                "message": get_message("otp.sent", language=language)
            }

        return await self.execute(operation, context, language)

    async def handle_verification_result(
            self,
            user: dict,
            user_id: str,
            phone: str,
            role: str,
            status: str,
            redis: Redis,
            client_ip: str,
            user_agent: str,
            language: LanguageCode,
            now: datetime
    ) -> dict:
        """Handle OTP verification result based on user status."""
        if status in [UserStatus.INCOMPLETE, UserStatus.PENDING]:
            new_jti = str(uuid4())
            temp_token = await generate_temp_token(
                phone=phone, role=role, jti=new_jti, status=status, phone_verified=True, language=language
            )
            await self.otp_repo.setex(f"temp_token:{new_jti}", settings.TEMP_TOKEN_EXPIRY, phone)
            return {
                "status": status,
                "temporary_token": temp_token,
                "message": get_message(
                    "auth.profile.incomplete" if status == UserStatus.INCOMPLETE else "auth.profile.pending",
                    language=language
                ),
                "phone": phone
            }

        if status == UserStatus.ACTIVE:
            await self.session_service.delete_incomplete_sessions(user_id)
            updated_user = await self.user_repo.find_user(f"{role}s", phone)
            session_result = await create_user_session(
                user_id=user_id,
                phone=phone,
                role=role,
                user=updated_user,
                redis=redis,
                client_ip=client_ip,
                user_agent=user_agent,
                language=language,
                now=now
            )
            session_result["message"] = get_message("otp.valid", language=language)
            return session_result

        raise InvalidCredentialsError(
            error_code=DomainErrorCode.INVALID_STATUS.value,
            message=get_message("server.error", language=language),
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=self.logger.logger.tracer.get_trace_id(),
            details={"status": status},
            language=language
        )

    async def update_user_after_verification(
            self,
            phone: str,
            role: str,
            language: LanguageCode,
            db: AsyncIOMotorDatabase
    ) -> tuple[dict, str]:
        """Insert or update user after OTP verification."""
        collection = f"{role}s"
        user = await self.user_repo.find_user(collection, phone)
        now = utc_now()

        if not user:
            user_data = self.create_user_data(phone, role, language, now)
            user_id = await self.user_repo.insert_user(collection, user_data)
            return {**user_data, "_id": user_id}, str(user_id)

        user_id = str(user["_id"])
        update_fields = {"updated_at": now}
        if not user.get("phone_verified"):
            update_fields["phone_verified"] = True
        if not user.get("preferred_languages"):
            update_fields["preferred_languages"] = [language]

        if update_fields:
            await self.user_repo.update_user(collection, user_id, update_fields)

        return user, user_id

    def create_user_data(self, phone: str, role: str, language: LanguageCode, now: datetime) -> dict:
        """Generate initial user record."""
        return {
            "phone": phone,
            "role": role,
            "status": UserStatus.INCOMPLETE,
            "phone_verified": True,
            "preferred_languages": [language],
            "created_at": now,
            "updated_at": now
        }

    async def handle_failed_verification(
            self,
            otp: str,
            temporary_token: str,
            phone: str,
            role: str,
            language: LanguageCode,
            db: AsyncIOMotorDatabase
    ):
        """Track failed OTP attempts and block if limit exceeded."""
        try:
            payload = await decode_token(temporary_token, token_type="temp", redis=self.otp_repo.redis)
            jti = payload.get("jti")
            keys = get_otp_keys(role, phone, jti)
            attempts = await self.otp_repo.incr(keys["attempt_key"])
            await self.otp_repo.expire(keys["attempt_key"], settings.OTP_ATTEMPT_EXPIRY or 3600)
            self.logger.logger.info("Incremented OTP attempt", context={"phone": phone, "attempts": attempts})

            if int(attempts) >= settings.MAX_OTP_ATTEMPTS:
                await self.storage.clear(phone, role, jti, language)
                await self.otp_repo.setex(keys["block_key"], settings.BLOCK_DURATION_OTP, "1")
                await self.notifier.notification_service.send(
                    receiver_id="admin",
                    receiver_type="admin",
                    template_key="notification_failed",
                    variables={"receiver_id": phone, "error": "Too many OTP attempts", "type": "security"},
                    reference_type="otp",
                    reference_id=phone,
                    language=language,
                    db=db
                )
                raise RateLimitExceededError(
                    endpoint="otp_verify",
                    limit=settings.MAX_OTP_ATTEMPTS,
                    error_code=DomainErrorCode.OTP_RATE_LIMIT.value,
                    message=get_message("otp.too_many.attempts", language=language),
                    status_code=HttpStatus.TOO_MANY_REQUESTS.value,
                    trace_id=self.logger.logger.tracer.get_trace_id(),
                    details={"phone": phone, "attempts": attempts},
                    language=language
                )

            remaining = settings.MAX_OTP_ATTEMPTS - int(attempts)
            raise InvalidCredentialsError(
                error_code=DomainErrorCode.OTP_INVALID.value,
                message=get_message("otp.invalid", language=language),
                status_code=HttpStatus.BAD_REQUEST.value,
                trace_id=self.logger.logger.tracer.get_trace_id(),
                details={"remaining_attempts": remaining},
                language=language
            )
        except ConnectionError as e:
            self.logger.logger.error("Redis connection failed during attempt tracking", context={"error": str(e)})
            raise CacheError(
                operation="attempt_tracking",
                error_code=DomainErrorCode.REDIS_ERROR.value,
                message=get_message("server.error", language=language),
                status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
                trace_id=self.logger.logger.tracer.get_trace_id(),
                details={"error": str(e)},
                language=language
            )

    async def verify_otp(
            self,
            otp: str,
            temporary_token: str,
            client_ip: str,
            language: LanguageCode = settings.DEFAULT_LANGUAGE,
            redis: Redis = None,
            db: AsyncIOMotorDatabase = None,
            request_id: str = None,
            client_version: str = None,
            device_fingerprint: Optional[str] = None,
            user_agent: str = "Unknown"
    ) -> dict:
        """Verify OTP and create/update user session."""
        context = {
            "entity_type": "otp",
            "entity_id": "unknown",
            "action": "verified",
            "endpoint": "/api/v1/verify-otp",
            "request_id": request_id
        }

        async def operation():
            payload = await decode_token(temporary_token, token_type="temp", redis=redis)
            phone = payload.get("sub")
            role = payload.get("role")
            jti = payload.get("jti")
            status = payload.get("status")
            context["entity_id"] = phone

            if not phone or not role or not jti:
                raise InvalidCredentialsError(
                    error_code=DomainErrorCode.INVALID_TOKEN.value,
                    message=get_message("token.invalid", language=language),
                    status_code=HttpStatus.BAD_REQUEST.value,
                    trace_id=self.logger.logger.tracer.get_trace_id(),
                    details={},
                    language=language
                )

            keys = get_otp_keys(role, phone, jti)
            temp_token_key = keys["temp_token_key"]
            if not await self.otp_repo.get(temp_token_key):
                attempts = await self.otp_repo.incr(keys["token_expired_attempt_key"])
                await self.otp_repo.expire(keys["token_expired_attempt_key"], settings.OTP_ATTEMPT_EXPIRY or 3600)
                self.logger.logger.error("Temporary token missing or expired",
                                         context={"jti": jti, "phone": phone, "attempts": attempts})

                await self.logger.log_failed_attempt(
                    phone=phone,
                    role=role,
                    reason="TOKEN_EXPIRED",
                    client_ip=client_ip,
                    request_id=request_id,
                    client_version=client_version,
                    device_fingerprint=device_fingerprint,
                    user_agent=user_agent
                )

                if attempts >= settings.MAX_TOKEN_EXPIRED_ATTEMPTS:
                    await self.otp_repo.setex(keys["block_key"], settings.BLOCK_DURATION_OTP, "1")
                    self.logger.logger.error("Blocked due to too many token expired attempts",
                                             context={"phone": phone, "attempts": attempts})
                    await self.notifier.notification_service.send(
                        receiver_id="admin",
                        receiver_type="admin",
                        template_key="notification_failed",
                        variables={"receiver_id": phone, "error": "Too many token expired attempts",
                                   "type": "security"},
                        reference_type="otp",
                        reference_id=phone,
                        language=language,
                        db=db
                    )
                    raise RateLimitExceededError(
                        endpoint="otp_verify",
                        limit=settings.MAX_TOKEN_EXPIRED_ATTEMPTS,
                        error_code=DomainErrorCode.TOKEN_EXPIRED_RATE_LIMIT.value,
                        message=get_message("token.too_many.attempts", language=language),
                        status_code=HttpStatus.TOO_MANY_REQUESTS.value,
                        trace_id=self.logger.logger.tracer.get_trace_id(),
                        details={"phone": phone, "remaining_attempts": settings.MAX_TOKEN_EXPIRED_ATTEMPTS - attempts},
                        language=language
                    )

                raise InvalidCredentialsError(
                    error_code=DomainErrorCode.TOKEN_EXPIRED.value,
                    message=get_message("token.invalid", language=language),
                    status_code=HttpStatus.BAD_REQUEST.value,
                    trace_id=self.logger.logger.tracer.get_trace_id(),
                    details={"remaining_attempts": settings.MAX_TOKEN_EXPIRED_ATTEMPTS - attempts},
                    language=language
                )

            if await self.otp_repo.get(keys["block_key"]):
                raise RateLimitExceededError(
                    endpoint="otp_verify",
                    limit=0,
                    error_code=DomainErrorCode.OTP_RATE_LIMIT.value,
                    message=get_message("otp.too_many.attempts", language=language),
                    status_code=HttpStatus.TOO_MANY_REQUESTS.value,
                    trace_id=self.logger.logger.tracer.get_trace_id(),
                    details={},
                    language=language
                )

            is_valid = await self.storage.validate(
                otp=otp,
                jti=jti,
                phone=phone,
                role=role,
                language=language,
                db=db,
                client_ip=client_ip,
                request_id=request_id,
                client_version=client_version,
                device_fingerprint=device_fingerprint,
                user_agent=user_agent
            )
            if not is_valid:
                await self.handle_failed_verification(otp, temporary_token, phone, role, language, db)
                return {}

            await self.storage.clear(phone, role, jti, language)
            user, user_id = await self.update_user_after_verification(phone, role, language, db)
            status = user.get("status")
            preferred_lang = (user.get("preferred_languages") or [language])[0]

            await self.logger.log_verified(
                phone, role, status, user_id, client_ip, request_id, client_version, device_fingerprint
            )
            notification_sent = await self.notifier.send_verified(phone, role, preferred_lang, db)

            now = utc_now()
            result = await self.handle_verification_result(
                user, user_id, phone, role, status, redis, client_ip, user_agent, preferred_lang, now
            )

            result.update({
                "notification_sent": notification_sent,
                "phone": phone
            })
            return result

        return await self.execute(operation, context, language)