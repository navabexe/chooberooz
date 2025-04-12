import hashlib
from datetime import datetime
from uuid import uuid4
from fastapi import Request
from motor.motor_asyncio import AsyncIOMotorDatabase
from redis.asyncio import Redis
from src.domain.authentication.services.session_service import get_session_service, create_user_session
from src.shared.base_service.base_service import BaseService
from src.shared.config.settings import settings
from src.shared.errors.base import BadRequestException, TooManyRequestsException
from src.shared.i18n.messages import get_message
from src.shared.security.token import decode_token, generate_temp_token
from src.shared.utilities.logging import create_log_data, log_info, log_error
from src.shared.utilities.network import extract_client_ip, parse_user_agent
from src.shared.utilities.text import generate_otp_code
from src.shared.utilities.time import utc_now
from src.domain.authentication.services.rate_limiter import check_rate_limits, store_rate_limit_keys
from src.domain.notification.services.notification_service import notification_service
from src.infrastructure.storage.cache.repositories.otp_repository import OTPRepository
from src.infrastructure.storage.nosql.repositories.user_repository import UserRepository

def hash_otp(otp: str) -> str:
    """Hash OTP with a salt for secure storage."""
    salted = f"{settings.OTP_SALT}:{otp}"
    hashed = hashlib.sha256(salted.encode()).hexdigest()
    log_info("Hashed OTP", extra={"otp": "****", "hashed": hashed[:10] + "..."})
    return hashed

class OTPService(BaseService):
    def __init__(self, otp_repo: OTPRepository, user_repo: UserRepository):
        """Initialize OTPService with injected dependencies."""
        self.otp_repo = otp_repo
        self.user_repo = user_repo

    async def generate_otp_and_token(self, phone: str, role: str, language: str) -> tuple[str, str]:
        """Generate an OTP code and a temporary token."""
        otp_code = generate_otp_code()
        jti = str(uuid4())
        temp_token = await generate_temp_token(
            phone=phone,
            role=role,
            jti=jti,
            status="incomplete",
            phone_verified=False,
            language=language
        )
        log_info("Generated OTP and token", extra={"phone": phone, "role": role, "jti": jti, "otp": "****"})
        return otp_code, temp_token

    async def store_otp(self, phone: str, role: str, otp_hash: str, jti: str):
        """Store the OTP hash and temporary token in Redis."""
        redis_key = f"otp:{role}:{phone}"
        temp_token_key = f"temp_token_used:{phone}"
        await self.otp_repo.setex(redis_key, settings.OTP_EXPIRY, otp_hash)
        await self.otp_repo.setex(f"temp_token:{jti}", settings.OTP_EXPIRY, phone)
        await self.otp_repo.setex(temp_token_key, settings.OTP_EXPIRY, "generated")
        await store_rate_limit_keys(phone, role, self.otp_repo)
        log_info("Stored OTP in Redis", extra={"redis_key": redis_key, "otp_hash": otp_hash[:10] + "...", "temp_key": f"temp_token:{jti}", "phone": phone})

    async def send_otp_notification(self, phone: str, role: str, otp_code: str, purpose: str, language: str, db: AsyncIOMotorDatabase) -> bool:
        """Send OTP notification to the user and admin."""
        return await notification_service.send(
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

    async def log_otp_request(self, phone: str, role: str, purpose: str, request: Request, request_id: str, client_version: str, device_fingerprint: str, jti: str, otp_code: str):
        """Log the OTP request event."""
        client_ip = await extract_client_ip(request)
        agent_info = parse_user_agent(request.headers.get("User-Agent", "Unknown"))
        log_data = create_log_data(
            entity_type="otp",
            entity_id=phone,
            action="requested",
            ip=client_ip,
            request_id=request_id,
            client_version=client_version,
            device_fingerprint=device_fingerprint,
            extra_data={
                "role": role,
                "purpose": purpose,
                "jti": jti,
                "otp": otp_code if settings.ENVIRONMENT == "development" else None,
                "device_name": agent_info["device_name"],
                "device_type": agent_info["device_type"],
                "os": agent_info["os"],
                "browser": agent_info["browser"]
            }
        )
        await self.user_repo.log_audit("otp_requested", log_data)

    async def request_otp(
        self,
        phone: str,
        role: str,
        purpose: str,
        request: Request,
        language: str = settings.DEFAULT_LANGUAGE,
        redis: Redis = None,
        db: AsyncIOMotorDatabase = None,
        request_id: str = None,
        client_version: str = None,
        device_fingerprint: str = None,
        user_agent: str = "Unknown"
    ) -> dict:
        """Request a new OTP for authentication."""
        context = {
            "entity_type": "otp",
            "entity_id": phone,
            "action": "requested",
            "endpoint": "/api/v1/request-otp",
            "request_id": request_id
        }
        async def operation():
            await check_rate_limits(phone, role, self.otp_repo, language)
            otp_code, temp_token = await self.generate_otp_and_token(phone, role, language)
            otp_hash = hash_otp(otp_code)
            await self.store_otp(phone, role, otp_hash, temp_token.split('.')[1])  # Extract jti from token
            await self.log_otp_request(phone, role, purpose, request, request_id, client_version, device_fingerprint, temp_token.split('.')[1], otp_code)
            notification_sent = await self.send_otp_notification(phone, role, otp_code, purpose, language, db)
            return {
                "temporary_token": temp_token,
                "expires_in": settings.OTP_EXPIRY,
                "notification_sent": notification_sent,
                "message": get_message("otp.sent", lang=language)
            }
        return await self.execute(operation, context, language)

    async def validate_otp(self, otp: str, temporary_token: str, phone: str, role: str, redis: Redis) -> bool:
        """Validate the OTP code against the stored hash."""
        redis_key = f"otp:{role}:{phone}"
        temp_key = f"temp_token:{temporary_token.split('.')[1]}"
        stored_otp_hash = await self.otp_repo.get(redis_key)
        stored_phone = await self.otp_repo.get(temp_key)
        log_info("Validating OTP", extra={
            "redis_key": redis_key,
            "temp_key": temp_key,
            "stored_otp_hash": stored_otp_hash[:10] + "..." if stored_otp_hash else None,
            "stored_phone": stored_phone,
            "input_otp": "****",
            "input_phone": phone
        })
        if not stored_otp_hash or not stored_phone:
            log_error("OTP validation failed: Expired or missing data", extra={"redis_key": redis_key, "temp_key": temp_key})
            raise BadRequestException(detail="The OTP code has expired.")
        computed_hash = hash_otp(otp)
        if stored_phone != phone or computed_hash != stored_otp_hash:
            log_error("OTP validation failed: Mismatch", extra={
                "stored_phone": stored_phone,
                "input_phone": phone,
                "computed_hash": computed_hash[:10] + "...",
                "stored_hash": stored_otp_hash[:10] + "..."
            })
            return False
        log_info("OTP validated successfully", extra={"phone": phone, "role": role})
        return True

    async def update_user_after_verification(self, phone: str, role: str, language: str, db: AsyncIOMotorDatabase) -> tuple[dict, str]:
        """Update user data after successful OTP verification."""
        collection = f"{role}s"
        user = await self.user_repo.find_user(collection, phone)
        now = utc_now()
        if not user:
            user_data = self.create_user_data(phone, role, language, now)
            user_id = await self.user_repo.insert_user(collection, user_data)
            user = {"_id": user_id, **user_data}
        else:
            user_id = str(user["_id"])
            update_fields = {"updated_at": now}
            if not user.get("phone_verified"):
                update_fields["phone_verified"] = True
            if not user.get("preferred_languages"):
                update_fields["preferred_languages"] = [language]
            if update_fields:
                await self.user_repo.update_user(collection, user_id, update_fields)
        return user, user_id

    async def send_verification_notification(self, phone: str, role: str, language: str, db: AsyncIOMotorDatabase) -> bool:
        """Send notification after successful OTP verification."""
        return await notification_service.send_otp_verified(phone, role, language, db=db)

    async def log_otp_verification(self, phone: str, role: str, status: str, user_id: str, client_ip: str, request_id: str, client_version: str, device_fingerprint: str):
        """Log the OTP verification event."""
        log_data = create_log_data(
            entity_type="otp",
            entity_id=phone,
            action="verified",
            ip=client_ip,
            request_id=request_id,
            client_version=client_version,
            device_fingerprint=device_fingerprint,
            extra_data={"role": role, "status": status, "user_id": user_id}
        )
        await self.user_repo.log_audit("otp_verified", log_data)

    async def handle_verification_result(self, user: dict, user_id: str, phone: str, role: str, status: str, redis: Redis, client_ip: str, user_agent: str, language: str, now: datetime) -> dict:
        """Handle the result of OTP verification (e.g., create session or return new token)."""
        if status in ["incomplete", "pending"]:
            new_jti = str(uuid4())
            temp_token = await generate_temp_token(phone=phone, role=role, jti=new_jti, status=status, phone_verified=True, language=language)
            await self.otp_repo.setex(f"temp_token:{new_jti}", settings.TEMP_TOKEN_EXPIRY, phone)
            return {
                "status": status,
                "temporary_token": temp_token,
                "message": get_message("auth.profile.incomplete" if status == "incomplete" else "auth.profile.pending", language),
                "phone": phone,
            }
        elif status == "active":
            session_service = get_session_service(redis)
            await session_service.delete_incomplete_sessions(user_id)
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
            session_result["message"] = get_message("otp.valid", language)
            return session_result
        raise BadRequestException(detail=get_message("server.error", language))

    async def handle_failed_verification(self, otp: str, temporary_token: str, phone: str, role: str, language: str, db: AsyncIOMotorDatabase) -> None:
        """Handle failed OTP verification attempts and block if necessary."""
        attempt_key = f"otp-attempts:{role}:{phone}"
        block_key = f"otp-blocked:{role}:{phone}"
        attempts = await self.otp_repo.incr(attempt_key)
        await self.otp_repo.expire(attempt_key, 600)
        remaining = settings.MAX_OTP_ATTEMPTS - int(attempts)
        if int(attempts) >= settings.MAX_OTP_ATTEMPTS:
            redis_key = f"otp:{role}:{phone}"
            temp_key = f"temp_token:{temporary_token.split('.')[1]}"
            await self.otp_repo.delete(redis_key)
            await self.otp_repo.delete(temp_key)
            await self.otp_repo.setex(block_key, settings.BLOCK_DURATION_OTP, "1")
            await notification_service.send(
                receiver_id="admin",
                receiver_type="admin",
                template_key="notification_failed",
                variables={"receiver_id": phone, "error": "Too many OTP attempts", "type": "security"},
                reference_type="otp",
                reference_id=phone,
                language=language,
                db=db
            )
            raise TooManyRequestsException(detail=get_message("otp.too_many.attempts", language))
        raise BadRequestException(detail=get_message("otp.invalid.with_attempts", language, variables={"remaining": remaining}))

    async def verify_otp(
        self,
        otp: str,
        temporary_token: str,
        client_ip: str,
        language: str = settings.DEFAULT_LANGUAGE,
        redis: Redis = None,
        db: AsyncIOMotorDatabase = None,
        request_id: str = None,
        client_version: str = None,
        device_fingerprint: str = None,
        user_agent: str = "Unknown"
    ) -> dict:
        """Verify an OTP and create or update user session."""
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
                raise BadRequestException(detail=get_message("token.invalid", language))
            block_key = f"otp-blocked:{role}:{phone}"
            if await self.otp_repo.get(block_key):
                raise TooManyRequestsException(detail=get_message("otp.too_many.attempts", language))
            if not await self.validate_otp(otp, temporary_token, phone, role, redis):
                await self.handle_failed_verification(otp, temporary_token, phone, role, language, db)
            redis_key = f"otp:{role}:{phone}"
            temp_key = f"temp_token:{jti}"
            attempt_key = f"otp-attempts:{role}:{phone}"
            await self.otp_repo.delete(redis_key)
            await self.otp_repo.delete(temp_key)
            await self.otp_repo.delete(attempt_key)
            user, user_id = await self.update_user_after_verification(phone, role, language, db)
            status = user.get("status")
            preferred_language = (user.get("preferred_languages") or [language])[0]
            notification_sent = await self.send_verification_notification(phone, role, preferred_language, db)
            await self.log_otp_verification(phone, role, status, user_id, client_ip, request_id, client_version, device_fingerprint)
            result = await self.handle_verification_result(user, user_id, phone, role, status, redis, client_ip, user_agent, preferred_language, utc_now())
            result["notification_sent"] = notification_sent
            result["phone"] = phone
            return result
        return await self.execute(operation, context, language)

    def create_user_data(self, phone: str, role: str, language: str, now: datetime) -> dict:
        """Create initial user data for a new user."""
        return {
            "phone": phone,
            "role": role,
            "status": "incomplete",
            "phone_verified": True,
            "preferred_languages": [language],
            "created_at": now,
            "updated_at": now
        }