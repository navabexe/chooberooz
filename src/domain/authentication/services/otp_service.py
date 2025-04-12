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
from src.shared.utilities.logging import create_log_data
from src.shared.utilities.network import extract_client_ip, parse_user_agent
from src.shared.utilities.text import generate_otp_code
from src.shared.utilities.time import utc_now
from src.domain.authentication.services.rate_limiter import check_rate_limits, store_rate_limit_keys
from src.domain.notification.services.notification_service import notification_service
from src.infrastructure.storage.cache.repositories.otp_repository import OTPRepository
from src.infrastructure.storage.nosql.client import get_nosql_db
from src.infrastructure.storage.nosql.repositories.user_repository import UserRepository


def hash_otp(otp: str) -> str:
    """Hash OTP with a salt for secure storage."""
    salted = f"{settings.OTP_SALT}:{otp}"
    return hashlib.sha256(salted.encode()).hexdigest()


class OTPService(BaseService):
    async def request_otp(
        self,
        phone: str,
        role: str,
        purpose: str,
        request: Request,
        language: str = "fa",
        redis: Redis = None,
        db: AsyncIOMotorDatabase = None,
        request_id: str = None,
        client_version: str = None,
        device_fingerprint: str = None,
        user_agent: str = "Unknown"
    ) -> dict:
        """Request a new OTP for authentication."""
        repo = OTPRepository(redis)
        if db is None:
            db = await get_nosql_db()
        auth_repo = UserRepository(db)

        context = {
            "entity_type": "otp",
            "entity_id": phone,
            "action": "requested",
            "endpoint": settings.REQUEST_OTP_PATH,
            "request_id": request_id
        }

        async def operation():
            client_ip = await extract_client_ip(request)
            redis_key = f"otp:{role}:{phone}"
            block_key = f"otp-blocked:{role}:{phone}"
            temp_token_key = f"temp_token_used:{phone}"

            if await repo.get(block_key):
                raise TooManyRequestsException(detail=get_message("otp.too_many.blocked", lang=language))

            await check_rate_limits(phone, role, repo, language)

            otp_code = generate_otp_code()
            otp_hash = hash_otp(otp_code)
            jti = str(uuid4())

            temp_token = await generate_temp_token(
                phone=phone,
                role=role,
                jti=jti,
                status="incomplete",
                phone_verified=False,
                language=language
            )

            await repo.setex(redis_key, settings.OTP_EXPIRY, otp_hash)
            await repo.setex(f"temp_token:{jti}", settings.OTP_EXPIRY, phone)
            await repo.setex(temp_token_key, settings.OTP_EXPIRY, "generated")
            await store_rate_limit_keys(phone, role, repo)

            agent_info = parse_user_agent(user_agent)

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
            await auth_repo.log_audit("otp_requested", log_data)

            notification_sent = await notification_service.send(
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

            return {
                "temporary_token": temp_token,
                "expires_in": settings.OTP_EXPIRY,
                "notification_sent": notification_sent,
                "message": get_message("otp.sent", lang=language)
            }

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

    async def verify_otp(
        self,
        otp: str,
        temporary_token: str,
        client_ip: str,
        language: str = "fa",
        redis: Redis = None,
        db: AsyncIOMotorDatabase = None,
        request_id: str = None,
        client_version: str = None,
        device_fingerprint: str = None,
        user_agent: str = "Unknown"
    ) -> dict:
        """Verify an OTP and create or update user session."""
        repo = OTPRepository(redis)
        if db is None:
            db = await get_nosql_db()
        auth_repo = UserRepository(db)
        session_service = get_session_service(redis)

        context = {
            "entity_type": "otp",
            "entity_id": "unknown",
            "action": "verified",
            "endpoint": settings.VERIFY_OTP_PATH,
            "request_id": request_id
        }

        async def operation():
            payload = await decode_token(temporary_token, token_type="temp", redis=redis)
            phone = payload.get("sub")
            role = payload.get("role")
            jti = payload.get("jti")
            context["entity_id"] = phone

            if not phone or not role or not jti:
                raise BadRequestException(detail=get_message("token.invalid", language))

            redis_key = f"otp:{role}:{phone}"
            temp_key = f"temp_token:{jti}"
            attempt_key = f"otp-attempts:{role}:{phone}"
            block_key = f"otp-blocked:{role}:{phone}"

            if await repo.get(block_key):
                raise TooManyRequestsException(detail=get_message("otp.too_many.attempts", language))

            stored_otp_hash = await repo.get(redis_key)
            stored_phone = await repo.get(temp_key)

            if not stored_otp_hash or not stored_phone:
                raise BadRequestException(detail=get_message("otp.expired", language))

            if stored_phone != phone or hash_otp(otp) != stored_otp_hash:
                attempts = await repo.incr(attempt_key)
                await repo.expire(attempt_key, 600)
                remaining = settings.MAX_OTP_ATTEMPTS - int(attempts)
                if int(attempts) >= settings.MAX_OTP_ATTEMPTS:
                    await repo.delete(redis_key)
                    await repo.delete(temp_key)
                    await repo.setex(block_key, settings.BLOCK_DURATION_OTP, "1")
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

            await repo.delete(redis_key)
            await repo.delete(temp_key)
            await repo.delete(attempt_key)

            collection = f"{role}s"
            user = await auth_repo.find_user(collection, phone)
            now = utc_now()

            if not user:
                user_data = self.create_user_data(phone, role, language, now)
                user_id = await auth_repo.insert_user(collection, user_data)
                user = {"_id": user_id, **user_data}
            else:
                user_id = str(user["_id"])
                update_fields = {"updated_at": now}
                if not user.get("phone_verified"):
                    update_fields["phone_verified"] = True
                if not user.get("preferred_languages"):
                    update_fields["preferred_languages"] = [language]
                if update_fields:
                    await auth_repo.update_user(collection, user_id, update_fields)

            status = user.get("status")
            preferred_language = (user.get("preferred_languages") or [language])[0]
            notification_sent = await notification_service.send_otp_verified(phone, role, preferred_language, db=db)

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
            await auth_repo.log_audit("otp_verified", log_data)

            if status in ["incomplete", "pending"]:
                new_jti = str(uuid4())
                temp_token = await generate_temp_token(phone=phone, role=role, jti=new_jti, status=status, phone_verified=True, language=preferred_language)
                await repo.setex(f"temp_token:{new_jti}", settings.TEMP_TOKEN_EXPIRY, phone)
                return {
                    "status": status,
                    "temporary_token": temp_token,
                    "message": get_message("auth.profile.incomplete" if status == "incomplete" else "auth.profile.pending", preferred_language),
                    "phone": phone,
                    "notification_sent": notification_sent
                }

            elif status == "active":
                await session_service.delete_incomplete_sessions(user_id)
                updated_user = await auth_repo.find_user(collection, phone)

                session_result = await create_user_session(
                    user_id=user_id,
                    phone=phone,
                    role=role,
                    user=updated_user,
                    redis=repo.redis,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    language=preferred_language,
                    now=now
                )
                session_result["notification_sent"] = notification_sent
                session_result["message"] = get_message("otp.valid", preferred_language)
                return session_result

            raise BadRequestException(detail=get_message("server.error", language))

        return await self.execute(operation, context, language)


otp_service = OTPService()