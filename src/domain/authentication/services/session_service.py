# Path: src/domain/authentication/session.py
from datetime import datetime, timezone
from typing import Dict, List, Literal
from uuid import uuid4
from redis.asyncio import Redis
from src.shared.config.settings import settings
from src.shared.security.token import generate_access_token, generate_refresh_token
from src.shared.utilities.constants import HttpStatus
from src.shared.utilities.network import get_location_from_ip
from src.shared.utilities.text import safe_json_dumps, decode_value
from src.domain.authentication.models.session import fetch_sessions_from_redis
from src.domain.authentication.models.token import VendorJWTProfile
from src.domain.notification.services.notification_service import notification_service
from src.infrastructure.storage.cache.repositories.otp_repository import OTPRepository
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.errors.domain.security import InvalidTokenError
from src.shared.utilities.types import LanguageCode

logger = LoggingService(LogConfig())


def stringify_session_data(data: dict) -> dict:
    """Convert all values in session_data to byte-safe strings."""
    result = {}
    for k, v in data.items():
        if v is None:
            continue
        key_encoded = k.encode()
        if isinstance(v, (dict, list, tuple)):
            result[key_encoded] = safe_json_dumps(v).encode()
        else:
            result[key_encoded] = str(v).encode()
    return result


async def create_user_session(
        *,
        user_id: str,
        phone: str,
        role: str,
        user: dict,
        redis: Redis,
        client_ip: str,
        user_agent: str,
        language: LanguageCode,
        now: datetime
) -> dict:
    """Create a user session and store it in Redis, returning access and refresh tokens."""
    session_id = str(uuid4())
    profile_data = VendorJWTProfile(**user).model_dump() if role == "vendor" else None
    location = await get_location_from_ip(client_ip) if client_ip else "Unknown"
    now = now or datetime.now(timezone.utc)

    session_data = {
        "ip": client_ip,
        "created_at": now.isoformat(),
        "last_seen_at": now.isoformat(),
        "device_name": "Unknown Device",
        "device_type": "Desktop",
        "os": "Windows",
        "browser": "Chrome",
        "user_agent": user_agent,
        "location": location,
        "status": "active",
        "jti": session_id,
        "vendor_profile": profile_data if profile_data else None
    }

    session_data_cleaned = stringify_session_data(session_data)

    logger.info("Session data to be stored in Redis", context={"cleaned_data": session_data_cleaned})

    session_key = f"sessions:{user_id}:{session_id}"
    await redis.hset(name=session_key, mapping=session_data_cleaned)
    await redis.expire(session_key, settings.SESSION_EXPIRY)

    access_token = await generate_access_token(
        user_id=user_id,
        role=role,
        session_id=session_id,
        vendor_profile=profile_data,
        language=language,
        status="active",
        phone_verified=True
    )

    refresh_token, refresh_jti = await generate_refresh_token(
        user_id=user_id,
        role=role,
        session_id=session_id,
        status="active",
        language=language,
        return_jti=True
    )

    await redis.setex(
        f"refresh_tokens:{user_id}:{refresh_jti}",
        settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
        "active"
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "status": "active",
        "message": "otp.valid",
        "phone": phone
    }


class SessionService:
    """Service for managing user sessions."""

    def __init__(self, redis: Redis = None):
        """Initialize session service with Redis repository."""
        self.repo = OTPRepository(redis)

    async def delete_incomplete_sessions(self, user_id: str):
        """Delete incomplete sessions for a user from Redis."""
        session_keys = await self.repo.scan_keys(f"sessions:{user_id}:*")
        for key in session_keys:
            session_data = await self.repo.hgetall(key)
            status = session_data.get(b"status") or session_data.get("status", b"")
            if decode_value(status) != "active":
                await self.repo.delete(key)
                logger.info("Deleted incomplete session", context={"user_id": user_id, "session_key": key})

    async def get_sessions(
            self,
            user_id: str,
            status_filter: Literal["active", "all"] = "active",
            language: LanguageCode = "fa",
            requester_role: str = "vendor",
            client_ip: str = "unknown",
    ) -> dict:
        """Retrieve user sessions from Redis with optional status filtering."""
        redis = await self.repo.redis
        sessions = await fetch_sessions_from_redis(redis=redis, user_id=user_id, status_filter=status_filter)

        notification_sent = False
        if requester_role == "admin":
            try:
                notification_sent = await notification_service.send_session_notification(
                    user_id=user_id,
                    sessions=sessions,
                    ip=client_ip,
                    language=language
                )
            except Exception as e:
                logger.error("Session notification failed", context={
                    "user_id": user_id,
                    "ip": client_ip,
                    "error": str(e)
                })
                raise InvalidTokenError(
                    error_code="NOTIFICATION_FAILED",
                    message=f"Session notification failed: {str(e)}",
                    status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
                    trace_id=logger.tracer.get_trace_id(),
                    details={"error": str(e), "user_id": user_id},
                    language=language
                )

        logger.info("Sessions retrieved successfully", context={
            "user_id": user_id,
            "session_count": len(sessions),
            "status_filter": status_filter
        })

        return {
            "sessions": sessions,
            "notification_sent": notification_sent
        }


def get_session_service(redis: Redis = None) -> SessionService:
    """Factory function to create a SessionService instance."""
    return SessionService(redis)