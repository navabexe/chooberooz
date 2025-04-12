from datetime import datetime, timezone
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, ConfigDict
from redis.asyncio import Redis

from src.shared.utilities.logging import log_info, log_warning


class Session(BaseModel):
    """Model representing a user session."""
    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique session identifier")
    user_id: str = Field(..., description="Identifier of the user owning the session")
    device_name: Optional[str] = Field(default=None, description="Name of the device")
    device_type: Optional[str] = Field(default=None, description="Type of device (e.g., mobile, desktop)")
    os: Optional[str] = Field(default=None, description="Operating system")
    browser: Optional[str] = Field(default=None, description="Browser name")
    user_agent: Optional[str] = Field(default=None, description="Full user agent string")
    ip_address: Optional[str] = Field(default=None, description="IP address of the session")
    location: Optional[str] = Field(default=None, description="Approximate location")
    is_active: bool = Field(default=True, description="Whether the session is active")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Session creation time"
    )
    last_seen_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Last activity time"
    )

    model_config = ConfigDict(
        json_encoders={
            datetime: lambda v: v.isoformat()
        }
    )


def get_session_ttl(expiry_ts: int) -> str:
    """Calculate remaining TTL for a session."""
    now_ts = int(datetime.now(tz=timezone.utc).timestamp())
    ttl = expiry_ts - now_ts
    return f"{ttl} seconds" if ttl > 0 else "expired"


async def fetch_sessions_from_redis(redis: Redis, user_id: str, status_filter: str = "active") -> List[dict]:
    """Retrieve user sessions from Redis with optional status filtering."""
    pattern = f"sessions:{user_id}:*"
    session_keys = [key async for key in redis.scan_iter(match=pattern)]

    log_info("Scanning session keys", extra={"pattern": pattern, "key_count": len(session_keys)})

    sessions = []
    for key in session_keys:
        session_data = await redis.hgetall(key)
        session_id = session_data.get("jti")
        raw_status = session_data.get("status")
        is_active = raw_status == "active"

        if status_filter == "active" and not is_active:
            continue

        try:
            session = Session(
                id=session_id,
                user_id=user_id,
                device_name=session_data.get("device_name"),
                device_type=session_data.get("device_type"),
                os=session_data.get("os"),
                browser=session_data.get("browser"),
                user_agent=session_data.get("user_agent"),
                ip_address=session_data.get("ip"),
                location=session_data.get("location"),
                is_active=is_active,
                created_at=session_data.get("created_at"),
                last_seen_at=session_data.get("last_seen_at"),
            )
            session_dict = session.model_dump()
            session_dict["ttl"] = get_session_ttl(int(session_data.get("exp", "0")))
            sessions.append(session_dict)
        except Exception as e:
            log_warning("Skipping invalid session entry", extra={"key": key, "error": str(e)})

    return sessions