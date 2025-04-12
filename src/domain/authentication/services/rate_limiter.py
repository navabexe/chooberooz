from src.shared.config.settings import settings
from src.shared.errors.base import TooManyRequestsException
from src.shared.i18n.messages import get_message
from src.infrastructure.storage.cache.repositories.otp_repository import OTPRepository


BLOCK_DURATION = settings.BLOCK_DURATION


async def check_rate_limits(phone: str, role: str, repo: OTPRepository, language: str):
    """Check rate limits for OTP requests based on phone and role."""
    keys_limits = {
        f"otp-limit:{role}:{phone}": (3, 60, "otp.too_many.1min"),
        f"otp-limit-10min:{role}:{phone}": (5, 600, "otp.too_many.10min"),
        f"otp-limit-1h:{role}:{phone}": (10, 3600, "otp.too_many.blocked"),
    }
    for key, (limit, ttl, msg_key) in keys_limits.items():
        attempts = await repo.get(key)
        if attempts and int(attempts) >= limit:
            if "1h" in key:
                await repo.setex(f"otp-blocked:{role}:{phone}", BLOCK_DURATION, "1")
            raise TooManyRequestsException(detail=get_message(msg_key, lang=language))


async def store_rate_limit_keys(phone: str, role: str, repo: OTPRepository):
    """Store rate limit keys in Redis with appropriate TTLs."""
    for key, ttl in [
        (f"otp-limit:{role}:{phone}", 60),
        (f"otp-limit-10min:{role}:{phone}", 600),
        (f"otp-limit-1h:{role}:{phone}", 3600),
    ]:
        await repo.incr(key)
        await repo.expire(key, ttl)