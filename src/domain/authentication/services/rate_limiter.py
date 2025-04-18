# Path: src/domain/otp/rate_limits.py
from src.shared.config.settings import settings
from src.shared.i18n.messages import get_message
from src.infrastructure.storage.cache.repositories.otp_repository import OTPRepository
from src.shared.errors.domain.security import RateLimitExceededError
from src.shared.utilities.types import LanguageCode
from src.shared.utilities.constants import HttpStatus, DomainErrorCode

BLOCK_DURATION = settings.BLOCK_DURATION

async def check_rate_limits(phone: str, role: str, repo: OTPRepository, language: LanguageCode, client_ip: str = None):
    """Check rate limits for OTP requests based on phone, role, and optionally IP."""
    # Block key check (based on phone & role)
    blocked_key = f"otp-blocked:{role}:{phone}"
    if await repo.get(blocked_key):
        raise RateLimitExceededError(
            endpoint="otp_request",
            limit=0,
            error_code=DomainErrorCode.RATE_LIMIT_EXCEEDED.value,
            message=get_message("otp.too_many.blocked", language=language),
            status_code=HttpStatus.TOO_MANY_REQUESTS.value,
            trace_id=None,
            details={"phone": phone, "role": role},
            language=language
        )

    # Optional IP-based blocking
    if client_ip:
        ip_block_key = f"otp-blocked-ip:{client_ip}"
        if await repo.get(ip_block_key):
            raise RateLimitExceededError(
                endpoint="otp_request",
                limit=0,
                error_code=DomainErrorCode.RATE_LIMIT_EXCEEDED.value,
                message=get_message("otp.too_many.blocked", language=language),
                status_code=HttpStatus.TOO_MANY_REQUESTS.value,
                trace_id=None,
                details={"client_ip": client_ip},
                language=language
            )

    # Rate limiting tiers
    keys_limits = {
        f"otp-limit:{role}:{phone}": (3, 60, "otp.too_many.1min"),
        f"otp-limit-10min:{role}:{phone}": (5, 600, "otp.too_many.10min"),
        f"otp-limit-1h:{role}:{phone}": (10, 3600, "otp.too_many.blocked"),
    }

    if client_ip:
        keys_limits[f"otp-limit-ip:{client_ip}"] = (20, 3600, "otp.too_many.blocked")

    # Evaluate all limits
    for key, (limit, ttl, msg_key) in keys_limits.items():
        attempts = await repo.get(key)
        if attempts is not None and int(attempts) >= limit:
            # Block phone or IP if final tier exceeded
            if "1h" in key or "ip" in key:
                await repo.setex(blocked_key, BLOCK_DURATION, "1")
                if client_ip:
                    await repo.setex(f"otp-blocked-ip:{client_ip}", BLOCK_DURATION, "1")
            raise RateLimitExceededError(
                endpoint="otp_request",
                limit=limit,
                error_code=DomainErrorCode.RATE_LIMIT_EXCEEDED.value,
                message=get_message(msg_key, language=language),
                status_code=HttpStatus.TOO_MANY_REQUESTS.value,
                trace_id=None,
                details={"phone": phone, "role": role, "key": key},
                language=language
            )

async def store_rate_limit_keys(phone: str, role: str, repo: OTPRepository, client_ip: str = None):
    """Increment rate limiting keys in Redis with proper TTL management."""
    keys_with_ttl = [
        (f"otp-limit:{role}:{phone}",  60),
        (f"otp-limit-10min:{role}:{phone}", 600),
        (f"otp-limit-1h:{role}:{phone}", 3600),
    ]

    if client_ip:
        keys_with_ttl.append((f"otp-limit-ip:{client_ip}", 3600))

    for key, ttl in keys_with_ttl:
        current = await repo.incr(key)
        if current == 1:
            await repo.expire(key, ttl)