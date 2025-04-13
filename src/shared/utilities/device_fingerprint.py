# path: src/shared/utilities/device_fingerprint.py
from redis.asyncio import Redis
from src.shared.config.settings import settings
from src.shared.errors.base import BadRequestException
from src.shared.i18n.messages import get_message
from src.shared.utilities.logging import log_info, log_error
from typing import Optional


async def manage_device_fingerprint(
    redis: Redis,
    role: str,
    phone: str,
    device_fingerprint: Optional[str],
    language: str = settings.DEFAULT_LANGUAGE
) -> None:
    """
    Validate and store device fingerprint in Redis.

    Args:
        redis: Redis instance for storage.
        role: User role (e.g., 'user', 'admin').
        phone: User's phone number.
        device_fingerprint: Device fingerprint (optional).
        language: Language for error messages.

    Raises:
        BadRequestException: If fingerprint mismatches stored value.
        Exception: For unexpected Redis errors.
    """
    if not device_fingerprint:
        log_info("No device fingerprint provided", extra={"phone": phone})
        return

    device_key = f"device:{role}:{phone}"

    try:
        stored_device = await redis.get(device_key)
        if stored_device:
            if stored_device != device_fingerprint:
                log_error("Device fingerprint mismatch", extra={
                    "phone": phone,
                    "stored_device": stored_device,
                    "received": device_fingerprint
                })
                raise BadRequestException(
                    detail="Suspicious device detected.",
                    message=get_message("device.mismatch", language),
                    error_code="DEVICE_MISMATCH",
                    language=language
                )
        else:
            log_info("No previous fingerprint stored", extra={"phone": phone})

        await redis.setex(device_key, settings.OTP_EXPIRY, device_fingerprint)
        log_info("Device fingerprint stored", extra={"phone": phone, "device_key": device_key})

    except Exception as e:
        log_error("Failed to validate/store device fingerprint", extra={"error": str(e), "phone": phone})
        raise