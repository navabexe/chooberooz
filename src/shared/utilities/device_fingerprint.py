# Path: src/shared/utilities/device_fingerprint.py
from redis.asyncio import Redis
from src.shared.config.settings import settings
from src.shared.i18n.messages import get_message
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.errors.domain.security import SuspiciousActivityError
from src.shared.errors.base import BaseError
from src.shared.utilities.types import LanguageCode
from src.shared.utilities.constants import HttpStatus
from typing import Optional

logger = LoggingService(LogConfig())


async def manage_device_fingerprint(
        redis: Redis,
        role: str,
        phone: str,
        device_fingerprint: Optional[str],
        language: LanguageCode = settings.DEFAULT_LANGUAGE
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
        SuspiciousActivityError: If fingerprint mismatches stored value.
        BaseError: For unexpected Redis errors.
    """
    if not device_fingerprint:
        logger.info("No device fingerprint provided", context={"phone": phone})
        return

    device_key = f"device:{role}:{phone}"

    try:
        stored_device = await redis.get(device_key)
        if stored_device:
            if stored_device != device_fingerprint:
                logger.error("Device fingerprint mismatch", context={
                    "phone": phone,
                    "stored_device": stored_device,
                    "received": device_fingerprint
                })
                raise SuspiciousActivityError(
                    user_id=phone,
                    activity="device_mismatch",
                    error_code="DEVICE_MISMATCH",
                    message=get_message("device.mismatch", language=language),
                    status_code=HttpStatus.BAD_REQUEST.value,
                    trace_id=logger.tracer.get_trace_id(),
                    details={"stored_device": stored_device, "received": device_fingerprint},
                    language=language
                )
        else:
            logger.info("No previous fingerprint stored", context={"phone": phone})

        await redis.setex(device_key, settings.OTP_EXPIRY, device_fingerprint)
        logger.info("Device fingerprint stored", context={"phone": phone, "device_key": device_key})

    except Exception as e:
        logger.error("Failed to validate/store device fingerprint", context={"error": str(e), "phone": phone})
        raise BaseError(
            error_code="DEVICE_FINGERPRINT_FAILED",
            message=f"Failed to process device fingerprint: {str(e)}",
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"error": str(e), "phone": phone},
            language=language
        )