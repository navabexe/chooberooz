# Path: src/infrastructure/monitoring/sentry.py
import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from src.shared.config.settings import settings
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.errors.base import BaseError
from src.shared.utilities.constants import HttpStatus

logger = LoggingService(LogConfig())


def initialize_sentry():
    """
    Initialize Sentry for error tracking and performance monitoring.

    Raises:
        BaseError: If Sentry initialization fails.
    """
    try:
        sentry_sdk.init(
            dsn=settings.SENTRY_DSN,
            integrations=[FastApiIntegration()],
            traces_sample_rate=settings.SENTRY_TRACES_SAMPLE_RATE,
            environment=settings.ENVIRONMENT,
            send_default_pii=settings.SENTRY_SEND_PII,
        )
        logger.info("Sentry initialized", context={"dsn": settings.SENTRY_DSN})
    except Exception as e:
        logger.error("Sentry initialization failed", context={"error": str(e)})
        raise BaseError(
            error_code="SENTRY_INIT_FAILED",
            message=f"Sentry initialization failed: {str(e)}",
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"error": str(e)},
            language="en"
        )