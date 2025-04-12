import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from src.shared.config.settings import settings
from src.shared.utilities.logging import log_info, log_error

def initialize_sentry():
    """
    Initialize Sentry for error tracking and performance monitoring.

    Raises:
        Exception: If Sentry initialization fails.
    """
    try:
        sentry_sdk.init(
            dsn=settings.SENTRY_DSN,
            integrations=[FastApiIntegration()],
            traces_sample_rate=settings.SENTRY_TRACES_SAMPLE_RATE,
            environment=settings.ENVIRONMENT,
            send_default_pii=settings.SENTRY_SEND_PII,
        )
        log_info("Sentry initialized", extra={"dsn": settings.SENTRY_DSN})
    except Exception as e:
        log_error("Sentry initialization failed", extra={"error": str(e)})
        raise