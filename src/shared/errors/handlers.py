# path: src/shared/errors/handlers.py
from typing import Dict, Any, Literal
import sentry_sdk
from src.shared.errors.base import DatabaseConnectionException
from src.shared.utilities.logging import log_error
from src.domain.notification.services.notification_service import notification_service

ErrorType = Literal["general", "database", "service", "authentication"]

async def send_admin_notification(
    *,
    exc: Exception,
    context: Dict[str, Any],
    language: str,
    error_type: ErrorType = "general"
):
    log_error(
        f"{error_type.capitalize()} error in {context.get('endpoint', 'unknown')}",
        extra={**context, "error": str(exc)},
        exc_info=True
    )

    sentry_sdk.capture_exception(exc)

    try:
        await notification_service.send(
            receiver_id="admin",
            receiver_type="admin",
            template_key="notification_failed",
            variables={
                "receiver_id": context.get("entity_id", "system"),
                "error": str(exc),
                "type": error_type
            },
            reference_type=context.get("entity_type", "system"),
            reference_id=context.get("entity_id", "unknown"),
            language=language
        )
    except Exception as notify_error:
        log_error("Failed to send admin notification", extra={
            **context,
            "original_error": str(exc),
            "notification_error": str(notify_error)
        })

async def handle_general_error(exc: Exception, context: Dict[str, Any], language: str):
    await send_admin_notification(exc=exc, context=context, language=language, error_type="general")

async def handle_db_error(exc: DatabaseConnectionException, context: Dict[str, Any], language: str):
    await send_admin_notification(exc=exc, context=context, language=language, error_type="database")
