# Path: src/shared/base_service/base_service.py
from abc import ABC
from typing import Dict, Any, Literal
import sentry_sdk

from src.shared.config.settings import settings
from src.shared.i18n.messages import get_message
from src.shared.errors.base import BaseError
from src.shared.errors.infrastructure.database import DatabaseConnectionError
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.utilities.constants import HttpStatus


class BaseService(ABC):
    """Base class for service operations."""

    def __init__(self):
        """Initialize service with logger."""
        self.logger = LoggingService(LogConfig())

    async def execute(self, operation, context: dict, language: Literal["fa", "en"]) -> Dict[str, Any]:
        """Execute service operation with error handling."""
        try:
            result = await operation()
            if result is None:
                self.logger.error("Service returned None", context=context)
                raise BaseError(
                    error_code="NO_RESULT",
                    message=get_message("server.error", language),
                    status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
                    trace_id=self.logger.tracer.get_trace_id(),
                    details={"context": context},
                    language=language
                )
            if not isinstance(result, dict):
                self.logger.error("Unexpected return type", context={
                    "type": str(type(result)),
                    "value": str(result),
                    **context
                })
                raise BaseError(
                    error_code="INVALID_RESULT",
                    message=get_message("server.error", language),
                    status_code=HttpStatus.BAD_REQUEST.value,
                    trace_id=self.logger.tracer.get_trace_id(),
                    details={"type": str(type(result)), "context": context},
                    language=language
                )
            return result
        except DatabaseConnectionError as e:
            self.logger.critical("Database connection error", context={**context, "error": str(e)})
            sentry_sdk.capture_exception(e)
            raise
        except BaseError as e:
            self.logger.error("Application-level error", context={**context, "error": str(e)})
            raise
        except Exception as e:
            self.logger.critical("Unhandled server error", context={**context, "error": str(e)})
            sentry_sdk.capture_exception(e)
            raise BaseError(
                error_code="INTERNAL_SERVER_ERROR",
                message=get_message("server.error", language),
                status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"error": str(e) if settings.ENVIRONMENT == "development" else "Unexpected error"},
                language=language
            )