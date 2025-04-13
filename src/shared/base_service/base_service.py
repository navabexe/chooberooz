from abc import ABC
from typing import Dict, Any

import sentry_sdk
from fastapi import HTTPException

from src.shared.errors.base import DatabaseConnectionException, InternalServerErrorException, BadRequestException, \
    AppHTTPException
from src.shared.errors.handlers import handle_db_error, handle_general_error
from src.shared.i18n.messages import get_message
from src.shared.utilities.logging import log_info, log_error


class BaseService(ABC):
    """Base class for all services with common error handling."""
    async def execute(self, operation, context: dict, language: str) -> Dict[str, Any]:
        """
        Execute an async operation with standardized error handling.

        Args:
            operation: The async operation to execute.
            context: Contextual data for logging.
            language: Language for error messages.

        Returns:
            Dict[str, Any]: Result of the operation.

        Raises:
            AppHTTPException: For application-specific HTTP errors.
            InternalServerErrorException: For unexpected server errors.
        """
        try:
            result = await operation()

            if not isinstance(result, dict):
                log_error("Unexpected return type in service operation", extra={
                    "type": str(type(result)),
                    "value": str(result),
                    **context
                })
                raise BadRequestException(
                    detail="Service returned unexpected result.",
                    message=get_message("server.error", language),
                    error_code="INVALID_RESULT",
                    language=language
                )

            return result

        except AppHTTPException as e:
            log_error("Application-level error", extra={**context, "error": str(e)})
            raise
        except DatabaseConnectionException as e:
            log_error("Database connection error", extra={**context, "error": str(e)}, exc_info=True)
            sentry_sdk.capture_exception(e)
            raise
        except Exception as e:
            log_error("Unhandled server error", extra={**context, "error": str(e)}, exc_info=True)
            sentry_sdk.capture_exception(e)
            raise InternalServerErrorException(
                detail="An unexpected error occurred.",
                message=get_message("server.error", language),
                error_code="SERVER_ERROR",
                language=language
            )