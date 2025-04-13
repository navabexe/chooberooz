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
    def __init__(self):
        self.default_language = "fa"

    async def execute(self, operation, context: dict, language: str):
        try:
            result = await operation()

            # ✅ بررسی کن که خروجی باید dict باشه
            if not isinstance(result, dict):
                log_error("Unexpected return type in service operation", extra={
                    "type": str(type(result)),
                    "value": str(result),
                    **context
                })
                raise BadRequestException(
                    detail="Service returned unexpected result.",
                    message=get_message("server.error", language),
                    language=language
                )

            return result

        except AppHTTPException as e:
            log_error("Application-level error", extra={**context, "error": str(e)})
            raise
        except Exception as e:
            log_error("Unhandled exception during operation", extra={**context, "error": str(e)}, exc_info=True)
            raise BadRequestException(
                detail=str(e),
                message=get_message("server.error", language),
                language=language
            )
