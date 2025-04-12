from abc import ABC
from typing import Dict, Any

import sentry_sdk
from fastapi import HTTPException

from src.shared.errors.base import DatabaseConnectionException, InternalServerErrorException
from src.shared.errors.handlers import handle_db_error, handle_general_error
from src.shared.utilities.logging import log_info, log_error


class BaseService(ABC):
    """Base class for all services with common error handling."""
    def __init__(self):
        self.default_language = "fa"

    async def execute(self, operation: callable, context: Dict[str, Any], language: str = "fa"):
        """Execute an operation with error handling and logging."""
        try:
            result = await operation()
            log_info(f"{context.get('action', 'Operation')} executed successfully", extra=context)
            return result
        except HTTPException as http_exc:
            log_error(f"HTTP exception in {context.get('endpoint', 'service')}",
                      extra={**context, "error": str(http_exc.detail)})
            log_info("Sending HTTP exception to Sentry", extra={"error": str(http_exc.detail)})
            sentry_sdk.capture_exception(http_exc)
            raise http_exc
        except DatabaseConnectionException as db_exc:
            await handle_db_error(db_exc, context, language)
            raise
        except Exception as e:
            await handle_general_error(e, context, language)
            raise InternalServerErrorException(detail="Internal server error")