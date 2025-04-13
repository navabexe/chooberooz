# path: src/shared/base_service/base_service.py
from abc import ABC
from typing import Dict, Any
import sentry_sdk
from src.shared.errors.base import DatabaseConnectionException, InternalServerErrorException, BadRequestException, AppHTTPException
from src.shared.i18n.messages import get_message
from src.shared.utilities.logging import log_error
import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path
from src.shared.config.settings import settings

# Configure log rotation
LOG_DIR = Path(__file__).resolve().parent.parent.parent / "logs"
LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOG_DIR / "senama.log"

rotating_handler = RotatingFileHandler(
    filename=LOG_FILE,
    maxBytes=5 * 1024 * 1024,  # 5MB
    backupCount=2,
    encoding="utf-8"
)
rotating_handler.setFormatter(logging.Formatter('[%(asctime)s] %(levelname)s | %(message)s | context=%(context)s'))
logger = logging.getLogger("senama")
if not any(isinstance(h, RotatingFileHandler) for h in logger.handlers):
    logger.addHandler(rotating_handler)

class BaseService(ABC):
    async def execute(self, operation, context: dict, language: str) -> Dict[str, Any]:
        try:
            result = await operation()
            if result is None:
                log_error("Service returned None", extra={**context})
                raise InternalServerErrorException(
                    detail="Service returned no result.",
                    message=get_message("server.error", language),
                    error_code="NO_RESULT",
                    language=language
                )
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
            if settings.ENVIRONMENT == "development":
                raise InternalServerErrorException(
                    detail=str(e),
                    message=get_message("server.error", language),
                    error_code="SERVER_ERROR",
                    language=language
                )
            else:
                raise InternalServerErrorException(
                    detail="An unexpected error occurred.",
                    message=get_message("server.error", language),
                    error_code="SERVER_ERROR",
                    language=language
                )