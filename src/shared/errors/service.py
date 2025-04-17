# Path: src/shared/errors/service.py
from typing import Optional, Dict, Any

from fastapi import HTTPException

from src.shared.errors.base import BaseError
from src.shared.errors.response import ErrorResponse
from src.shared.errors.router import ErrorRouter
from src.shared.logging.service import LoggingService
from src.shared.utilities.constants import HttpStatus
from src.shared.utilities.types import LanguageCode


class ErrorService:
    """Central service for error handling."""

    def __init__(self, logger: LoggingService):
        """Initialize service with logger."""
        self.router = ErrorRouter(logger)

    def handle(
            self,
            error: BaseError,
            language: LanguageCode = "en",
            context: Optional[Dict[str, Any]] = None
    ) -> ErrorResponse:
        """Handle error and return response."""
        try:
            response = self.router.route(error, context)
            return response
        except Exception as e:
            # Fallback for router errors
            fallback_error = BaseError(
                error_code="INTERNAL_SERVER_ERROR",
                message="Failed to handle error.",
                status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
                trace_id=error.trace_id,
                details={"original_error": str(e)},
                language=language
            )
            self.router.logger.error(f"Error handling failed: {str(e)}", context)
            return ErrorResponse.from_error(fallback_error)

    def raise_error(self, error: BaseError) -> None:
        """Raise error with response conversion."""
        response = self.handle(error, error.language)
        raise HTTPException(
            status_code=response.status_code,
            detail=response.model_dump()
        )