# Path: src/shared/errors/router.py
from typing import Optional, Dict, Any
from src.shared.errors.base import BaseError
from src.shared.logging.service import LoggingService
from src.shared.models.responses.base import ErrorResponse
from src.shared.utilities.constants import DomainErrorCode, InfraErrorCode, HttpStatus


class ErrorRouter:
    """Router for handling errors."""

    def __init__(self, logger: LoggingService):
        """Initialize router with logger."""
        self.logger = logger

    def route(
            self,
            error: BaseError,
            context: Optional[Dict[str, Any]] = None
    ) -> ErrorResponse:
        """Route error to appropriate handler based on error code."""
        response = ErrorResponse.from_error(error)
        context = context or error.details

        if error.error_code in {e.value for e in DomainErrorCode}:
            return self._handle_domain_error(error, response, context)
        elif error.error_code in {e.value for e in InfraErrorCode}:
            return self._handle_infra_error(error, response, context)
        else:
            return self._handle_generic_error(error, response, context)

    def _handle_domain_error(
            self,
            error: BaseError,
            response: ErrorResponse,
            context: Dict[str, Any]
    ) -> ErrorResponse:
        """Handle domain errors."""
        if error.status_code >= HttpStatus.INTERNAL_SERVER_ERROR.value:
            self.logger.error(f"Domain error: {error.error_code}", context)
        else:
            self.logger.info(f"Domain error: {error.error_code}", context)
        return response

    def _handle_infra_error(
            self,
            error: BaseError,
            response: ErrorResponse,
            context: Dict[str, Any]
    ) -> ErrorResponse:
        """Handle infrastructure errors."""
        self.logger.critical(f"Infrastructure error: {error.error_code}", context)
        # Placeholder for alerting (e.g., Sentry, PagerDuty)
        return response

    def _handle_generic_error(
            self,
            error: BaseError,
            response: ErrorResponse,
            context: Dict[str, Any]
    ) -> ErrorResponse:
        """Handle generic errors."""
        self.logger.error(f"Generic error: {error.error_code}", context)
        return response