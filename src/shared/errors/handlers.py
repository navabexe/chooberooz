# Path: src/shared/errors/handlers.py
from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from starlette.status import HTTP_500_INTERNAL_SERVER_ERROR

from src.shared.errors.base import BaseError
from src.shared.errors.response import ErrorResponse
from src.shared.errors.service import ErrorService
from src.shared.utilities.constants import HttpStatus


def register_error_handlers(app: FastAPI, error_service: ErrorService):
    """Register error handlers for FastAPI app."""

    @app.exception_handler(BaseError)
    async def base_error_handler(request: Request, exc: BaseError) -> ErrorResponse:
        """Handle BaseError exceptions."""
        language = request.headers.get("accept-language", "en").split(",")[0]
        return error_service.handle(exc, language=language)

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(request: Request, exc: RequestValidationError) -> ErrorResponse:
        """Handle validation errors."""
        language = request.headers.get("accept-language", "en").split(",")[0]
        details = {"errors": exc.errors()}
        error = BaseError(
            error_code="VALIDATION_ERROR",
            message="Invalid input data.",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=error_service.router.logger.tracer.get_trace_id(),
            details=details,
            language=language
        )
        return error_service.handle(error, language=language, context=details)

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> ErrorResponse:
        """Handle HTTP exceptions."""
        language = request.headers.get("accept-language", "en").split(",")[0]
        error = BaseError(
            error_code="HTTP_ERROR",
            message=exc.detail,
            status_code=exc.status_code,
            trace_id=error_service.router.logger.tracer.get_trace_id(),
            details={"detail": exc.detail},
            language=language
        )
        return error_service.handle(error, language=language)

    @app.exception_handler(Exception)
    async def generic_error_handler(request: Request, exc: Exception) -> ErrorResponse:
        """Handle generic exceptions."""
        language = request.headers.get("accept-language", "en").split(",")[0]
        error = BaseError(
            error_code="INTERNAL_SERVER_ERROR",
            message="Unexpected server error.",
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            trace_id=error_service.router.logger.tracer.get_trace_id(),
            details={"error": str(exc)},
            language=language
        )
        return error_service.handle(error, language=language, context={"error": str(exc)})