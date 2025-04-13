from typing import Optional, Dict, Any
from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_500_INTERNAL_SERVER_ERROR

from src.shared.utilities.logging import log_error
from src.shared.models.responses.base import ErrorResponse  # مدل بهبودیافته
from src.shared.i18n.messages import get_message
from src.shared.errors.base import AppHTTPException


def register_exception_handlers(app: FastAPI):
    """Register global exception handlers for all expected error types."""

    def build_error_response(
            status_code: int,
            detail: str,
            message: Optional[str] = None,
            error_code: Optional[str] = None,
            metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Build a standardized JSON error response.

        Args:
            status_code: HTTP status code (e.g., 400, 500).
            detail: Technical error description.
            message: User-friendly error message (optional, defaults to detail).
            error_code: Unique error code (optional).
            metadata: Additional error information (optional).

        Returns:
            JSONResponse with ErrorResponse model.
        """
        return JSONResponse(
            status_code=status_code,
            content=ErrorResponse(
                detail=detail,
                message=message or detail,
                error_code=error_code,
                status="error",
                metadata=metadata
            ).model_dump()
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        """Handles Pydantic validation errors (e.g., missing fields, wrong types)."""
        language = request.query_params.get("response_language", "en")
        errors = exc.errors()
        details = []
        for err in errors:
            loc = err.get("loc", [])
            msg = err.get("msg", "Invalid input.")
            field = loc[-1] if loc else "field"
            details.append(f"{field}: {msg}")

        error_message = "; ".join(details)
        log_error("Validation error", extra={
            "path": request.url.path,
            "method": request.method,
            "errors": error_message,
            "language": language
        })

        return build_error_response(
            status_code=HTTP_400_BAD_REQUEST,
            detail=error_message,
            message=get_message("server.error", language),
            error_code="VALIDATION_ERROR"
        )

    @app.exception_handler(AppHTTPException)
    async def custom_http_exception_handler(request: Request, exc: AppHTTPException):
        """Handles custom HTTP exceptions defined in src.shared.errors.base."""
        language = exc.language or request.query_params.get("response_language", "en")
        log_error("Custom HTTPException caught", extra={
            "path": request.url.path,
            "method": request.method,
            "status_code": exc.status_code,
            "detail": exc.detail,
            "error_code": exc.error_code,
            "metadata": exc.metadata,
            "language": language
        })

        return build_error_response(
            status_code=exc.status_code,
            detail=exc.detail,
            message=exc.message,
            error_code=exc.error_code,
            metadata=exc.metadata
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Handles standard HTTP exceptions not covered by AppHTTPException."""
        language = request.query_params.get("response_language", "en")
        log_error("HTTPException caught", extra={
            "path": request.url.path,
            "method": request.method,
            "status_code": exc.status_code,
            "detail": str(exc.detail),
            "language": language
        })

        return build_error_response(
            status_code=exc.status_code,
            detail=str(exc.detail),
            message=get_message("server.error", language),
            error_code="HTTP_ERROR"
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        """Handles uncaught general exceptions as a fallback."""
        language = request.query_params.get("response_language", "en")
        log_error("Unhandled exception", extra={
            "path": request.url.path,
            "method": request.method,
            "error": str(exc),
            "language": language
        }, exc_info=True)

        return build_error_response(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error occurred.",
            message=get_message("server.error", language),
            error_code="INTERNAL_SERVER_ERROR"
        )