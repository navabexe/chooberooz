# Path: src/shared/errors/exception_handlers.py
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_500_INTERNAL_SERVER_ERROR
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.i18n.messages import get_message
from src.shared.errors.base import BaseError
from src.shared.errors.router import ErrorRouter
from src.shared.utilities.language import extract_language
from src.shared.utilities.constants import HttpStatus, DomainErrorCode

logger = LoggingService(LogConfig())
error_router = ErrorRouter(logger)


def register_exception_handlers(app: FastAPI):
    """
    Register exception handlers for FastAPI application.

    Args:
        app: The FastAPI application instance.
    """

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        """Handle validation errors."""
        language = extract_language(request)
        errors = exc.errors()
        details = []
        for err in errors:
            loc = err.get("loc", [])
            msg = err.get("msg", "Invalid input.")
            field = loc[-1] if loc else "field"
            details.append(f"{field}: {msg}")

        error_message = "; ".join(details)
        error = BaseError(
            error_code=DomainErrorCode.VALIDATION_ERROR.value,
            message=get_message("server.error", language=language),
            status_code=HTTP_400_BAD_REQUEST,
            trace_id=logger.tracer.get_trace_id(),
            details={"errors": error_message},
            language=language
        )

        logger.error("Validation error", context={
            "path": request.url.path,
            "method": request.method,
            "errors": error_message,
            "language": language
        })

        response = error_router.route(error)
        return JSONResponse(
            status_code=response.status_code,
            content=response.model_dump()
        )

    @app.exception_handler(BaseError)
    async def base_error_handler(request: Request, exc: BaseError):
        """Handle custom BaseError exceptions."""
        language = exc.language or extract_language(request)
        logger.error("Custom BaseError caught", context={
            "path": request.url.path,
            "method": request.method,
            "status_code": exc.status_code,
            "detail": exc.message,
            "error_code": exc.error_code,
            "details": exc.details,
            "language": language
        })

        response = error_router.route(exc)
        return JSONResponse(
            status_code=response.status_code,
            content=response.model_dump()
        )

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        """Handle uncaught exceptions."""
        language = extract_language(request)
        error = BaseError(
            error_code="INTERNAL_SERVER_ERROR",
            message=get_message("server.error", language=language),
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            trace_id=logger.tracer.get_trace_id(),
            details={"error": str(exc)},
            language=language
        )

        logger.error("Unhandled exception", context={
            "path": request.url.path,
            "method": request.method,
            "error": str(exc),
            "language": language
        })

        response = error_router.route(error)
        return JSONResponse(
            status_code=response.status_code,
            content=response.model_dump()
        )