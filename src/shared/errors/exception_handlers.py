# path: src/shared/errors/exception_handlers.py
from typing import Optional, Dict, Any
from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_500_INTERNAL_SERVER_ERROR

from src.shared.utilities.logging import log_error
from src.shared.models.responses.base import ErrorResponse
from src.shared.i18n.messages import get_message
from src.shared.errors.base import AppHTTPException
from src.shared.utilities.language import extract_language

def register_exception_handlers(app: FastAPI):
    def build_error_response(
            status_code: int,
            detail: str,
            message: Optional[str] = None,
            error_code: Optional[str] = None,
            metadata: Optional[Dict[str, Any]] = None
    ):
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
        language = extract_language(request)
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
        language = exc.language or extract_language(request)
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
        language = extract_language(request)
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
        language = extract_language(request)
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
