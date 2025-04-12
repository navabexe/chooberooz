from fastapi import FastAPI, Request, HTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_500_INTERNAL_SERVER_ERROR

from src.shared.utilities.logging import log_error
from src.shared.models.responses.standard_response import ErrorResponse


def register_exception_handlers(app: FastAPI):
    """Register global exception handlers for all expected error types."""
    def build_error_response(status_code: int, detail: str, message: str = None):
        return JSONResponse(
            status_code=status_code,
            content=ErrorResponse(
                detail=detail,
                message=message or detail,
                status="error",
            ).model_dump()
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        """Handles Pydantic validation errors (e.g., missing fields, wrong types, etc.)."""
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
            "errors": error_message
        })

        return build_error_response(HTTP_400_BAD_REQUEST, detail=error_message)

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        """Handles all HTTP exceptions (including custom ones)."""
        log_error("HTTPException caught", extra={
            "path": request.url.path,
            "method": request.method,
            "status_code": exc.status_code,
            "detail": str(exc.detail),
        })

        return build_error_response(status_code=exc.status_code, detail=str(exc.detail))

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        """Handles uncaught general exceptions."""
        log_error("Unhandled exception", extra={
            "path": request.url.path,
            "method": request.method,
            "error": str(exc),
        }, exc_info=True)

        return build_error_response(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error occurred."
        )