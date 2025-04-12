# File: src/common/middleware/error_middleware.py

import sentry_sdk
from fastapi.exceptions import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from src.shared.models.responses.base import ErrorResponse
from src.shared.utilities.logging import log_error, log_info


class ErrorLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        try:
            return await call_next(request)

        except HTTPException as http_exc:
            raise http_exc

        except Exception as exc:
            error_context = {
                "path": request.url.path,
                "method": request.method,
                "error": str(exc),
                "client_ip": request.client.host if request.client else "unknown",
                "headers": dict(request.headers),
            }

            log_error("Unhandled error in middleware", extra=error_context, exc_info=True)
            log_info("Sending to Sentry", extra={"error": str(exc), "path": request.url.path})
            sentry_sdk.capture_exception(exc)

            return JSONResponse(
                status_code=500,
                content=ErrorResponse(
                    detail="Unexpected server error.",
                    message="Something went wrong.",
                    status="error"
                ).model_dump()
            )
