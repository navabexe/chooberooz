from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import Response
from src.api.v1.middleware.error_handler import ErrorLoggingMiddleware
from src.shared.config.settings import settings
from src.shared.utilities.logging import log_info, log_error

async def log_requests_middleware(request: Request, call_next):
    """
    Middleware to log incoming HTTP requests.

    Args:
        request: The incoming HTTP request.
        call_next: The next middleware or endpoint to process the request.

    Returns:
        Response: The HTTP response.
    """
    try:
        body = await request.json()
        log_info(
            "Raw request body",
            extra={"method": request.method, "url": str(request.url), "body": body},
        )
    except Exception as e:
        log_error(
            "Failed to parse request body",
            extra={"error": str(e), "method": request.method, "url": str(request.url)},
        )
    log_info(
        "Incoming request",
        extra={"method": request.method, "url": str(request.url)},
    )
    return await call_next(request)

def setup_middlewares(app: FastAPI):
    """
    Configure FastAPI middlewares (CORS, error handling, request logging).

    Args:
        app: The FastAPI application instance.
    """
    # Add request logging middleware
    app.middleware("http")(log_requests_middleware)

    # Add error logging middleware
    app.add_middleware(ErrorLoggingMiddleware)

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[origin.strip() for origin in settings.CORS_ORIGINS.split(",")],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    log_info(
        "Middlewares configured",
        extra={"cors_origins": settings.CORS_ORIGINS},
    )