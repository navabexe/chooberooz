# Path: src/api/v1/middleware/middleware.py
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import Response
from src.shared.config.settings import settings
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig

logger = LoggingService(LogConfig())


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
        logger.info(
            "Raw request body",
            context={"method": request.method, "url": str(request.url), "body": body},
        )
    except Exception as e:
        logger.error(
            "Failed to parse request body",
            context={"error": str(e), "method": request.method, "url": str(request.url)},
        )
    logger.info(
        "Incoming request",
        context={"method": request.method, "url": str(request.url)},
    )
    return await call_next(request)


def setup_middlewares(app: FastAPI):
    """
    Configure FastAPI middlewares (CORS, request logging).

    Args:
        app: The FastAPI application instance.
    """
    # Add request logging middleware
    app.middleware("http")(log_requests_middleware)

    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[origin.strip() for origin in settings.CORS_ORIGINS.split(",")],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    logger.info(
        "Middlewares configured",
        context={"cors_origins": settings.CORS_ORIGINS},
    )