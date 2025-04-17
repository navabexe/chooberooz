# Path: src/app/main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI

from src.infrastructure.setup.database_setup import database_lifespan
from src.infrastructure.setup.middleware_setup import setup_middlewares
from src.infrastructure.setup.router_setup import setup_routers
from src.infrastructure.setup.sentry_setup import initialize_sentry
from src.shared.errors.exception_handlers import register_exception_handlers
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.errors.base import BaseError
from src.shared.utilities.constants import HttpStatus

logger = LoggingService(LogConfig())


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage the lifecycle of the FastAPI application.

    Args:
        app: The FastAPI application instance.

    Raises:
        BaseError: If an error occurs during startup or shutdown.
    """
    try:
        initialize_sentry()
        async with database_lifespan():
            logger.info("Senama API started", context={"version": app.version})
            yield
            logger.info("Senama API stopped", context={})
    except Exception as e:
        logger.error("Lifespan error", context={"error": str(e)})
        raise BaseError(
            error_code="LIFESPAN_ERROR",
            message=f"Application lifecycle error: {str(e)}",
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"error": str(e)},
            language="en"
        )


app = FastAPI(
    title="Senama Marketplace API",
    version="1.0.0",
    description="Modular, scalable backend built with FastAPI.",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

setup_middlewares(app)
register_exception_handlers(app)
setup_routers(app)