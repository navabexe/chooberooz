from contextlib import asynccontextmanager
from fastapi import FastAPI
from src.shared.config.settings import settings
from src.shared.utilities.logging import log_info
from src.shared.errors.exception_handlers import register_exception_handlers
from src.infrastructure.setup.database_setup import database_lifespan
from src.infrastructure.setup.sentry_setup import initialize_sentry
from src.infrastructure.setup.middleware_setup import setup_middlewares
from src.infrastructure.setup.router_setup import setup_routers

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Manage the lifecycle of the FastAPI application.

    Initializes Sentry, database connections, and logs startup/shutdown events.

    Args:
        app: The FastAPI application instance.

    Yields:
        None: After successful startup.

    Raises:
        Exception: If any setup step fails.
    """
    initialize_sentry()
    async with database_lifespan():
        log_info("Senama API started", extra={"version": app.version})
        yield
        log_info("Senama API stopped")

app = FastAPI(
    title="Senama Marketplace API",
    version="1.0.0",
    description="Modular, scalable backend built with FastAPI.",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# Setup middlewares and exception handlers
setup_middlewares(app)
register_exception_handlers(app)

# Setup routers
setup_routers(app)