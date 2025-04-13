# path: Root/App/main.py
from contextlib import asynccontextmanager
from fastapi import FastAPI
from src.shared.utilities.logging import log_info, log_error
from src.shared.errors.exception_handlers import register_exception_handlers
from src.infrastructure.setup.database_setup import database_lifespan
from src.infrastructure.setup.sentry_setup import initialize_sentry
from src.infrastructure.setup.middleware_setup import setup_middlewares
from src.infrastructure.setup.router_setup import setup_routers

@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        initialize_sentry()
        async with database_lifespan():
            log_info("Senama API started", extra={"version": app.version})
            yield
            log_info("Senama API stopped")
    except Exception as e:
        log_error("Lifespan error", extra={"error": str(e)})
        raise

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
