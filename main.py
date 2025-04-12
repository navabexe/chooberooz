from contextlib import asynccontextmanager

import sentry_sdk
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from sentry_sdk.integrations.fastapi import FastApiIntegration

from src.api.routers.all_endpoints import all_routers
from src.shared.config.settings import settings
from src.shared.errors.exception_handlers import register_exception_handlers
from src.shared.utilities.logging import log_info, log_error
from src.api.middleware.error_middleware import ErrorLoggingMiddleware
from src.infrastructure.storage.nosql.client import MongoDBConnection
from src.infrastructure.storage.nosql.repositories.base import MongoRepository
from src.infrastructure.storage.cache.client import init_cache_pool, close_cache_pool
from src.infrastructure.setup.initial_setup import setup_admin_and_categories


# Load environment variables
load_dotenv()

# Initialize Sentry
sentry_sdk.init(
    dsn=settings.SENTRY_DSN,
    integrations=[FastApiIntegration()],
    traces_sample_rate=settings.SENTRY_TRACES_SAMPLE_RATE,
    environment=settings.ENVIRONMENT,
    send_default_pii=settings.SENTRY_SEND_PII
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown tasks for the FastAPI app."""
    # Startup tasks
    try:
        await MongoDBConnection.connect()
        db = MongoDBConnection.get_db()

        admins_repo = MongoRepository(db, "admins")
        categories_repo = MongoRepository(db, "business_categories")
        await setup_admin_and_categories(admins_repo, categories_repo)

        await init_cache_pool()

        log_info("Registered routes", extra={"routes": [route.path for route in app.routes]})
        log_info("Senama API started", extra={"version": app.version})
    except Exception as e:
        log_error("Startup failed", extra={"error": str(e)})
        sentry_sdk.capture_exception(e)
        raise

    yield  # Application is running

    # Shutdown tasks
    await MongoDBConnection.disconnect()
    await close_cache_pool()
    log_info("Senama API stopped")


# Create FastAPI app instance
app = FastAPI(
    title="Senama Marketplace API",
    version="1.0.0",
    description="Modular, scalable backend built with FastAPI.",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)


# Request logger middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log incoming HTTP requests."""
    log_info("Incoming request", extra={"method": request.method, "url": str(request.url)})
    return await call_next(request)


# Register middlewares
app.add_middleware(ErrorLoggingMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register exception handlers
register_exception_handlers(app)

# Register routers
try:
    log_info("Attempting to include all_routers", extra={"router": str(all_routers)})
    app.include_router(all_routers)
    log_info("Successfully included all_routers")
except Exception as e:
    log_error("Failed to include all_routers", extra={"error": str(e)})
    sentry_sdk.capture_exception(e)
    raise