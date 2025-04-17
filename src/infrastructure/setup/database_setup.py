# Path: src/infrastructure/setup/lifespan.py
from contextlib import asynccontextmanager
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
from src.infrastructure.storage.nosql.client import MongoDBConnection
from src.infrastructure.storage.cache.client import init_cache_pool, close_cache_pool
from src.shared.config.settings import settings
from src.infrastructure.storage.nosql.repositories.base import MongoRepository
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig

logger = LoggingService(LogConfig())


@asynccontextmanager
async def database_lifespan():
    """
    Manage the lifecycle of database connections (MongoDB and Redis) with retry mechanism.

    Yields:
        None: After successful connection setup.

    Raises:
        Exception: If all retry attempts for connecting to MongoDB or Redis fail.
    """

    # Retry decorator for MongoDB connection
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_fixed(2),
        retry=retry_if_exception_type(Exception),
        after=lambda retry_state: logger.error(
            f"MongoDB connection attempt {retry_state.attempt_number} failed",
            context={"error": str(retry_state.outcome.exception())},
        ),
    )
    async def connect_mongo():
        await MongoDBConnection.connect()
        logger.info(
            "MongoDB connection established",
            context={"uri": settings.MONGO_URI, "db": settings.MONGO_DB},
        )

    # Retry decorator for Redis connection
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_fixed(2),
        retry=retry_if_exception_type(Exception),
        after=lambda retry_state: logger.error(
            f"Redis connection attempt {retry_state.attempt_number} failed",
            context={"error": str(retry_state.outcome.exception())},
        ),
    )
    async def connect_redis():
        await init_cache_pool()
        logger.info(
            "Redis connection established",
            context={
                "host": settings.REDIS_HOST,
                "port": settings.REDIS_PORT,
                "db": settings.REDIS_DB,
            },
        )

    try:
        # Connect to MongoDB with retry
        await connect_mongo()
        db = MongoDBConnection.get_db()

        # Connect to Redis with retry
        await connect_redis()

        # Setup initial data (admins and categories)
        admins_repo = MongoRepository(db, "admins")
        categories_repo = MongoRepository(db, "business_categories")
        from src.infrastructure.setup.initial_setup import setup_admin_and_categories
        await setup_admin_and_categories(admins_repo, categories_repo)
        logger.info("Initial admin and categories setup completed", context={})

        yield

    except Exception as e:
        logger.error("Database setup failed after retries", context={"error": str(e)})
        raise
    finally:
        # Cleanup
        await MongoDBConnection.disconnect()
        await close_cache_pool()
        logger.info("MongoDB and Redis connections closed", context={})