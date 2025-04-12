from contextlib import asynccontextmanager
from src.infrastructure.storage.nosql.client import MongoDBConnection
from src.infrastructure.storage.cache.client import init_cache_pool, close_cache_pool
from src.shared.utilities.logging import log_info, log_error
from src.shared.config.settings import settings
from src.infrastructure.storage.nosql.repositories.base import MongoRepository

@asynccontextmanager
async def database_lifespan():
    """
    Manage the lifecycle of database connections (MongoDB and Redis).

    Yields:
        None: After successful connection setup.
    Raises:
        Exception: If connection to MongoDB or Redis fails.
    """
    try:
        # Connect to MongoDB
        await MongoDBConnection.connect()
        db = MongoDBConnection.get_db()
        log_info(
            "MongoDB connection established",
            extra={"uri": settings.MONGO_URI, "db": settings.MONGO_DB},
        )

        # Connect to Redis
        await init_cache_pool()
        log_info(
            "Redis connection established",
            extra={
                "host": settings.REDIS_HOST,
                "port": settings.REDIS_PORT,
                "db": settings.REDIS_DB,
            },
        )

        # Setup initial data (admins and categories)
        admins_repo = MongoRepository(db, "admins")
        categories_repo = MongoRepository(db, "business_categories")
        from src.infrastructure.setup.initial_setup import setup_admin_and_categories
        await setup_admin_and_categories(admins_repo, categories_repo)
        log_info("Initial admin and categories setup completed")

        yield

    except Exception as e:
        log_error("Database setup failed", extra={"error": str(e)})
        raise
    finally:
        # Cleanup
        await MongoDBConnection.disconnect()
        await close_cache_pool()
        log_info("MongoDB and Redis connections closed")