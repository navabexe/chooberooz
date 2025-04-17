# Path: src/api/v1/middleware/database_check.py
from fastapi import Request, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase
from redis.asyncio import Redis
from src.infrastructure.storage.nosql.client import get_nosql_db
from src.infrastructure.storage.cache.client import get_cache_client
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.errors.infrastructure.database import DatabaseConnectionError, CacheError
from src.shared.utilities.constants import HttpStatus

logger = LoggingService(LogConfig())


async def check_database_connection(
        request: Request,
        db: AsyncIOMotorDatabase = Depends(get_nosql_db),
        redis: Redis = Depends(get_cache_client),
):
    """
    Ensure database and Redis connections are available.

    Args:
        request: The incoming HTTP request.
        db: The MongoDB database instance.
        redis: The Redis client instance.

    Returns:
        dict: A dictionary containing the db and redis instances.

    Raises:
        DatabaseConnectionError: If db connection is None.
        CacheError: If redis connection is None.
    """
    if db is None:
        logger.error("Database connection is None", context={"endpoint": request.url.path})
        raise DatabaseConnectionError(
            db_type="MongoDB",
            error_code="DATABASE_CONNECTION_FAILED",
            message="Database unavailable",
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"endpoint": request.url.path},
            language="en"
        )
    if redis is None:
        logger.error("Redis connection is None", context={"endpoint": request.url.path})
        raise CacheError(
            operation="connect",
            error_code="CACHE_ERROR",
            message="Redis unavailable",
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"endpoint": request.url.path},
            language="en"
        )
    return {"db": db, "redis": redis}