from fastapi import HTTPException, Request, status, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase
from redis.asyncio import Redis
from src.shared.utilities.logging import log_error
from src.infrastructure.storage.nosql.client import get_nosql_db
from src.infrastructure.storage.cache.client import get_cache_client

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
        HTTPException: If either db or redis connection is None.
    """
    if db is None:
        log_error("Database connection is None", extra={"endpoint": request.url.path})
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database unavailable")
    if redis is None:
        log_error("Redis connection is None", extra={"endpoint": request.url.path})
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Redis unavailable")
    return {"db": db, "redis": redis}