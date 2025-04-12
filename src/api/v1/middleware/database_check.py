# src/api/v1/middleware/database_check.py
from fastapi import HTTPException, Request, status
from motor.motor_asyncio import AsyncIOMotorDatabase
from redis.asyncio import Redis
from src.shared.utilities.logging import log_error

async def check_database_connection(
    request: Request,
    db: AsyncIOMotorDatabase,
    redis: Redis,
):
    """Ensure database and Redis connections are available."""
    if db is None:
        log_error("Database connection is None", extra={"endpoint": request.url.path})
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Database unavailable")
    if redis is None:
        log_error("Redis connection is None", extra={"endpoint": request.url.path})
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Redis unavailable")
    return {"db": db, "redis": redis}