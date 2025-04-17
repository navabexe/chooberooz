# Path: src/infrastructure/di/health_check.py
from redis.asyncio import Redis
from motor.motor_asyncio import AsyncIOMotorDatabase
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig

logger = LoggingService(LogConfig())

async def validate_redis(redis: Redis) -> bool:
    """Check Redis connection health."""
    try:
        await redis.ping()
        logger.info("Redis connection is healthy", context={})
        return True
    except Exception as e:
        logger.error("Redis connection check failed", context={"error": str(e)})
        return False

async def validate_mongo(db: AsyncIOMotorDatabase) -> bool:
    """Check MongoDB connection health."""
    try:
        await db.command("ping")
        logger.info("MongoDB connection is healthy", context={})
        return True
    except Exception as e:
        logger.error("MongoDB connection check failed", context={"error": str(e)})
        return False

async def validate_dependencies(redis: Redis, db: AsyncIOMotorDatabase) -> dict:
    """Validate Redis and MongoDB connections."""
    return {
        "redis_ok": await validate_redis(redis),
        "mongo_ok": await validate_mongo(db)
    }