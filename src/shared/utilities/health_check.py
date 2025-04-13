# path: src/infrastructure/di/health_check.py
from redis.asyncio import Redis
from motor.motor_asyncio import AsyncIOMotorDatabase
from src.shared.utilities.logging import log_info, log_error

async def validate_redis(redis: Redis) -> bool:
    try:
        await redis.ping()
        log_info("Redis connection is healthy")
        return True
    except Exception as e:
        log_error("Redis connection check failed", extra={"error": str(e)})
        return False

async def validate_mongo(db: AsyncIOMotorDatabase) -> bool:
    try:
        await db.command("ping")
        log_info("MongoDB connection is healthy")
        return True
    except Exception as e:
        log_error("MongoDB connection check failed", extra={"error": str(e)})
        return False

async def validate_dependencies(redis: Redis, db: AsyncIOMotorDatabase) -> dict:
    return {
        "redis_ok": await validate_redis(redis),
        "mongo_ok": await validate_mongo(db)
    }
