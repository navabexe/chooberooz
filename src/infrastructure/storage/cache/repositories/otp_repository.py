# Path: src/infrastructure/storage/cache/repositories/otp_repository.py
from typing import Optional, Dict, List
from redis.asyncio import Redis
from redis.exceptions import RedisError
from src.infrastructure.storage.cache.client import get_cache_client
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.errors.infrastructure.database import CacheError
from src.shared.utilities.constants import HttpStatus


class OTPRepository:
    """Repository for OTP operations in Redis."""

    def __init__(self, redis: Redis = None):
        """Initialize repository with optional Redis client."""
        self._redis = redis if redis else None
        self._redis_initialized = False
        self.logger = LoggingService(LogConfig())

    async def _get_redis(self) -> Redis:
        """Lazily initialize and return a Redis client."""
        if not self._redis_initialized:
            self._redis = await get_cache_client()
            self._redis_initialized = True
        return self._redis

    async def get(self, key: str) -> Optional[str]:
        """Get value from Redis by key."""
        try:
            redis = await self._get_redis()
            value = await redis.get(key)
            return value.decode("utf-8") if isinstance(value, bytes) else value
        except RedisError as e:
            self.logger.error("Redis GET failed", context={"key": key, "error": str(e)})
            raise CacheError(
                operation="get",
                error_code="CACHE_ERROR",
                message=f"Redis operation failed: {str(e)}",
                status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"key": key, "error": str(e)},
                language="en"
            )

    async def setex(self, key: str, ttl: int, value: str):
        """Set key with expiration in Redis."""
        try:
            redis = await self._get_redis()
            await redis.setex(key, ttl, value)
        except RedisError as e:
            self.logger.error("Redis SETEX failed", context={"key": key, "error": str(e)})
            raise CacheError(
                operation="setex",
                error_code="CACHE_ERROR",
                message=f"Redis operation failed: {str(e)}",
                status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"key": key, "error": str(e)},
                language="en"
            )

    async def incr(self, key: str) -> int:
        """Increment key in Redis."""
        try:
            redis = await self._get_redis()
            return await redis.incr(key)
        except RedisError as e:
            self.logger.error("Redis INCR failed", context={"key": key, "error": str(e)})
            raise CacheError(
                operation="incr",
                error_code="CACHE_ERROR",
                message=f"Redis operation failed: {str(e)}",
                status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"key": key, "error": str(e)},
                language="en"
            )

    async def expire(self, key: str, ttl: int):
        """Set expiration for key in Redis."""
        try:
            redis = await self._get_redis()
            await redis.expire(key, ttl)
        except RedisError as e:
            self.logger.error("Redis EXPIRE failed", context={"key": key, "error": str(e)})
            raise CacheError(
                operation="expire",
                error_code="CACHE_ERROR",
                message=f"Redis operation failed: {str(e)}",
                status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"key": key, "error": str(e)},
                language="en"
            )

    async def delete(self, key: str):
        """Delete key from Redis."""
        try:
            redis = await self._get_redis()
            await redis.delete(key)
        except RedisError as e:
            self.logger.error("Redis DELETE failed", context={"key": key, "error": str(e)})
            raise CacheError(
                operation="delete",
                error_code="CACHE_ERROR",
                message=f"Redis operation failed: {str(e)}",
                status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"key": key, "error": str(e)},
                language="en"
            )

    async def hset(self, key: str, mapping: Dict[bytes, bytes]):
        """Set hash fields in Redis."""
        try:
            redis = await self._get_redis()
            await redis.hset(key, mapping=mapping)
        except RedisError as e:
            self.logger.error("Redis HSET failed", context={"key": key, "error": str(e)})
            raise CacheError(
                operation="hset",
                error_code="CACHE_ERROR",
                message=f"Redis operation failed: {str(e)}",
                status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"key": key, "error": str(e)},
                language="en"
            )

    async def hgetall(self, key: str) -> Dict[bytes, bytes]:
        """Get all hash fields from Redis."""
        try:
            redis = await self._get_redis()
            return await redis.hgetall(key)
        except RedisError as e:
            self.logger.error("Redis HGETALL failed", context={"key": key, "error": str(e)})
            raise CacheError(
                operation="hgetall",
                error_code="CACHE_ERROR",
                message=f"Redis operation failed: {str(e)}",
                status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"key": key, "error": str(e)},
                language="en"
            )

    async def scan_keys(self, pattern: str) -> List[str]:
        """Scan Redis keys matching pattern."""
        cursor = b"0"
        keys = []
        try:
            redis = await self._get_redis()
            while cursor != 0:
                cursor, batch = await redis.scan(cursor=cursor, match=pattern, count=100)
                keys.extend(batch)
            return [key.decode() if isinstance(key, bytes) else key for key in keys]
        except RedisError as e:
            self.logger.error("Redis SCAN failed", context={"pattern": pattern, "error": str(e)})
            raise CacheError(
                operation="scan",
                error_code="CACHE_ERROR",
                message=f"Redis operation failed: {str(e)}",
                status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"pattern": pattern, "error": str(e)},
                language="en"
            )