# # path: src/infrastructure/storage/cache/repositories/otp_repository.py
# from typing import Optional, Dict, List
# from redis.asyncio import Redis
# from redis.exceptions import RedisError
# from src.infrastructure.storage.cache.client import get_cache_client
# from src.shared.errors.base import DatabaseConnectionException
# from src.shared.utilities.logging import log_error
#
# class OTPRepository:
#     def __init__(self, redis: Redis = None):
#         self.redis = redis or get_cache_client()
#
#     async def get(self, key: str) -> Optional[str]:
#         try:
#             value = await (await self.redis).get(key)
#             return value.decode("utf-8") if isinstance(value, bytes) else value
#         except RedisError as e:
#             log_error("Redis GET failed", extra={"key": key, "error": str(e)})
#             raise DatabaseConnectionException("Redis", detail=str(e))
#
#     async def setex(self, key: str, ttl: int, value: str):
#         try:
#             await (await self.redis).setex(key, ttl, value)
#         except RedisError as e:
#             log_error("Redis SETEX failed", extra={"key": key, "error": str(e)})
#             raise DatabaseConnectionException("Redis", detail=str(e))
#
#     async def incr(self, key: str) -> int:
#         try:
#             return await (await self.redis).incr(key)
#         except RedisError as e:
#             log_error("Redis INCR failed", extra={"key": key, "error": str(e)})
#             raise DatabaseConnectionException("Redis", detail=str(e))
#
#     async def expire(self, key: str, ttl: int):
#         try:
#             await (await self.redis).expire(key, ttl)
#         except RedisError as e:
#             log_error("Redis EXPIRE failed", extra={"key": key, "error": str(e)})
#             raise DatabaseConnectionException("Redis", detail=str(e))
#
#     async def delete(self, key: str):
#         try:
#             await (await self.redis).delete(key)
#         except RedisError as e:
#             log_error("Redis DELETE failed", extra={"key": key, "error": str(e)})
#             raise DatabaseConnectionException("Redis", detail=str(e))
#
#     async def hset(self, key: str, mapping: Dict[bytes, bytes]):
#         try:
#             await (await self.redis).hset(key, mapping=mapping)
#         except RedisError as e:
#             log_error("Redis HSET failed", extra={"key": key, "error": str(e)})
#             raise DatabaseConnectionException("Redis", detail=str(e))
#
#     async def hgetall(self, key: str) -> Dict[bytes, bytes]:
#         try:
#             return await (await self.redis).hgetall(key)
#         except RedisError as e:
#             log_error("Redis HGETALL failed", extra={"key": key, "error": str(e)})
#             raise DatabaseConnectionException("Redis", detail=str(e))
#
#     async def scan_keys(self, pattern: str) -> List[str]:
#         cursor = b"0"
#         keys = []
#         try:
#             redis = await self.redis
#             while cursor != 0:
#                 cursor, batch = await redis.scan(cursor=cursor, match=pattern, count=100)
#                 keys.extend(batch)
#             return [key.decode() if isinstance(key, bytes) else key for key in keys]
#         except RedisError as e:
#             log_error("Redis SCAN failed", extra={"pattern": pattern, "error": str(e)})
#             raise DatabaseConnectionException("Redis", detail=str(e))

# path: src/infrastructure/storage/cache/repositories/otp_repository.py
from typing import Optional, Dict, List
from redis.asyncio import Redis
from redis.exceptions import RedisError
from src.infrastructure.storage.cache.client import get_cache_client
from src.shared.errors.base import DatabaseConnectionException
from src.shared.utilities.logging import log_error

class OTPRepository:
    def __init__(self, redis: Redis = None):
        self._redis = redis if redis else None
        self._redis_initialized = False

    async def _get_redis(self) -> Redis:
        """Lazily initialize and return a Redis client."""
        if not self._redis_initialized:
            self._redis = await get_cache_client()
            self._redis_initialized = True
        return self._redis

    async def get(self, key: str) -> Optional[str]:
        try:
            redis = await self._get_redis()
            value = await redis.get(key)
            return value.decode("utf-8") if isinstance(value, bytes) else value
        except RedisError as e:
            log_error("Redis GET failed", extra={"key": key, "error": str(e)})
            raise DatabaseConnectionException("Redis", detail=str(e))

    async def setex(self, key: str, ttl: int, value: str):
        try:
            redis = await self._get_redis()
            await redis.setex(key, ttl, value)
        except RedisError as e:
            log_error("Redis SETEX failed", extra={"key": key, "error": str(e)})
            raise DatabaseConnectionException("Redis", detail=str(e))

    async def incr(self, key: str) -> int:
        try:
            redis = await self._get_redis()
            return await redis.incr(key)
        except RedisError as e:
            log_error("Redis INCR failed", extra={"key": key, "error": str(e)})
            raise DatabaseConnectionException("Redis", detail=str(e))

    async def expire(self, key: str, ttl: int):
        try:
            redis = await self._get_redis()
            await redis.expire(key, ttl)
        except RedisError as e:
            log_error("Redis EXPIRE failed", extra={"key": key, "error": str(e)})
            raise DatabaseConnectionException("Redis", detail=str(e))

    async def delete(self, key: str):
        try:
            redis = await self._get_redis()
            await redis.delete(key)
        except RedisError as e:
            log_error("Redis DELETE failed", extra={"key": key, "error": str(e)})
            raise DatabaseConnectionException("Redis", detail=str(e))

    async def hset(self, key: str, mapping: Dict[bytes, bytes]):
        try:
            redis = await self._get_redis()
            await redis.hset(key, mapping=mapping)
        except RedisError as e:
            log_error("Redis HSET failed", extra={"key": key, "error": str(e)})
            raise DatabaseConnectionException("Redis", detail=str(e))

    async def hgetall(self, key: str) -> Dict[bytes, bytes]:
        try:
            redis = await self._get_redis()
            return await redis.hgetall(key)
        except RedisError as e:
            log_error("Redis HGETALL failed", extra={"key": key, "error": str(e)})
            raise DatabaseConnectionException("Redis", detail=str(e))

    async def scan_keys(self, pattern: str) -> List[str]:
        cursor = b"0"
        keys = []
        try:
            redis = await self._get_redis()
            while cursor != 0:
                cursor, batch = await redis.scan(cursor=cursor, match=pattern, count=100)
                keys.extend(batch)
            return [key.decode() if isinstance(key, bytes) else key for key in keys]
        except RedisError as e:
            log_error("Redis SCAN failed", extra={"pattern": pattern, "error": str(e)})
            raise DatabaseConnectionException("Redis", detail=str(e))