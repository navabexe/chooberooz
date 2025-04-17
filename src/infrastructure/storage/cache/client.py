# Path: src/infrastructure/cache/redis.py
import ssl
from typing import Optional
from redis.asyncio import Redis, ConnectionPool
from redis.exceptions import RedisError
from src.shared.config.settings import settings
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.errors.infrastructure.database import CacheError
from src.shared.utilities.constants import HttpStatus

redis_pool: Optional[ConnectionPool] = None
redis_client: Optional[Redis] = None
logger = LoggingService(LogConfig())

async def init_cache_pool() -> ConnectionPool:
    """Initialize Redis connection pool with settings from .env."""
    global redis_pool, redis_client
    try:
        connection_kwargs = {
            "host": settings.REDIS_HOST,
            "port": settings.REDIS_PORT,
            "db": settings.REDIS_DB,
            "decode_responses": True
        }

        redis_password = getattr(settings, "REDIS_PASSWORD", None)
        if redis_password and redis_password.strip():
            connection_kwargs["password"] = redis_password
            logger.info("Using Redis with password", context={"host": settings.REDIS_HOST})

        if settings.REDIS_USE_SSL:
            ssl_context = ssl.create_default_context(cafile=settings.REDIS_SSL_CA_CERTS)
            ssl_context.load_cert_chain(certfile=settings.REDIS_SSL_CERT, keyfile=settings.REDIS_SSL_KEY)
            connection_kwargs["ssl_context"] = ssl_context
            redis_pool = ConnectionPool.from_url(
                f"rediss://{settings.REDIS_HOST}:{settings.REDIS_PORT}/{settings.REDIS_DB}",
                **connection_kwargs
            )
        else:
            redis_pool = ConnectionPool(**connection_kwargs)

        redis_client = Redis(connection_pool=redis_pool)
        await redis_client.ping()
        logger.info("Redis connection established", context={
            "host": settings.REDIS_HOST,
            "port": settings.REDIS_PORT,
            "db": settings.REDIS_DB,
            "ssl": settings.REDIS_USE_SSL
        })

    except RedisError as e:
        logger.error("Redis connection failed", context={"error": str(e), "host": settings.REDIS_HOST})
        raise CacheError(
            operation="connect",
            error_code="CACHE_ERROR",
            message="Redis unavailable",
            status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"error": str(e)},
            language="en"
        )

    return redis_pool

async def close_cache_pool():
    """Close Redis connection pool."""
    global redis_pool, redis_client
    if redis_client:
        await redis_client.close()
    if redis_pool:
        await redis_pool.disconnect()
    logger.info("Redis connection pool closed", context={})
    redis_pool = None
    redis_client = None

async def get_cache_client() -> Redis:
    """Dependency to get Redis client."""
    global redis_client
    try:
        if redis_client is None or not await redis_client.ping():
            await init_cache_pool()
        return redis_client
    except Exception as e:
        logger.error("Failed to get Redis client", context={"error": str(e)})
        raise CacheError(
            operation="get_client",
            error_code="CACHE_ERROR",
            message="Could not connect to Redis",
            status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"error": str(e)},
            language="en"
        )