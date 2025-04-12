from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from src.shared.config.settings import settings
from src.shared.errors.base import ServiceUnavailableException
from src.shared.utilities.logging import log_info, log_error


class MongoDBConnection:
    _client: AsyncIOMotorClient = None
    _db: AsyncIOMotorDatabase = None

    @classmethod
    async def connect(cls):
        if cls._client is None:
            try:
                mongo_uri = settings.MONGO_URI or "mongodb://localhost:27017"
                timeout = getattr(settings, "MONGO_TIMEOUT", 20000)

                log_info("Attempting MongoDB connection", extra={"uri": mongo_uri, "timeout": timeout})

                cls._client = AsyncIOMotorClient(
                    mongo_uri,
                    serverSelectionTimeoutMS=timeout
                )
                cls._db = cls._client[settings.MONGO_DB]
                await cls._client.admin.command("ping")

                log_info("MongoDB connection established", extra={
                    "db": settings.MONGO_DB,
                    "uri": mongo_uri
                })

            except Exception as e:
                log_error("MongoDB connection failed", extra={
                    "uri": mongo_uri,
                    "timeout": timeout,
                    "error": str(e)
                }, exc_info=True)
                raise ServiceUnavailableException("MongoDB unavailable")

    @classmethod
    async def disconnect(cls):
        if cls._client is not None:
            cls._client.close()
            log_info("MongoDB connection closed", extra={"db": settings.MONGO_DB})
            cls._client = None
            cls._db = None

    @classmethod
    def get_db(cls) -> AsyncIOMotorDatabase:
        if cls._db is None:
            log_error("Attempt to access MongoDB before connection was established")
            raise ServiceUnavailableException("MongoDB not connected. Call connect() first.")
        return cls._db


async def get_nosql_db() -> AsyncIOMotorDatabase:
    if MongoDBConnection._client is None:
        await MongoDBConnection.connect()
    return MongoDBConnection.get_db()


async def startup_db():
    await MongoDBConnection.connect()


async def shutdown_db():
    await MongoDBConnection.disconnect()