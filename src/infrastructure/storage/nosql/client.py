# Path: src/infrastructure/storage/nosql/mongodb.py
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from src.shared.config.settings import settings
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.errors.infrastructure.database import DatabaseConnectionError
from src.shared.utilities.constants import HttpStatus, InfraErrorCode

logger = LoggingService(LogConfig())

class MongoDBConnection:
    _client: AsyncIOMotorClient = None
    _db: AsyncIOMotorDatabase = None

    @classmethod
    async def connect(cls):
        """Connect to MongoDB."""
        if cls._client is None:
            try:
                mongo_uri = settings.MONGO_URI or "mongodb://localhost:27017"
                timeout = getattr(settings, "MONGO_TIMEOUT", 20000)

                logger.info("Attempting MongoDB connection", context={"uri": mongo_uri, "timeout": timeout})

                cls._client = AsyncIOMotorClient(
                    mongo_uri,
                    serverSelectionTimeoutMS=timeout
                )
                cls._db = cls._client[settings.MONGO_DB]
                await cls._client.admin.command("ping")

                logger.info("MongoDB connection established", context={
                    "db": settings.MONGO_DB,
                    "uri": mongo_uri
                })

            except Exception as e:
                logger.error("MongoDB connection failed", context={
                    "uri": mongo_uri,
                    "timeout": timeout,
                    "error": str(e)
                })
                raise DatabaseConnectionError(
                    db_type="MongoDB",
                    error_code=InfraErrorCode.DATABASE_CONNECTION.value,
                    message="MongoDB unavailable",
                    status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
                    trace_id=logger.tracer.get_trace_id(),
                    details={"error": str(e)},
                    language="en"
                )

    @classmethod
    async def disconnect(cls):
        """Disconnect from MongoDB."""
        if cls._client is not None:
            cls._client.close()
            logger.info("MongoDB connection closed", context={"db": settings.MONGO_DB})
            cls._client = None
            cls._db = None

    @classmethod
    def get_db(cls) -> AsyncIOMotorDatabase:
        """Get MongoDB database instance."""
        if cls._db is None:
            logger.error("Attempt to access MongoDB before connection was established", context={})
            raise DatabaseConnectionError(
                db_type="MongoDB",
                error_code=InfraErrorCode.DATABASE_CONNECTION.value,
                message="MongoDB not connected. Call connect() first.",
                status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
                trace_id=logger.tracer.get_trace_id(),
                details={},
                language="en"
            )
        return cls._db

async def get_nosql_db() -> AsyncIOMotorDatabase:
    """Dependency to get MongoDB database."""
    if MongoDBConnection._client is None:
        await MongoDBConnection.connect()
    return MongoDBConnection.get_db()

async def startup_db():
    """Startup MongoDB connection."""
    await MongoDBConnection.connect()

async def shutdown_db():
    """Shutdown MongoDB connection."""
    await MongoDBConnection.disconnect()