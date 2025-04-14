from dependency_injector import containers, providers
from redis.asyncio import Redis
from motor.motor_asyncio import AsyncIOMotorClient

from src.shared.config.settings import settings

from src.infrastructure.storage.cache.repositories.otp_repository import OTPRepository
from src.infrastructure.storage.nosql.repositories.user_repository import UserRepository

from src.domain.notification.services.notification_service import NotificationService
from src.domain.authentication.services.session_service import SessionService
from src.domain.authentication.services.otp_service import OTPService
from src.domain.authentication.services.complete_profile_service import CompleteProfileService


class Container(containers.DeclarativeContainer):
    """Dependency Injection container for managing application dependencies."""
    config = providers.Configuration()

    # Redis client
    redis = providers.Singleton(
        Redis,
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        password=settings.REDIS_PASSWORD,
        ssl=settings.REDIS_USE_SSL,
        ssl_ca_certs=settings.REDIS_SSL_CA_CERTS if settings.REDIS_SSL_CA_CERTS else None,
        ssl_certfile=settings.REDIS_SSL_CERT if settings.REDIS_SSL_CERT else None,
        ssl_keyfile=settings.REDIS_SSL_KEY if settings.REDIS_SSL_KEY else None,
    )

    # MongoDB client
    mongo_client = providers.Singleton(AsyncIOMotorClient, settings.MONGO_URI)

    # MongoDB database
    mongo_db = providers.Singleton(
        lambda client: client[settings.MONGO_DB],
        client=mongo_client
    )

    # Repositories
    otp_repo = providers.Factory(OTPRepository, redis=redis)
    user_repo = providers.Factory(UserRepository, db=mongo_db)

    # Services
    notification_service = providers.Singleton(NotificationService)
    session_service = providers.Singleton(SessionService)

    otp_service = providers.Factory(
        OTPService,
        otp_repo=otp_repo,
        user_repo=user_repo,
        notification_service=notification_service,
        session_service=session_service
    )

    complete_profile_service = providers.Factory(
        CompleteProfileService,
        user_repo=user_repo,
        otp_repo=otp_repo,
        notification_service=notification_service,
        session_service=session_service
    )


# Create the container instance
container = Container(config=settings)