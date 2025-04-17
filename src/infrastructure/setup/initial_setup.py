# Path: src/infrastructure/setup/initial_setup.py
from datetime import datetime, timezone
from src.infrastructure.storage.nosql.repositories.base import MongoRepository
from src.shared.config.settings import settings
from src.shared.utilities.password import hash_password
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.errors.base import BaseError
from src.shared.utilities.constants import HttpStatus
from src.shared.utilities.time import utc_now

logger = LoggingService(LogConfig())


async def setup_admin_and_categories(admins_repo: MongoRepository, categories_repo: MongoRepository):
    """
    Set up initial admin user and business categories in the database.

    Args:
        admins_repo: MongoDB repository for admins collection.
        categories_repo: MongoDB repository for categories collection.

    Raises:
        BaseError: If admin credentials are invalid or missing.
    """
    # Fetch admin credentials from settings
    admin_username = settings.ADMIN_USERNAME
    admin_password = settings.ADMIN_PASSWORD

    # Validate admin credentials
    if not admin_username:
        raise BaseError(
            error_code="MISSING_ADMIN_USERNAME",
            message="ADMIN_USERNAME must be set in .env",
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={},
            language="en"
        )
    if not admin_password:
        raise BaseError(
            error_code="MISSING_ADMIN_PASSWORD",
            message="ADMIN_PASSWORD must be set in .env for security in production",
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={},
            language="en"
        )
    if len(admin_password) < 8:
        raise BaseError(
            error_code="INVALID_ADMIN_PASSWORD",
            message="ADMIN_PASSWORD must be at least 8 characters long",
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={},
            language="en"
        )

    hashed_password = hash_password(admin_password)

    # Check if admin exists, create if not
    admin = await admins_repo.find_one({"username": admin_username})
    if not admin:
        admin_data = {
            "username": admin_username,
            "password": hashed_password,
            "role": "admin",
            "status": "active",
            "created_at": datetime.now(timezone.utc),
            "updated_at": utc_now(),
        }
        admin_id = await admins_repo.insert_one(admin_data)
        logger.info("Admin user created", context={"admin_id": str(admin_id)})

    # Default business categories
    default_categories = [
        {"name": "Furniture", "description": "Furniture and home decor", "created_at": datetime.now(timezone.utc)},
        {"name": "Electronics", "description": "Electronic gadgets and appliances",
         "created_at": datetime.now(timezone.utc)},
        {"name": "Clothing", "description": "Clothing and fashion items", "created_at": datetime.now(timezone.utc)}
    ]

    # Insert categories if they don't exist
    for category in default_categories:
        if not await categories_repo.find_one({"name": category["name"]}):
            category_id = await categories_repo.insert_one(category)
            logger.info("Business category created", context={"category_id": str(category_id)})