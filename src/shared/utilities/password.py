# Path: src/infrastructure/security/password.py
from passlib.context import CryptContext
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig

# Initialize password hashing context
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12
)

logger = LoggingService(LogConfig())


def hash_password(password: str) -> str:
    """
    Hash a password for secure storage.

    Raises:
        ValueError: If password is empty or invalid.
        Exception: If hashing fails for other reasons.
    """
    if not password or not isinstance(password, str):
        logger.error("Invalid password input", context={"input_type": type(password)})
        raise ValueError("Password must be a non-empty string")

    try:
        return pwd_context.hash(password)
    except Exception as e:
        logger.error("Password hashing failed", context={"error": str(e)})
        raise Exception(f"Failed to hash password: {str(e)}")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plain password against a hashed password.

    Raises:
        ValueError: If inputs are empty or invalid.
        Exception: If verification fails for other reasons.
    """
    if not plain_password or not isinstance(plain_password, str):
        logger.error("Invalid plain password input", context={"input_type": type(plain_password)})
        raise ValueError("Plain password must be a non-empty string")
    if not hashed_password or not isinstance(hashed_password, str):
        logger.error("Invalid hashed password input", context={"input_type": type(hashed_password)})
        raise ValueError("Hashed password must be a non-empty string")

    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error("Password verification failed", context={"error": str(e)})
        raise Exception(f"Failed to verify password: {str(e)}")