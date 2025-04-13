from pathlib import Path
from typing import List, Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

# Calculate base directory for consistent file paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
ENV_PATH = BASE_DIR / ".env"

class Settings(BaseSettings):
    """Application configuration loaded from environment variables."""
    ENVIRONMENT: str = Field(default="development", description="Application environment")
    BASE_DIR: Path = Field(default=BASE_DIR, description="Base directory of the project")

    # Security keys
    SECRET_KEY: str = Field(..., description="Primary secret key for signing")
    ACCESS_SECRET: str = Field(..., description="Secret for access tokens")
    REFRESH_SECRET: str = Field(..., description="Secret for refresh tokens")
    SMS_PANEL_KEY: str = Field(..., description="API key for SMS provider")
    OTP_SALT: str = Field(..., description="Salt value used for hashing OTP codes")

    # Token expiration & algorithms
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(60, description="Access token expiry in minutes")
    ALGORITHM: str = Field("HS256", description="JWT signing algorithm")
    TEMP_TOKEN_TTL: int = Field(300, description="Temporary token TTL in seconds")
    ACCESS_TTL: int = Field(900, description="Access token TTL in seconds")
    REFRESH_TTL: int = Field(86400, description="Refresh token TTL in seconds")
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(30, description="Refresh token expiry in days")
    TEMP_TOKEN_EXPIRY: int = Field(86400, description="Temporary token expiry time in seconds")
    TEMP_TOKEN_EXPIRE_MINUTES: int = Field(300, description="Temporary token expiry in minutes")
    OTP_EXPIRY: int = Field(300, description="OTP expiry time in seconds")
    BLOCK_DURATION: int = Field(3600, description="General block duration in seconds")
    MAX_OTP_ATTEMPTS: int = Field(5, description="Maximum OTP attempts allowed")
    BLOCK_DURATION_OTP: int = Field(600, description="OTP block duration in seconds")
    SESSION_EXPIRY: int = Field(86400, description="Session expiry time in seconds")
    MAX_OTP_EXPIRED_ATTEMPTS: int = Field(5, description="Maximum attempts for expired OTP")
    MAX_TOKEN_EXPIRED_ATTEMPTS: int = Field(5, description="Maximum attempts for expired token")
    OTP_ATTEMPT_EXPIRY: int = Field(3600, description="Expiry time for OTP attempt keys in seconds")

    # MongoDB
    MONGO_URI: str = Field("mongodb://localhost:27017", description="MongoDB connection URI")
    MONGO_DB: str = Field("senama_db", description="MongoDB database name")
    MONGO_TIMEOUT: int = Field(5000, description="MongoDB connection timeout in milliseconds")

    # SMS
    MOCK_SMS: bool = Field(True, description="Mock SMS sending for testing")

    # Admin credentials
    ADMIN_USERNAME: str = Field(..., description="Admin username")
    ADMIN_PASSWORD: str = Field(..., description="Admin password")

    # Redis
    REDIS_HOST: str = Field("localhost", description="Redis host")
    REDIS_PORT: int = Field(6379, description="Redis port")
    REDIS_DB: int = Field(0, description="Redis database number")
    REDIS_PASSWORD: Optional[str] = Field(None, description="Redis password")
    REDIS_SSL_CA_CERTS: str = Field("", description="Path to Redis SSL CA certificate")
    REDIS_SSL_CERT: str = Field("", description="Path to Redis SSL certificate")
    REDIS_SSL_KEY: str = Field("", description="Path to Redis SSL key")
    REDIS_USE_SSL: bool = Field(False, description="Use SSL for Redis connection")

    # SSL
    SSL_CERT_FILE: str = Field("", description="Path to HTTPS certificate file")
    SSL_KEY_FILE: str = Field("", description="Path to HTTPS key file")

    # IP info
    IPINFO_TOKEN: str = Field(..., description="API token for ipinfo.io to fetch geolocation data")

    # Sentry settings
    SENTRY_DSN: str = Field(
        "https://8f51433419338619b6bf8aae83aca361@o4509130626301952.ingest.de.sentry.io/4509130899914832",
        description="Sentry DSN for error tracking"
    )
    SENTRY_TRACES_SAMPLE_RATE: float = Field(1.0, description="Sample rate for performance tracing (0.0 to 1.0)")
    SENTRY_SEND_PII: bool = Field(True, description="Send personally identifiable information to Sentry")

    # API Routes and Tags
    AUTH_TAG: str = Field("Authentication", description="Tag for authentication endpoints")
    REQUEST_OTP_PATH: str = Field("/api/v1/request-otp", description="Path for request OTP endpoint")
    VERIFY_OTP_PATH: str = Field("/api/v1/verify-otp", description="Path for verify OTP endpoint")
    APPROVE_VENDOR_PATH: str = Field("/approve-vendor", description="Path for approve vendor endpoint")
    ADMIN_TAG: str = Field("Admin", description="Tag for admin endpoints")
    VENDOR_APPROVAL_RATE_LIMIT: int = Field(10, description="Max vendor approval attempts per hour")
    COMPLETE_VENDOR_PROFILE_PATH: str = Field("/complete-vendor-profile", description="Path for complete vendor profile endpoint")
    COMPLETE_USER_PROFILE_PATH: str = Field("/complete-user-profile", description="Path for complete user profile endpoint")
    PROFILE_COMPLETE_RATE_LIMIT: int = Field(5, description="Max profile completion attempts per hour")
    VALID_VISIBILITY: List[str] = Field(["COLLABORATIVE", "PUBLIC", "PRIVATE", "TEMPORARILY_CLOSED"], description="Valid visibility options for vendors")
    VALID_VENDOR_TYPES: List[str] = Field(["BASIC", "PRO"], description="Valid vendor types")

    CORS_ORIGINS: str = Field("http://localhost:3000", description="Comma-separated list of allowed CORS origins")

    # Language settings
    DEFAULT_LANGUAGE: str = Field("fa", description="Default language for responses")
    SUPPORTED_LANGUAGES: str = Field("fa,en,ar", description="Comma-separated list of supported languages")

    model_config = SettingsConfigDict(
        env_file=ENV_PATH,
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="allow"  # Allow extra fields to avoid Pydantic errors
    )

settings = Settings()