from typing import Optional, Dict, Any, Literal
from fastapi import HTTPException, status

from src.shared.i18n.messages import get_message


class AppHTTPException(HTTPException):
    """Base class for custom HTTP exceptions with support for localized messages and error codes."""

    def __init__(
            self,
            status_code: int,
            detail: str,
            message: Optional[str] = None,
            error_code: Optional[str] = None,
            language: Literal["fa", "en"] = "en",
            metadata: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the exception with detailed error information.

        Args:
            status_code: HTTP status code (e.g., 400, 429).
            detail: Technical error description for developers/logs.
            message: User-friendly message for clients (optional, defaults to detail).
            error_code: Unique error code for the client (e.g., "BAD_REQUEST").
            language: Language for localized messages ("fa" or "en").
            metadata: Additional error information (e.g., remaining attempts).
        """
        self.error_code = error_code or self.__class__.__name__.replace("Exception", "").upper()
        self.metadata = metadata or {}
        self.language = language
        # Use provided message or fallback to detail
        self.message = message or detail
        super().__init__(status_code=status_code, detail=detail)

    def __str__(self) -> str:
        """Return the detail string without status code prefix."""
        return self.detail


class TooManyRequestsException(AppHTTPException):
    """Exception for rate limit exceeded errors."""

    def __init__(
            self,
            detail: str = None,
            message: Optional[str] = None,
            error_code: Optional[str] = "TOO_MANY_REQUESTS",
            language: Literal["fa", "en"] = "en",
            metadata: Optional[Dict[str, Any]] = None
    ):
        detail = detail or get_message("otp.too_many.blocked", language)
        message = message or get_message("otp.too_many.blocked", language)
        super().__init__(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=detail,
            message=message,
            error_code=error_code,
            language=language,
            metadata=metadata
        )


class UnauthorizedException(AppHTTPException):
    """Exception for unauthorized access attempts."""

    def __init__(
            self,
            detail: str = None,
            message: Optional[str] = None,
            error_code: Optional[str] = "UNAUTHORIZED",
            language: Literal["fa", "en"] = "en",
            metadata: Optional[Dict[str, Any]] = None
    ):
        detail = detail or get_message("auth.login.invalid", language)
        message = message or get_message("auth.login.invalid", language)
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=detail,
            message=message,
            error_code=error_code,
            language=language,
            metadata=metadata
        )


class ForbiddenException(AppHTTPException):
    """Exception for forbidden actions."""

    def __init__(
            self,
            detail: str = None,
            message: Optional[str] = None,
            error_code: Optional[str] = "FORBIDDEN",
            language: Literal["fa", "en"] = "en",
            metadata: Optional[Dict[str, Any]] = None
    ):
        detail = detail or get_message("auth.forbidden", language)
        message = message or get_message("auth.forbidden", language)
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=detail,
            message=message,
            error_code=error_code,
            language=language,
            metadata=metadata
        )


class NotFoundException(AppHTTPException):
    """Exception for resources that cannot be found."""

    def __init__(
            self,
            detail: str = None,
            message: Optional[str] = None,
            error_code: Optional[str] = "NOT_FOUND",
            language: Literal["fa", "en"] = "en",
            metadata: Optional[Dict[str, Any]] = None
    ):
        detail = detail or get_message("user.not_found", language)
        message = message or get_message("user.not_found", language)
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail,
            message=message,
            error_code=error_code,
            language=language,
            metadata=metadata
        )


class BadRequestException(AppHTTPException):
    """Exception for invalid request parameters or inputs."""

    def __init__(
            self,
            detail: str = None,
            message: Optional[str] = None,
            error_code: Optional[str] = "BAD_REQUEST",
            language: Literal["fa", "en"] = "en",
            metadata: Optional[Dict[str, Any]] = None
    ):
        detail = detail or get_message("server.error", language)
        message = message or get_message("server.error", language)
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail,
            message=message,
            error_code=error_code,
            language=language,
            metadata=metadata
        )


class ConflictException(AppHTTPException):
    """Exception for resource conflicts."""

    def __init__(
            self,
            detail: str = None,
            message: Optional[str] = None,
            error_code: Optional[str] = "CONFLICT",
            language: Literal["fa", "en"] = "en",
            metadata: Optional[Dict[str, Any]] = None
    ):
        detail = detail or get_message("server.error", language)
        message = message or get_message("server.error", language)
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            detail=detail,
            message=message,
            error_code=error_code,
            language=language,
            metadata=metadata
        )


class InternalServerErrorException(AppHTTPException):
    """Exception for unexpected server errors."""

    def __init__(
            self,
            detail: str = None,
            message: Optional[str] = None,
            error_code: Optional[str] = "INTERNAL_SERVER_ERROR",
            language: Literal["fa", "en"] = "en",
            metadata: Optional[Dict[str, Any]] = None
    ):
        detail = detail or get_message("server.error", language)
        message = message or get_message("server.error", language)
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=detail,
            message=message,
            error_code=error_code,
            language=language,
            metadata=metadata
        )


class ServiceUnavailableException(AppHTTPException):
    """Exception for temporary service unavailability."""

    def __init__(
            self,
            detail: str = None,
            message: Optional[str] = None,
            error_code: Optional[str] = "SERVICE_UNAVAILABLE",
            language: Literal["fa", "en"] = "en",
            metadata: Optional[Dict[str, Any]] = None
    ):
        detail = detail or get_message("server.error", language)
        message = message or get_message("server.error", language)
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=detail,
            message=message,
            error_code=error_code,
            language=language,
            metadata=metadata
        )


class DatabaseConnectionException(AppHTTPException):
    """Exception for database connection failures."""

    def __init__(
            self,
            db_type: str,
            detail: str = None,
            message: Optional[str] = None,
            error_code: Optional[str] = "DATABASE_CONNECTION_FAILED",
            language: Literal["fa", "en"] = "en",
            metadata: Optional[Dict[str, Any]] = None
    ):
        detail = detail or get_message("server.error", language)
        message = message or get_message("server.error", language)
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"{db_type}: {detail}",
            message=message,
            error_code=error_code,
            language=language,
            metadata=metadata
        )


CUSTOM_HTTP_EXCEPTIONS = [
    TooManyRequestsException,
    UnauthorizedException,
    ForbiddenException,
    NotFoundException,
    BadRequestException,
    ConflictException,
    InternalServerErrorException,
    ServiceUnavailableException,
    DatabaseConnectionException,
]