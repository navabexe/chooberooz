# Path: src/shared/errors/domain/security.py
from ..base import BaseError
from ...utilities.constants import DomainErrorCode, HttpStatus
from ...utilities.helpers import generate_trace_id
from ...utilities.types import TraceId, ErrorDetails, LanguageCode


class UnauthorizedAccessError(BaseError):
    """Error when access is unauthorized."""

    def __init__(
            self,
            resource: str,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=DomainErrorCode.UNAUTHORIZED_ACCESS.value,
            message=f"Unauthorized access to {resource}.",
            status_code=HttpStatus.UNAUTHORIZED.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"resource": resource},
            language=language
        )


class RateLimitExceededError(BaseError):
    """Error when rate limit is exceeded."""

    def __init__(
            self,
            endpoint: str,
            limit: int,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=DomainErrorCode.RATE_LIMIT_EXCEEDED.value,
            message=f"Rate limit exceeded for {endpoint}.",
            status_code=HttpStatus.TOO_MANY_REQUESTS.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"endpoint": endpoint, "limit": limit},
            language=language
        )


class SuspiciousActivityError(BaseError):
    """Error when suspicious activity is detected."""

    def __init__(
            self,
            user_id: str,
            activity: str,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=DomainErrorCode.SUSPICIOUS_ACTIVITY.value,
            message=f"Suspicious activity detected for user {user_id}.",
            status_code=HttpStatus.FORBIDDEN.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"user_id": user_id, "activity": activity},
            language=language
        )


class InvalidTokenError(BaseError):
    """Error when token processing fails."""

    def __init__(
            self,
            error_code: str,
            message: str,
            status_code: int,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=error_code,
            message=message,
            status_code=status_code,
            trace_id=trace_id or generate_trace_id(),
            details=details or {},
            language=language
        )


class InvalidCredentialsError(BaseError):
    """Error when provided credentials are invalid."""

    def __init__(
            self,
            error_code: str,
            message: str,
            status_code: int,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=error_code,
            message=message,
            status_code=status_code,
            trace_id=trace_id or generate_trace_id(),
            details=details or {},
            language=language
        )