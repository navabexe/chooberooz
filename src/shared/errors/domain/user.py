# Path: src/shared/errors/domain/user.py
from ..base import BaseError
from ...utilities.constants import DomainErrorCode, HttpStatus
from ...utilities.helpers import generate_trace_id
from ...utilities.types import TraceId, ErrorDetails, LanguageCode


class UserNotFoundError(BaseError):
    """Error when a user is not found."""

    def __init__(
            self,
            user_id: str,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=DomainErrorCode.USER_NOT_FOUND.value,
            message=f"User with ID {user_id} not found.",
            status_code=HttpStatus.NOT_FOUND.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"user_id": user_id},
            language=language
        )


class InvalidCredentialsError(BaseError):
    """Error when login credentials are invalid."""

    def __init__(
            self,
            identifier: str,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
            message=f"Invalid credentials for {identifier}.",
            status_code=HttpStatus.UNAUTHORIZED.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"identifier": identifier},
            language=language
        )


class UserAlreadyExistsError(BaseError):
    """Error when trying to create an existing user."""

    def __init__(
            self,
            identifier: str,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=DomainErrorCode.USER_ALREADY_EXISTS.value,
            message=f"User with {identifier} already exists.",
            status_code=HttpStatus.CONFLICT.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"identifier": identifier},
            language=language
        )