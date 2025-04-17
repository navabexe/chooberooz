# Path: src/shared/errors/response.py
from pydantic import BaseModel, Field

from src.shared.errors.base import BaseError
from src.shared.utilities.constants import ErrorType, DomainErrorCode, InfraErrorCode
from src.shared.utilities.types import ErrorDetails


class ErrorResponse(BaseModel):
    """Standard API error response model."""

    status: str = Field("error", description="Response status, always 'error'")
    error_code: str = Field(..., description="Unique error code")
    message: str = Field(..., description="User-friendly error message")
    details: ErrorDetails = Field(default_factory=dict, description="Additional error details")
    trace_id: str = Field(..., description="Trace ID for debugging")
    timestamp: str = Field(..., description="Error timestamp")
    error_type: ErrorType = Field(ErrorType.GENERAL, description="Type of error")

    @classmethod
    def from_error(cls, error: BaseError) -> "ErrorResponse":
        """Create response from BaseError instance."""
        return cls(
            status="error",
            error_code=error.error_code,
            message=error.message,
            details=error.details,
            trace_id=str(error.trace_id),
            timestamp=error.timestamp,
            error_type=cls._infer_error_type(error)
        )

    @staticmethod
    def _infer_error_type(error: BaseError) -> ErrorType:
        """Infer error type from error code."""
        domain_codes = {e.value for e in DomainErrorCode}
        infra_codes = {e.value for e in InfraErrorCode}

        if error.error_code in domain_codes:
            if "AUTH" in error.error_code:
                return ErrorType.AUTHENTICATION
            if "SERVICE" in error.error_code:
                return ErrorType.SERVICE
            return ErrorType.GENERAL
        elif error.error_code in infra_codes:
            if "DATABASE" in error.error_code or "MONGO" in error.error_code:
                return ErrorType.DATABASE
            return ErrorType.GENERAL
        return ErrorType.GENERAL