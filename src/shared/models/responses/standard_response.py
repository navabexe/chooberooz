from typing import Optional, Dict, Any, Literal
from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    """Standard response model for errors in the API."""

    detail: str = Field(
        ...,
        description="Detailed error message for developers and logs, often technical.",
        examples=["The OTP code has expired for phone +989123456789."]
    )
    message: Optional[str] = Field(
        None,
        description="User-friendly error message for clients, suitable for UI display.",
        examples=["The code you entered has expired."]
    )
    error_code: Optional[str] = Field(
        None,
        description="Unique error code for identifying the error type.",
        examples=["OTP_EXPIRED", "BAD_REQUEST"]
    )
    status: Literal["error"] = Field(
        "error",
        description="Status of the response, always 'error' for error responses."
    )
    metadata: Optional[Dict[str, Any]] = Field(
        None,
        description="Additional error information, such as remaining attempts.",
        examples=[{"remaining_attempts": 4}]
    )

    @classmethod
    def from_exception(
            cls,
            detail: str,
            message: Optional[str] = None,
            error_code: Optional[str] = None,
            metadata: Optional[Dict[str, Any]] = None
    ) -> "ErrorResponse":
        """
        Create an ErrorResponse from exception details.

        Args:
            detail: Technical error description.
            message: User-friendly error message (optional, defaults to detail).
            error_code: Unique error code (optional).
            metadata: Additional error information (optional).

        Returns:
            ErrorResponse instance.
        """
        return cls(
            detail=detail,
            message=message or detail,
            error_code=error_code,
            metadata=metadata
        )