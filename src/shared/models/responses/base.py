from typing import Optional, Dict, Any, Literal
from pydantic import BaseModel, Field


class Meta(BaseModel):
    message: str = Field(..., description="Descriptive message for response")
    status: Literal["success", "error"] = Field(..., examples=["success", "error"])
    code: int = Field(..., description="HTTP status code")


class StandardResponse(BaseModel):
    data: Optional[Any] = Field(None, description="Payload or result")
    meta: Meta = Field(..., description="Standard metadata with status, message, and code")

    @classmethod
    def success(
        cls,
        data: Optional[Any] = None,
        message: str = "Success",
        code: int = 200
    ) -> "StandardResponse":
        return cls(
            data=data,
            meta=Meta(
                message=message,
                status="success",
                code=code
            )
        )


class ErrorResponse(BaseModel):
    detail: str = Field(..., description="Detailed error message for developers and logs")
    message: Optional[str] = Field(None, description="User-friendly error message for clients")
    error_code: Optional[str] = Field(None, description="Unique error code for identifying the error type")
    status: Literal["error"] = Field("error", description="Status of the response, always 'error'")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional error information")

    @classmethod
    def from_exception(
        cls,
        detail: str,
        message: Optional[str] = None,
        error_code: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> "ErrorResponse":
        return cls(
            detail=detail,
            message=message or detail,
            error_code=error_code,
            metadata=metadata
        )
