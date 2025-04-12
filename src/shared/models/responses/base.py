from typing import Any, Optional, Literal

from pydantic import BaseModel, Field


class Meta(BaseModel):
    message: str = Field(..., description="Descriptive message for response.")
    status: Literal["success", "error"] = Field(..., examples=["success", "error"])
    code: int = Field(..., description="HTTP status code (e.g., 200, 400, 500)")


class StandardResponse(BaseModel):
    data: Optional[Any] = Field(None, description="Payload or result")
    meta: Meta = Field(..., description="Standard metadata with status, message, and code")

    @staticmethod
    def success(data: Any = None, message: str = "Success", code: int = 200):
        return StandardResponse(
            data=data,
            meta=Meta(
                message=message,
                status="success",
                code=code
            )
        )


class ErrorResponse(BaseModel):
    detail: str = Field(..., examples=["Invalid credentials."])
    message: Optional[str] = Field(default=None)
    error_code: Optional[str] = Field(None, examples=["AUTH_001"])
    status: Literal["error"] = "error"

    @staticmethod
    def from_exception(detail: str, message: Optional[str] = None, error_code: Optional[str] = None):
        return ErrorResponse(
            detail=detail,
            message=message or detail,
            error_code=error_code,
        )


class StandardLoginResponse(BaseModel):
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type, typically 'bearer'")
    expires_in: Optional[int] = Field(default=3600, description="Token expiration time in seconds")