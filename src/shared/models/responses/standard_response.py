from pydantic import BaseModel, Field


class ErrorResponse(BaseModel):
    """Standard response model for errors."""
    detail: str = Field(..., description="Detailed error message")
    message: str = Field(..., description="User-friendly error message")
    status: str = Field(..., description="Status of the response, typically 'error'")