from typing import Optional, Literal

from pydantic import BaseModel, Field, ConfigDict


class BaseRequestModel(BaseModel):
    """Base model for all API request bodies. Includes shared metadata like language and tracking fields."""
    response_language: Literal["fa", "en"] = Field(
        default="fa",
        description="Language for response messages (e.g., 'fa' for Farsi, 'en' for English)"
    )
    request_id: Optional[str] = Field(
        default=None,
        description="Optional request ID for traceability and debugging"
    )
    client_version: Optional[str] = Field(
        default=None,
        description="Optional client version string (e.g., 'v1.2.3')"
    )

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True
    )