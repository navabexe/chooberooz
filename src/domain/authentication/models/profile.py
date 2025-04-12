import re
from typing import Optional, List

from pydantic import BaseModel, Field, EmailStr, ConfigDict, field_validator

from src.shared.models.requests.base import BaseRequestModel


class Location(BaseModel):
    """Geographical location coordinates."""
    lat: float = Field(..., ge=-90, le=90, description="Latitude")
    lng: float = Field(..., ge=-180, le=180, description="Longitude")


class CompleteUserProfile(BaseRequestModel):
    """Request model for completing a user profile."""
    temporary_token: str = Field(..., min_length=1, description="Temporary token from verify-otp")
    first_name: str = Field(..., min_length=2, max_length=50, description="User's first name")
    last_name: str = Field(..., min_length=2, max_length=50, description="User's last name")
    email: EmailStr = Field(..., description="Valid email address")
    bio: Optional[str] = Field(default=None, max_length=500, description="User bio")
    avatar_urls: List[str] = Field(default_factory=list, description="List of avatar URLs")
    additional_phones: List[str] = Field(default_factory=list, description="Additional phone numbers")
    birthdate: Optional[str] = Field(default=None, description="ISO format date string (e.g., 1990-01-01)")
    gender: Optional[str] = Field(default=None, description="Gender (e.g., male, female, other)")
    languages: List[str] = Field(default_factory=list, description="Preferred languages")
    preferred_language: Optional[str] = Field(default="fa", description="Preferred language for messages")
    request_id: Optional[str] = Field(default=None, max_length=36, description="Request identifier for tracing")
    client_version: Optional[str] = Field(default=None, max_length=15, description="Version of the client app")
    device_fingerprint: Optional[str] = Field(default=None, max_length=100, description="Unique device fingerprint (optional)")

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid"
    )

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, v: Optional[str]) -> Optional[str]:
        if v and len(v) > 36:
            raise ValueError("Request identifier is too long.")
        return v

    @field_validator("client_version")
    @classmethod
    def validate_client_version(cls, v: Optional[str]) -> Optional[str]:
        if v and (len(v) > 15 or not re.match(r"^\d+\.\d+\.\d+$", v)):
            raise ValueError("Invalid client version format. Expected format: X.Y.Z.")
        return v


class CompleteVendorProfile(BaseRequestModel):
    """Request model for completing a vendor profile."""
    temporary_token: str = Field(..., description="Temporary token from verify-otp")
    business_name: Optional[str] = Field(default=None, min_length=3, max_length=100, description="Business name")
    first_name: Optional[str] = Field(default=None, min_length=2, max_length=50, description="Vendor's first name")
    last_name: Optional[str] = Field(default=None, min_length=2, max_length=50, description="Vendor's last name")
    city: Optional[str] = Field(default=None, min_length=2, max_length=50, description="City name")
    province: Optional[str] = Field(default=None, min_length=2, max_length=50, description="Province name")
    location: Optional[Location] = Field(default=None, description="Geographical coordinates")
    address: Optional[str] = Field(default=None, min_length=5, max_length=200, description="Full address")
    business_category_ids: Optional[List[str]] = Field(default_factory=list, description="Category IDs")
    visibility: Optional[str] = Field(default="COLLABORATIVE", description="Profile visibility status")
    vendor_type: Optional[str] = Field(default=None, description="Type of vendor")
    preferred_languages: List[str] = Field(default_factory=list, description="Preferred languages for the vendor profile")
    request_id: Optional[str] = Field(default=None, max_length=36, description="Request identifier for tracing")
    client_version: Optional[str] = Field(default=None, max_length=15, description="Version of the client app")
    device_fingerprint: Optional[str] = Field(default=None, max_length=100, description="Unique device fingerprint (optional)")

    model_config = ConfigDict(
        str_strip_whitespace=True,
        extra="forbid"
    )

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, v: Optional[str]) -> Optional[str]:
        if v and len(v) > 36:
            raise ValueError("Request identifier is too long.")
        return v

    @field_validator("client_version")
    @classmethod
    def validate_client_version(cls, v: Optional[str]) -> Optional[str]:
        if v and (len(v) > 15 or not re.match(r"^\d+\.\d+\.\d+$", v)):
            raise ValueError("Invalid client version format. Expected format: X.Y.Z.")
        return v