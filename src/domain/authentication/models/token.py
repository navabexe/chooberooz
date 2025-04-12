from typing import Optional, List

from pydantic import BaseModel, Field, ConfigDict

from src.domain.authentication.models.profile import Location


class UserJWTProfile(BaseModel):
    """Profile data embedded in JWT for users."""
    first_name: Optional[str] = Field(default=None, max_length=50)
    last_name: Optional[str] = Field(default=None, max_length=50)
    email: Optional[str] = Field(default=None)
    phone: Optional[str] = Field(default=None)
    bio: Optional[str] = Field(default=None, max_length=500)
    avatar_urls: List[str] = Field(default_factory=list)
    additional_phones: List[str] = Field(default_factory=list)
    birthdate: Optional[str] = Field(default=None, description="ISO format date string")
    gender: Optional[str] = Field(default=None)
    preferred_languages: List[str] = Field(default_factory=list, description="List of preferred languages")
    status: Optional[str] = Field(default=None)


class VendorJWTProfile(BaseModel):
    """Profile data embedded in JWT for vendors."""
    first_name: Optional[str] = Field(default=None, max_length=50)
    last_name: Optional[str] = Field(default=None, max_length=50)
    phone: Optional[str] = Field(default=None)
    address: Optional[str] = Field(default=None, max_length=200)
    location: Optional[Location] = Field(default=None)
    city: Optional[str] = Field(default=None, max_length=50)
    province: Optional[str] = Field(default=None, max_length=50)
    logo_urls: List[str] = Field(default_factory=list)
    banner_urls: List[str] = Field(default_factory=list)
    visibility: Optional[str] = Field(default=None)
    status: Optional[str] = Field(default=None)
    business_category_ids: List[str] = Field(default_factory=list)
    preferred_languages: List[str] = Field(default_factory=list, description="List of preferred languages")
    vendor_type: Optional[str] = Field(default=None)
    account_types: List[str] = Field(default_factory=list)
    show_followers_publicly: bool = Field(default=True)
    profile_picture: Optional[str] = Field(default=None)


class TokenPayload(BaseModel):
    """JWT token payload structure."""
    sub: str = Field(..., description="Subject identifier (user ID or phone)")
    role: str = Field(..., description="User role (e.g., user, vendor, admin)")
    scopes: List[str] = Field(default_factory=list, description="Access scopes")
    status: Optional[str] = Field(default=None, description="Account status")
    vendor_id: Optional[str] = Field(default=None, description="Vendor identifier")
    active_role: Optional[str] = Field(default=None, description="Currently active role")
    phone_verified: Optional[bool] = Field(default=None, description="Phone verification status")
    account_verified: Optional[bool] = Field(default=None, description="Account verification status")
    jti: str = Field(..., description="JWT identifier")
    iat: Optional[int] = Field(default=None, description="Issued-at timestamp")
    exp: int = Field(..., description="Expiration timestamp")
    session_id: Optional[str] = Field(default=None, description="Session identifier")
    preferred_language: Optional[str] = Field(default="fa", description="Preferred language from profile")
    user_profile: Optional[UserJWTProfile] = Field(default=None)
    vendor_profile: Optional[VendorJWTProfile] = Field(default=None)

    model_config = ConfigDict(
        validate_by_name=True
    )