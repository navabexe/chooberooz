# path: src/domain/authentication/models/complete_profile.py
from typing import Optional, Literal, List
from pydantic import BaseModel, Field, ConfigDict, EmailStr, field_validator
from pydantic_core.core_schema import ValidationInfo

from src.shared.config.settings import settings
from src.shared.models.requests.base import BaseRequestModel
from src.shared.i18n.messages import get_message

class CompleteUserProfileInput(BaseRequestModel):
    temporary_token: str = Field(..., description="Temporary token from verify-otp")
    first_name: str = Field(..., min_length=2, max_length=30, description="User's first name")
    last_name: str = Field(..., min_length=2, max_length=30, description="User's last name")
    email: Optional[EmailStr] = Field(default=None, description="User's email address")
    preferred_languages: Optional[List[str]] = Field(
        default_factory=list, description="Preferred languages for the user profile"
    )
    request_id: Optional[str] = Field(default=None, max_length=36, description="Request identifier for tracing")
    client_version: Optional[str] = Field(default=None, max_length=50, description="Version of the client app")
    device_fingerprint: Optional[str] = Field(default=None, max_length=100, description="Device fingerprint")

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    @field_validator("preferred_languages")
    @classmethod
    def validate_languages(cls, v: List[str], info: ValidationInfo) -> List[str]:
        lang = info.data.get("response_language", settings.DEFAULT_LANGUAGE)
        allowed = settings.SUPPORTED_LANGUAGES.split(",")
        invalid = [l for l in v if l not in allowed]
        if invalid:
            raise ValueError(get_message("invalid.language", lang=lang, variables={"allowed": ", ".join(allowed)}))
        return v

class CompleteVendorProfileInput(BaseRequestModel):
    temporary_token: str = Field(..., description="Temporary token from verify-otp")
    first_name: Optional[str] = Field(default=None, min_length=2, max_length=30, description="Vendor's first name")
    last_name: Optional[str] = Field(default=None, min_length=2, max_length=30, description="Vendor's last name")
    business_name: str = Field(..., min_length=2, max_length=100, description="Business name")
    city: Optional[str] = Field(default=None, min_length=2, max_length=50, description="City")
    province: Optional[str] = Field(default=None, min_length=2, max_length=50, description="Province")
    location: Optional[dict] = Field(default=None, description="Geographical location coordinates")
    address: Optional[str] = Field(default=None, max_length=200, description="Business address")
    business_category_ids: Optional[List[str]] = Field(
        default_factory=list, description="List of business category IDs"
    )
    visibility: Optional[Literal["COLLABORATIVE", "PUBLIC", "PRIVATE", "TEMPORARILY_CLOSED"]] = Field(
        default="COLLABORATIVE", description="Vendor profile visibility"
    )
    vendor_type: Optional[str] = Field(default=None, description="Type of vendor")
    preferred_languages: Optional[List[str]] = Field(
        default_factory=list, description="Preferred languages for the vendor profile"
    )
    request_id: Optional[str] = Field(default=None, max_length=36, description="Request identifier for tracing")
    client_version: Optional[str] = Field(default=None, max_length=50, description="Version of the client app")
    device_fingerprint: Optional[str] = Field(default=None, max_length=100, description="Device fingerprint")

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    @field_validator("preferred_languages")
    @classmethod
    def validate_languages(cls, v: List[str], info: ValidationInfo) -> List[str]:
        lang = info.data.get("response_language", settings.DEFAULT_LANGUAGE)
        allowed = settings.SUPPORTED_LANGUAGES.split(",")
        invalid = [l for l in v if l not in allowed]
        if invalid:
            raise ValueError(get_message("invalid.language", lang=lang, variables={"allowed": ", ".join(allowed)}))
        return v

    @field_validator("business_category_ids")
    @classmethod
    def validate_category_ids(cls, v: List[str], info: ValidationInfo) -> List[str]:
        lang = info.data.get("response_language", settings.DEFAULT_LANGUAGE)
        for cid in v:
            if not cid.isalnum():
                raise ValueError(get_message("invalid.business_category_id", lang=lang))
        return v