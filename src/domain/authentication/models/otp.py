# path: src/domain/authentication/models/otp.py
import re
from datetime import datetime, timezone
from typing import Optional, Literal
from pydantic import BaseModel, Field, ConfigDict, field_validator, model_validator
from pydantic_core.core_schema import ValidationInfo

from src.shared.utilities.validators import validate_and_format_phone
from src.shared.config.settings import settings
from src.shared.i18n.messages import get_message

class RequestOTPInput(BaseModel):
    phone: str = Field(..., min_length=10, max_length=15, description="Phone number in international format (e.g., +989123456789)")
    role: Literal["user", "vendor"] = Field(..., description="Role requesting OTP")
    purpose: Literal["login", "signup", "password_reset"] = Field(default="login", description="Purpose of the OTP")
    response_language: str = Field(default=settings.DEFAULT_LANGUAGE, description="Preferred response language")
    request_id: Optional[str] = Field(default=None, max_length=36, description="Request identifier for tracing")
    client_version: Optional[str] = Field(default=None, max_length=50, description="Version of the client app")
    device_fingerprint: Optional[str] = Field(default=None, max_length=100, description="Unique device fingerprint (optional)")

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, v: str, info: ValidationInfo) -> str:
        lang = info.data.get("response_language", settings.DEFAULT_LANGUAGE)
        try:
            return validate_and_format_phone(v)
        except ValueError:
            raise ValueError(get_message("invalid.phone", lang=lang))

    @field_validator("response_language")
    @classmethod
    def validate_language(cls, v: str) -> str:
        allowed = settings.SUPPORTED_LANGUAGES.split(",")
        if v not in allowed:
            raise ValueError(get_message("invalid.language", lang=settings.DEFAULT_LANGUAGE, variables={"allowed": ", ".join(allowed)}))
        return v

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, v: Optional[str], info: ValidationInfo) -> Optional[str]:
        lang = info.data.get("response_language", settings.DEFAULT_LANGUAGE)
        if v and len(v) > 36:
            raise ValueError(get_message("invalid.request_id", lang=lang))
        return v

    @field_validator("client_version")
    @classmethod
    def validate_client_version(cls, v: Optional[str], info: ValidationInfo) -> Optional[str]:
        lang = info.data.get("response_language", settings.DEFAULT_LANGUAGE)
        if v and (len(v) > 50 or not re.match(r"^[a-zA-Z0-9_.+-]+(\.[a-zA-Z0-9_.+-]+)*$", v)):
            raise ValueError(get_message("invalid.client_version", lang=lang))
        return v

    @field_validator("device_fingerprint")
    @classmethod
    def validate_device_fingerprint(cls, v: Optional[str], info: ValidationInfo) -> Optional[str]:
        lang = info.data.get("response_language", settings.DEFAULT_LANGUAGE)
        if v and not re.match(r"^[a-zA-Z0-9\-_]{1,100}$", v):
            raise ValueError(get_message("invalid.device_fingerprint", lang=lang))
        return v

    @model_validator(mode="after")
    def validate_model(self) -> "RequestOTPInput":
        if self.purpose not in ["login", "signup", "password_reset"]:
            raise ValueError(get_message("server.error", lang=self.response_language))
        return self

class OTP(BaseModel):
    phone: str = Field(..., max_length=15, description="Phone number associated with the OTP")
    code: str = Field(..., min_length=4, max_length=10, description="Generated OTP code")
    purpose: str = Field(default="login", description="Purpose of the OTP (e.g., login, signup)")
    attempts: int = Field(default=0, ge=0, description="Number of verification attempts")
    channel: Optional[str] = Field(default="sms", description="Delivery channel (e.g., sms, email)")
    ip_address: Optional[str] = Field(default=None, description="IP address of the request")
    device_fingerprint: Optional[str] = Field(default=None, max_length=100, description="Device fingerprint for security")
    expires_at: datetime = Field(..., description="Expiration time of the OTP")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Creation time of the OTP")

    model_config = ConfigDict(json_encoders={datetime: lambda v: v.isoformat()})

    @field_validator("code")
    @classmethod
    def validate_code(cls, v: str, info: ValidationInfo) -> str:
        lang = info.data.get("response_language", settings.DEFAULT_LANGUAGE)
        if not v.isdigit():
            raise ValueError(get_message("invalid.otp_code", lang=lang))
        return v

    @field_validator("device_fingerprint")
    @classmethod
    def validate_device_fingerprint(cls, v: Optional[str], info: ValidationInfo) -> Optional[str]:
        lang = info.data.get("response_language", settings.DEFAULT_LANGUAGE)
        if v and not re.match(r"^[a-zA-Z0-9\-_]{1,100}$", v):
            raise ValueError(get_message("invalid.device_fingerprint", lang=lang))
        return v
