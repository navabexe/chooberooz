from typing import Annotated
from fastapi import APIRouter, Request, Depends
from pydantic import Field, field_validator
from starlette import status
from src.shared.config.settings import settings
from src.shared.utilities.network import get_client_ip
from src.shared.utilities.logging import log_info, log_error
from src.shared.models.requests.base import BaseRequestModel
from src.shared.models.responses.base import StandardResponse, Meta
from src.shared.i18n.messages import get_message
from src.shared.errors.base import TooManyRequestsException, BadRequestException
from src.shared.security.token import decode_token
from src.api.v1.dependencies.permissions import check_permissions
from src.api.v1.middleware.database_check import check_database_connection
from src.infrastructure.di.container import container

router = APIRouter(prefix="/api/v1", tags=[settings.AUTH_TAG])

class VerifyOTPModel(BaseRequestModel):
    otp: Annotated[str, Field(min_length=4, max_length=10, description="One-time password")]
    temporary_token: Annotated[str, Field(description="Temporary token issued with OTP")]
    request_id: Annotated[str | None, Field(default=None, description="Request identifier for tracing")]
    client_version: Annotated[str | None, Field(default=None, description="Version of the client app")]
    device_fingerprint: Annotated[str | None, Field(default=None, description="Device fingerprint")]
    role: str | None = None
    status: str | None = None
    model_config = {
        "str_strip_whitespace": True,
        "extra": "allow",
    }
    @field_validator("response_language")
    @classmethod
    def validate_language(cls, v: str) -> str:
        allowed = settings.SUPPORTED_LANGUAGES.split(",")
        if v not in allowed:
            raise ValueError(f"Unsupported language. Allowed: {', '.join(allowed)}.")
        return v

@router.post(
    "/verify-otp",
    status_code=status.HTTP_200_OK,
    response_model=StandardResponse,
    summary="Verify OTP"
)
async def verify_otp_endpoint(
    data: VerifyOTPModel,
    request: Request,
    client_ip: Annotated[str, Depends(get_client_ip)],
    context: dict = Depends(check_database_connection),
) -> StandardResponse:
    """Verify an OTP code provided by the user."""
    log_info("Received request body", extra={"body": data.model_dump()})
    try:
        payload = await decode_token(data.temporary_token, token_type="temp", redis=context["redis"])
        data.role = payload.get("role")
        data.status = payload.get("status")
    except Exception as e:
        log_error("Failed to verify token", extra={"error": str(e), "temporary_token": data.temporary_token[:10] + "..."})
        return StandardResponse(
            data=None,
            meta=Meta(
                message=get_message("token.invalid", data.response_language),
                status="error",
                code=status.HTTP_401_UNAUTHORIZED
            )
        )
    try:
        await check_permissions(data.role, "read:otp", vendor_status=data.status if data.role == "vendor" else None)
    except Exception as e:
        log_error("Permission check failed", extra={"error": str(e), "role": data.role})
        return StandardResponse(
            data=None,
            meta=Meta(
                message=str(e),
                status="error",
                code=status.HTTP_403_FORBIDDEN
            )
        )
    otp_service = container.otp_service()
    user_agent = request.headers.get("User-Agent", "Unknown")
    try:
        result = await otp_service.verify_otp(
            otp=data.otp,
            temporary_token=data.temporary_token,
            client_ip=client_ip,
            language=data.response_language,
            redis=context["redis"],
            db=context["db"],
            request_id=data.request_id,
            client_version=data.client_version,
            device_fingerprint=data.device_fingerprint,
            user_agent=user_agent
        )
        log_info("OTP verified successfully", extra={
            "phone": result.get("phone"),
            "ip": client_ip,
            "endpoint": "/api/v1/verify-otp",
            "request_id": data.request_id,
            "client_version": data.client_version,
            "device_fingerprint": data.device_fingerprint,
            "user_agent": user_agent
        })
        return StandardResponse.success(
            data={key: val for key, val in result.items() if key != "message"},
            message=result["message"]
        )
    except TooManyRequestsException as e:
        log_error("Too many OTP attempts", extra={"error": str(e), "client_ip": client_ip})
        return StandardResponse(
            data=None,
            meta=Meta(
                message=get_message("otp.too_many.attempts", data.response_language),
                status="error",
                code=status.HTTP_429_TOO_MANY_REQUESTS
            )
        )
    except BadRequestException as e:
        log_error("Invalid OTP", extra={"error": str(e), "client_ip": client_ip})
        return StandardResponse(
            data=None,
            meta=Meta(
                message=get_message("otp.invalid", data.response_language),
                status="error",
                code=status.HTTP_400_BAD_REQUEST
            )
        )
    except Exception as e:
        log_error("Failed to verify OTP", extra={
            "error": str(e),
            "otp": "****",
            "temporary_token": data.temporary_token[:10] + "...",
            "client_ip": client_ip
        })
        return StandardResponse(
            data=None,
            meta=Meta(
                message=get_message("server.error", data.response_language),
                status="error",
                code=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        )