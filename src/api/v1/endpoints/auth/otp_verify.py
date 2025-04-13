from typing import Annotated, Coroutine, Any, Union
from fastapi import APIRouter, Request, Depends, status
from pydantic import Field, field_validator
from redis.exceptions import ConnectionError as RedisConnectionError

from src.shared.config.settings import settings
from src.shared.utilities.network import get_client_ip
from src.shared.utilities.logging import log_info, log_error
from src.shared.models.requests.base import BaseRequestModel
from src.shared.models.responses.base import StandardResponse, ErrorResponse
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

def check_otp_permission(role: str, status: str | None) -> Coroutine[Any, Any, str]:
    """Check if the role has permission to verify OTP."""
    return check_permissions(role, "read:otp", vendor_status=status if role == "vendor" else None)

async def call_otp_verification(data: VerifyOTPModel, request: Request, client_ip: str, context: dict) -> dict:
    """Call OTP service to verify the OTP."""
    try:
        otp_service = container.otp_service()
        return await otp_service.verify_otp(
            otp=data.otp,
            temporary_token=data.temporary_token,
            client_ip=client_ip,
            language=data.response_language,
            redis=context["redis"],
            db=context["db"],
            request_id=data.request_id,
            client_version=data.client_version,
            device_fingerprint=data.device_fingerprint,
            user_agent=request.headers.get("User-Agent", "Unknown")
        )
    except RedisConnectionError as e:
        log_error("Redis connection failed during OTP verification", extra={"error": str(e)})
        raise BadRequestException(
            detail="Redis unavailable.",
            message=get_message("server.error", data.response_language),
            error_code="REDIS_ERROR",
            language=data.response_language
        )

@router.post(
    "/verify-otp",
    status_code=status.HTTP_200_OK,
    response_model=Union[StandardResponse, ErrorResponse],
    summary="Verify OTP",
    responses={
        200: {
            "description": "OTP successfully verified",
            "content": {
                "application/json": {
                    "example": {
                        "data": {
                            "status": "incomplete",
                            "temporary_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                            "phone": "+989123456789"
                        },
                        "meta": {
                            "message": "Please complete your profile.",
                            "status": "success",
                            "code": 200
                        }
                    }
                }
            }
        },
        400: {
            "description": "Invalid OTP or token",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "The entered code is incorrect. 4 attempts left.",
                        "message": "The code you entered is incorrect.",
                        "error_code": "OTP_INVALID",
                        "status": "error",
                        "metadata": {"remaining_attempts": 4}
                    }
                }
            }
        }
    }
)
async def verify_otp_endpoint(
    data: VerifyOTPModel,
    request: Request,
    client_ip: Annotated[str, Depends(get_client_ip)],
    context: dict = Depends(check_database_connection),
) -> Union[StandardResponse, ErrorResponse]:
    """Verify an OTP and proceed with authentication."""
    log_info("Received request body", extra={"body": data.model_dump()})

    try:
        payload = await decode_token(data.temporary_token, token_type="temp", redis=context["redis"])
        data.role = payload.get("role")
        data.status = payload.get("status")
    except Exception as e:
        log_error("Failed to verify token", extra={"error": str(e), "temporary_token": data.temporary_token[:10] + "..."})
        return ErrorResponse(
            detail=str(e),
            message=get_message("token.invalid", data.response_language),
            error_code="INVALID_TOKEN"
        )

    try:
        await check_otp_permission(data.role, data.status)
    except Exception as e:
        log_error("Permission check failed", extra={"error": str(e), "role": data.role})
        return ErrorResponse(
            detail=str(e),
            message=get_message("auth.forbidden", data.response_language),
            error_code="PERMISSION_DENIED"
        )

    try:
        result = await call_otp_verification(data, request, client_ip, context)
        log_info("OTP verified successfully", extra={
            "phone": result.get("phone"),
            "ip": client_ip,
            "endpoint": "/api/v1/verify-otp",
            "request_id": data.request_id,
            "client_version": data.client_version,
            "device_fingerprint": data.device_fingerprint,
            "user_agent": request.headers.get("User-Agent", "Unknown")
        })
        return StandardResponse.success(
            data={key: val for key, val in result.items() if key != "message"},
            message=result["message"],
            code=status.HTTP_200_OK
        )
    except TooManyRequestsException as e:
        log_error("Too many OTP attempts", extra={"error": e.detail, "client_ip": client_ip})
        return ErrorResponse(
            detail=e.detail,
            message=e.message,
            error_code=e.error_code,
            metadata=e.metadata
        )
    except BadRequestException as e:
        log_error("Invalid OTP", extra={"error": e.detail, "client_ip": client_ip})
        return ErrorResponse(
            detail=e.detail,
            message=e.message,
            error_code=e.error_code,
            metadata=e.metadata
        )
    except Exception as e:
        log_error("Failed to verify OTP", extra={
            "error": str(e),
            "otp": "****",
            "temporary_token": data.temporary_token[:10] + "...",
            "client_ip": client_ip
        })
        return ErrorResponse(
            detail=str(e),
            message=get_message("server.error", data.response_language),
            error_code="SERVER_ERROR"
        )