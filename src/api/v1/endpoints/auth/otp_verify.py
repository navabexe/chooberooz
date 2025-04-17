# Path: src/api/v1/endpoints/auth/verify_otp.py
from typing import Annotated, Coroutine, Any, Union
from fastapi import APIRouter, Request, Depends, status
from pydantic import Field, field_validator
from redis.exceptions import ConnectionError as RedisConnectionError
from src.shared.config.settings import settings
from src.shared.utilities.network import extract_client_ip
from src.shared.models.requests.base import BaseRequestModel
from src.shared.models.responses.base import StandardResponse, ErrorResponse
from src.shared.i18n.messages import get_message
from src.shared.security.token import decode_token
from src.api.v1.dependencies.permissions import check_permissions
from src.api.v1.middleware.database_check import check_database_connection
from src.infrastructure.di.container import container
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.errors.domain.security import RateLimitExceededError, InvalidCredentialsError
from src.shared.errors.base import BaseError
from src.shared.errors.infrastructure.database import CacheError
from src.shared.utilities.types import LanguageCode
from src.shared.utilities.constants import HttpStatus, DomainErrorCode

router = APIRouter(prefix="/api/v1", tags=[settings.AUTH_TAG])

logger = LoggingService(LogConfig())


class VerifyOTPModel(BaseRequestModel):
    """Model for OTP verification input."""
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
        """Validate response language."""
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
        logger.error("Redis connection failed during OTP verification", context={"error": str(e)})
        raise CacheError(
            operation="connect",
            error_code="CACHE_ERROR",
            message=get_message("server.error", language=data.response_language),
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"error": str(e)},
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
            "description": "Invalid OTP, token, or device mismatch",
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
        },
        403: {
            "description": "Device mismatch or permission error",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Suspicious device detected.",
                        "message": "Device mismatch detected.",
                        "error_code": "DEVICE_MISMATCH",
                        "status": "error",
                        "metadata": {}
                    }
                }
            }
        },
        429: {
            "description": "Too many attempts with expired OTP or token",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Too many attempts with expired token.",
                        "message": "Please try again later.",
                        "error_code": "TOKEN_EXPIRED_RATE_LIMIT",
                        "status": "error",
                        "metadata": {"remaining_attempts": 0}
                    }
                }
            }
        }
    }
)
async def verify_otp_endpoint(
        data: VerifyOTPModel,
        request: Request,
        client_ip: Annotated[str, Depends(extract_client_ip)],
        context: dict = Depends(check_database_connection),
) -> Union[StandardResponse, ErrorResponse]:
    """
    Verify an OTP and proceed with authentication.

    Args:
        data: Input data including OTP, token, and optional device fingerprint.
        request: FastAPI request object.
        client_ip: Client IP address.
        context: Database and Redis connections.

    Returns:
        StandardResponse with auth details or ErrorResponse if failed.
    """
    logger.info("Received request body", context={
        "body": data.model_dump(),
        "device_fingerprint": data.device_fingerprint
    })

    try:
        payload = await decode_token(data.temporary_token, token_type="temp", redis=context["redis"])
        data.role = payload.get("role")
        data.status = payload.get("status")
    except Exception as e:
        logger.error("Failed to verify token", context={
            "error": str(e),
            "temporary_token": data.temporary_token[:10] + "...",
            "device_fingerprint": data.device_fingerprint
        })
        return ErrorResponse(
            detail=str(e),
            message=get_message("token.invalid", language=data.response_language),
            error_code="INVALID_TOKEN",
            status="error"
        )

    try:
        await check_otp_permission(data.role, data.status)
    except Exception as e:
        logger.error("Permission check failed", context={"error": str(e), "role": data.role})
        return ErrorResponse(
            detail=str(e),
            message=get_message("auth.forbidden", language=data.response_language),
            error_code="PERMISSION_DENIED",
            status="error"
        )

    try:
        result = await call_otp_verification(data, request, client_ip, context)
        logger.info("OTP verified successfully", context={
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
    except RateLimitExceededError as e:
        logger.error("Too many OTP attempts", context={"error": e.message, "client_ip": client_ip})
        return ErrorResponse(
            detail=e.message,
            message=e.message,
            error_code=e.error_code,
            metadata=e.details
        )
    except InvalidCredentialsError as e:
        logger.error("Invalid OTP", context={
            "error": e.message,
            "client_ip": client_ip,
            "error_code": e.error_code,
            "device_fingerprint": data.device_fingerprint
        })
        return ErrorResponse(
            detail=e.message,
            message=e.message,
            error_code=e.error_code,
            metadata=e.details
        )
    except Exception as e:
        import traceback
        logger.error("Failed to verify OTP", context={
            "type": str(type(e)),
            "error": str(e),
            "repr": repr(e),
            "trace": traceback.format_exc(),
            "otp": "****",
            "temporary_token": data.temporary_token[:10] + "...",
            "client_ip": client_ip,
            "device_fingerprint": data.device_fingerprint
        })
        return ErrorResponse(
            detail=str(e),
            message=get_message("server.error", language=data.response_language),
            error_code="SERVER_ERROR",
            status="error"
        )