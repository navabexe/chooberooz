# Path: src/api/v1/endpoints/auth/request_otp.py
from typing import Annotated, Coroutine, Any, Union
from fastapi import APIRouter, Request, Depends, status
from pydantic import BaseModel, Field
from redis.exceptions import ConnectionError as RedisConnectionError
from src.shared.config.settings import settings
from src.shared.utilities.network import extract_client_ip
from src.shared.models.responses.base import StandardResponse, ErrorResponse
from src.shared.i18n.messages import get_message
from src.domain.authentication.models.otp import RequestOTPInput
from src.api.v1.dependencies.permissions import check_permissions
from src.api.v1.middleware.database_check import check_database_connection
from src.infrastructure.di.container import container
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.errors.domain.security import RateLimitExceededError, InvalidCredentialsError
from src.shared.errors.base import BaseError
from src.shared.errors.infrastructure.database import CacheError
from src.shared.utilities.constants import HttpStatus, DomainErrorCode

router = APIRouter(prefix="/api/v1", tags=[settings.AUTH_TAG])

logger = LoggingService(LogConfig())


class RequestOTPResponse(BaseModel):
    """Response model for OTP request."""
    temporary_token: str = Field(
        ...,
        description="A temporary JWT token",
        json_schema_extra={"example": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
    )
    expires_in: int = Field(
        ...,
        description="Token expiration time in seconds",
        json_schema_extra={"example": 120}
    )
    notification_sent: bool = Field(
        ...,
        description="Whether notification was sent",
        json_schema_extra={"example": True}
    )


def check_otp_permission(role: str) -> Coroutine[Any, Any, str]:
    """Check if the role has permission to request OTP."""
    return check_permissions(role, "write:otp")


async def call_otp_service(data: RequestOTPInput, request: Request, client_ip: str, context: dict) -> dict:
    """Call OTP service to request an OTP."""
    try:
        otp_service = container.otp_service()
        result = await otp_service.request_otp(
            phone=data.phone,
            role=data.role,
            purpose=data.purpose,
            request=request,
            language=data.response_language,
            redis=context["redis"],
            db=context["db"],
            request_id=data.request_id,
            client_version=data.client_version,
            device_fingerprint=data.device_fingerprint,
            user_agent=request.headers.get("User-Agent", "Unknown")
        )
        logger.info("OTP request successful", context={
            "phone": data.phone,
            "role": data.role,
            "purpose": data.purpose,
            "ip": client_ip,
            "endpoint": "/api/v1/request-otp",
            "request_id": data.request_id,
            "client_version": data.client_version,
            "device_fingerprint": data.device_fingerprint
        })
        return result
    except RedisConnectionError as e:
        logger.error("Redis connection failed during OTP request", context={"error": str(e)})
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
    "/request-otp",
    status_code=status.HTTP_200_OK,
    response_model=Union[StandardResponse, ErrorResponse],
    summary="Request OTP for login/signup",
    responses={
        200: {
            "description": "OTP successfully generated",
            "content": {
                "application/json": {
                    "example": {
                        "data": {
                            "temporary_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                            "expires_in": 120,
                            "notification_sent": True
                        },
                        "meta": {
                            "message": "OTP sent",
                            "status": "success",
                            "code": 200
                        }
                    }
                }
            }
        },
        400: {
            "description": "Invalid request or rate limit exceeded",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "You are temporarily blocked due to too many requests.",
                        "message": "Please try again later.",
                        "error_code": "OTP_RATE_LIMIT",
                        "status": "error",
                        "metadata": {"remaining_attempts": 0}
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
        }
    }
)
async def request_otp_endpoint(
        data: RequestOTPInput,
        request: Request,
        client_ip: Annotated[str, Depends(extract_client_ip)],
        context: dict = Depends(check_database_connection),
) -> Union[StandardResponse, ErrorResponse]:
    """
    Request an OTP for authentication.

    Args:
        data: Input data including phone, role, purpose, and optional device fingerprint.
        request: FastAPI request object.
        client_ip: Client IP address.
        context: Database and Redis connections.

    Returns:
        StandardResponse with OTP details or ErrorResponse if failed.
    """
    logger.info("Received request body", context={
        "body": data.model_dump(),
        "device_fingerprint": data.device_fingerprint
    })
    try:
        await check_otp_permission(data.role)
        result = await call_otp_service(data, request, client_ip, context)
        return StandardResponse.success(
            data={
                "temporary_token": result["temporary_token"],
                "expires_in": result["expires_in"],
                "notification_sent": result["notification_sent"]
            },
            message=result["message"],
            code=status.HTTP_200_OK
        )

    except RateLimitExceededError as e:
        logger.error("Too many OTP requests", context={"error": e.message, "phone": data.phone})
        return ErrorResponse(
            detail=e.message,
            message=e.message,
            error_code=e.error_code,
            metadata=e.details
        )
    except InvalidCredentialsError as e:
        logger.error("Invalid OTP request", context={
            "error": e.message,
            "phone": data.phone,
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
        logger.error("Failed to request OTP", context={
            "type": str(type(e)),
            "error": str(e),
            "repr": repr(e),
            "trace": traceback.format_exc(),
            "phone": data.phone,
            "role": data.role,
            "purpose": data.purpose,
            "device_fingerprint": data.device_fingerprint
        })
        return ErrorResponse(
            detail=str(e),
            message=get_message("server.error", language=data.response_language),
            error_code="SERVER_ERROR",
            status="error"
        )