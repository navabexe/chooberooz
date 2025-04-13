from typing import Annotated, Coroutine, Any, Union
from fastapi import APIRouter, Request, Depends, status
from pyasn1.compat.octets import null
from pydantic import BaseModel, Field
from redis.exceptions import ConnectionError as RedisConnectionError

from src.shared.config.settings import settings
from src.shared.utilities.network import get_client_ip
from src.shared.utilities.logging import log_info, log_error
from src.shared.models.responses.base import StandardResponse, ErrorResponse
from src.shared.i18n.messages import get_message
from src.shared.errors.base import TooManyRequestsException, BadRequestException
from src.domain.authentication.models.otp import RequestOTPInput
from src.api.v1.dependencies.permissions import check_permissions
from src.api.v1.middleware.database_check import check_database_connection
from src.infrastructure.di.container import container

router = APIRouter(prefix="/api/v1", tags=[settings.AUTH_TAG])

class RequestOTPResponse(BaseModel):
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
            device_fingerprint=data.device_fingerprint
        )
        log_info("OTP request successful", extra={
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
        log_error("Redis connection failed during OTP request", extra={"error": str(e)})
        raise BadRequestException(
            detail="Redis unavailable.",
            message=get_message("server.error", data.response_language),
            error_code="REDIS_ERROR",
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
                        "metadata": null
                    }
                }
            }
        }
    }
)
async def request_otp_endpoint(
    data: RequestOTPInput,
    request: Request,
    client_ip: Annotated[str, Depends(get_client_ip)],
    context: dict = Depends(check_database_connection),
) -> Union[StandardResponse, ErrorResponse]:
    """Request an OTP for authentication."""
    log_info("Received request body", extra={"body": data.model_dump()})
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

    except TooManyRequestsException as e:
        log_error("Too many OTP requests", extra={"error": e.detail, "phone": data.phone})
        return ErrorResponse(
            detail=e.detail,
            message=e.message,
            error_code=e.error_code,
            metadata=e.metadata
        )
    except BadRequestException as e:
        log_error("Invalid OTP request", extra={"error": e.detail, "phone": data.phone})
        return ErrorResponse(
            detail=e.detail,
            message=e.message,
            error_code=e.error_code,
            metadata=e.metadata
        )
    except Exception as e:
        import traceback
        log_error("Failed to request OTP", extra={
            "type": str(type(e)),
            "error": str(e),
            "repr": repr(e),
            "trace": traceback.format_exc(),
            "phone": data.phone,
            "role": data.role,
            "purpose": data.purpose
        })
        return ErrorResponse(
            detail=str(e),
            message=get_message("server.error", data.response_language),
            error_code="SERVER_ERROR"
        )
