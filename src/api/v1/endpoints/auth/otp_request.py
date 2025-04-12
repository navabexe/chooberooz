from typing import Annotated
from fastapi import APIRouter, Request, Depends
from starlette import status
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

@router.post(
    "/request-otp",
    status_code=status.HTTP_200_OK,
    response_model=StandardResponse,
    summary="Request OTP for login/signup"
)
async def request_otp_endpoint(
    data: RequestOTPInput,
    request: Request,
    client_ip: Annotated[str, Depends(get_client_ip)],
    context: dict = Depends(check_database_connection),
) -> StandardResponse:
    """Request an OTP to be sent to the user's phone."""
    log_info("Received request body", extra={"body": data.model_dump()})
    try:
        await check_permissions(data.role, "write:otp")
    except Exception as e:
        log_error("Permission check failed", extra={"error": str(e), "role": data.role})
        return ErrorResponse.from_exception(
            detail=str(e),
            message=str(e),
            error_code="PERMISSION_DENIED",
        )
    otp_service = container.otp_service()
    try:
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
        return StandardResponse.success(
            data={
                "temporary_token": result["temporary_token"],
                "expires_in": result["expires_in"],
                "notification_sent": result["notification_sent"]
            },
            message=result["message"]
        )
    except TooManyRequestsException as e:
        log_error("Too many OTP requests", extra={"error": str(e), "phone": data.phone})
        return ErrorResponse.from_exception(
            detail=str(e),
            message=get_message("otp.too_many.blocked", data.response_language),
            error_code="OTP_RATE_LIMIT",
        )
    except BadRequestException as e:
        log_error("Invalid OTP request", extra={"error": str(e), "phone": data.phone})
        return ErrorResponse.from_exception(
            detail=str(e),
            message=get_message("server.error", data.response_language),
            error_code="BAD_REQUEST",
        )
    except Exception as e:
        log_error("Failed to request OTP", extra={
            "error": str(e),
            "phone": data.phone,
            "role": data.role,
            "purpose": data.purpose
        })
        return ErrorResponse.from_exception(
            detail="Unexpected server error",
            message=get_message("server.error", data.response_language),
            error_code="SERVER_ERROR",
        )