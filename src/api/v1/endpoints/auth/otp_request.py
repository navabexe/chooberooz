from typing import Annotated
from fastapi import APIRouter, Request, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase
from redis.asyncio import Redis
from starlette import status
from src.shared.config.settings import settings
from src.shared.utilities.network import get_client_ip
from src.shared.utilities.logging import log_info, log_error
from src.shared.models.responses.base import StandardResponse
from src.domain.authentication.services.otp_service import otp_service
from src.domain.authentication.models.otp import RequestOTPInput
from src.infrastructure.storage.nosql.client import get_nosql_db
from src.infrastructure.storage.cache.client import get_cache_client
from src.shared.security.permissions_loader import get_scopes_for_role

router = APIRouter()

@router.post(
    settings.REQUEST_OTP_PATH,
    status_code=status.HTTP_200_OK,
    response_model=StandardResponse,
    summary="Request OTP for login/signup",
    tags=[settings.AUTH_TAG]
)
async def request_otp_endpoint(
    data: RequestOTPInput,
    request: Request,
    redis: Annotated[Redis, Depends(get_cache_client)],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_nosql_db)],
    client_ip: Annotated[str, Depends(get_client_ip)],
):
    """Request an OTP to be sent to the user's phone."""
    log_info("Received request body", extra={"body": data.model_dump()})
    try:
        scopes = get_scopes_for_role(data.role)
        log_info("Scopes for role", extra={"role": data.role, "scopes": scopes})
        if "write:otp" not in scopes:
            raise HTTPException(status_code=403, detail="Insufficient permissions to request OTP")
    except Exception as e:
        log_error("Failed to check permissions", extra={"error": str(e), "role": data.role})
        raise HTTPException(status_code=400, detail="Invalid role or permission data")
    log_info("Checking db injection in router", extra={"db_is_none": db is None})
    if db is None:
        log_error("Database connection is None", extra={"endpoint": settings.REQUEST_OTP_PATH})
        raise HTTPException(status_code=500, detail="Database connection error")
    try:
        result = await otp_service.request_otp(
            phone=data.phone,
            role=data.role,
            purpose=data.purpose,
            request=request,
            language=data.response_language,
            redis=redis,
            db=db,
            request_id=data.request_id,
            client_version=data.client_version,
            device_fingerprint=data.device_fingerprint
        )
    except Exception as e:
        log_error("Failed to request OTP", extra={
            "error": str(e),
            "phone": data.phone,
            "role": data.role,
            "purpose": data.purpose
        })
        raise HTTPException(status_code=500, detail=f"Failed to process OTP request: {str(e)}")
    log_info("OTP request successful", extra={
        "phone": data.phone,
        "role": data.role,
        "purpose": data.purpose,
        "ip": client_ip,
        "endpoint": settings.REQUEST_OTP_PATH,
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