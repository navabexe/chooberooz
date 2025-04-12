from typing import Annotated
from fastapi import APIRouter, Request, Depends, HTTPException
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import Field
from redis.asyncio import Redis
from starlette import status
from src.shared.config.settings import settings
from src.shared.utilities.network import get_client_ip
from src.shared.utilities.logging import log_info, log_error
from src.shared.models.requests.base import BaseRequestModel
from src.shared.models.responses.base import StandardResponse
from src.domain.authentication.services.otp_service import otp_service
from src.shared.security.token import decode_token
from src.shared.security.permissions_loader import get_scopes_for_role
from src.infrastructure.storage.nosql.client import get_nosql_db
from src.infrastructure.storage.cache.client import get_cache_client

router = APIRouter()

class VerifyOTPModel(BaseRequestModel):
    otp: Annotated[str, Field(min_length=4, max_length=10, description="One-time password")]
    temporary_token: Annotated[str, Field(description="Temporary token issued with OTP")]
    request_id: Annotated[str | None, Field(default=None, description="Request identifier for tracing")]
    client_version: Annotated[str | None, Field(default=None, description="Version of the client app")]
    device_fingerprint: Annotated[str | None, Field(default=None, description="Device fingerprint")]
    model_config = {
        "str_strip_whitespace": True,
        "extra": "allow",
    }

@router.post(
    settings.VERIFY_OTP_PATH,
    status_code=status.HTTP_200_OK,
    response_model=StandardResponse,
    summary="Verify OTP",
    tags=[settings.AUTH_TAG]
)
async def verify_otp_endpoint(
    data: VerifyOTPModel,
    request: Request,
    redis: Annotated[Redis, Depends(get_cache_client)],
    db: Annotated[AsyncIOMotorDatabase, Depends(get_nosql_db)],
    client_ip: Annotated[str, Depends(get_client_ip)],
):
    """Verify an OTP code provided by the user."""
    log_info("Received request body", extra={"body": data.model_dump()})
    try:
        payload = await decode_token(data.temporary_token, token_type="temp", redis=redis)
        role = payload.get("role")
        status = payload.get("status")
        scopes = get_scopes_for_role(role, vendor_status=status if role == "vendor" else None)
        log_info("Scopes for role", extra={"role": role, "scopes": scopes, "status": status})
        if "read:otp" not in scopes:
            raise HTTPException(status_code=403, detail="Insufficient permissions to verify OTP")
    except Exception as e:
        log_error("Failed to verify token or permissions", extra={"error": str(e), "temporary_token": data.temporary_token[:10] + "..."})
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    log_info("Checking db injection in verify_otp router", extra={"db_is_none": db is None})
    if db is None:
        log_error("Database connection is None", extra={"endpoint": settings.VERIFY_OTP_PATH})
        raise HTTPException(status_code=500, detail="Database connection error")
    language = getattr(data, "response_language", "fa")
    user_agent = request.headers.get("User-Agent", "Unknown")
    try:
        result = await otp_service.verify_otp(
            otp=data.otp,
            temporary_token=data.temporary_token,
            client_ip=client_ip,
            language=language,
            redis=redis,
            db=db,
            request_id=data.request_id,
            client_version=data.client_version,
            device_fingerprint=data.device_fingerprint,
            user_agent=user_agent
        )
    except Exception as e:
        log_error("Failed to verify OTP", extra={
            "error": str(e),
            "otp": "****",
            "temporary_token": data.temporary_token[:10] + "...",
            "client_ip": client_ip
        })
        raise HTTPException(status_code=500, detail=f"Failed to verify OTP: {str(e)}")
    log_info("OTP verified successfully", extra={
        "phone": result.get("phone"),
        "ip": client_ip,
        "endpoint": settings.VERIFY_OTP_PATH,
        "request_id": data.request_id,
        "client_version": data.request_id,
        "device_fingerprint": data.device_fingerprint,
        "user_agent": user_agent
    })
    return StandardResponse.success(
        data={key: val for key, val in result.items() if key != "message"},
        message=result["message"]
    )