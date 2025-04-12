from typing import Annotated

from fastapi import APIRouter, Request, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase
from pydantic import Field
from redis.asyncio import Redis
from starlette import status

from src.shared.config.settings import settings
from src.shared.utilities.network import get_client_ip
from src.shared.utilities.logging import log_info
from src.shared.models.requests.base import BaseRequestModel
from src.shared.models.responses.base import StandardResponse
from src.domain.authentication.services.otp_service import otp_service
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
    client_ip: Annotated[str, Depends(get_client_ip)]
):
    """Verify an OTP with the provided temporary token."""
    # Log to check db injection
    log_info("Checking db injection in verify_otp router", extra={"db_is_none": db is None})

    language = getattr(data, "response_language", "fa")
    user_agent = request.headers.get("User-Agent", "Unknown")

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

    log_info("OTP verified successfully", extra={
        "phone": result.get("phone"),
        "ip": client_ip,
        "endpoint": settings.VERIFY_OTP_PATH,
        "request_id": data.request_id,
        "client_version": data.client_version,
        "device_fingerprint": data.device_fingerprint,
        "user_agent": user_agent
    })

    return StandardResponse.success(
        data={key: val for key, val in result.items() if key != "message"},
        message=result["message"]
    )