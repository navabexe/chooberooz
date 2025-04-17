from typing import Annotated, Optional, Union
import traceback
from fastapi import APIRouter, Request, Depends, status
from pydantic import Field, model_validator
from src.shared.config.settings import settings
from src.shared.models.requests.base import BaseRequestModel
from src.shared.models.responses.base import StandardResponse, ErrorResponse
from src.shared.i18n.messages import get_message
from src.shared.utilities.network import extract_client_ip
from src.api.v1.middleware.database_check import check_database_connection
from src.infrastructure.di.container import container
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.errors.domain.security import InvalidCredentialsError, RateLimitExceededError

router = APIRouter(prefix="/api/v1", tags=[settings.AUTH_TAG])

logger = LoggingService(LogConfig())


class LoginRequest(BaseRequestModel):
    """Model for login input."""
    phone: Optional[str] = Field(
        default=None,
        min_length=10,
        pattern=r"^\+?\d+$",
        description="User/Vendor phone number (e.g. +989123456789)",
        examples=["+989123456789"]
    )
    username: Optional[str] = Field(
        default=None,
        min_length=3,
        max_length=50,
        description="Admin username (e.g. navabexe)",
        examples=["navabexe"]
    )
    password: str = Field(
        min_length=8,
        max_length=128,
        description="User/Admin/Vendor password",
        examples=["P@ssword123"]
    )
    request_id: Optional[str] = Field(default=None, max_length=36, description="Request identifier for tracing")
    client_version: Optional[str] = Field(default=None, max_length=15, description="Version of the client app")
    device_fingerprint: Optional[str] = Field(default=None, max_length=100, description="Device fingerprint")

    model_config = {
        "str_strip_whitespace": True,
        "extra": "forbid"
    }

    @model_validator(mode="before")
    @classmethod
    def at_least_one_identifier(cls, values):
        if not values.get("phone") and not values.get("username"):
            raise ValueError("Either phone or username must be provided.")
        if values.get("phone") and values.get("username"):
            raise ValueError("Provide either phone or username, not both.")
        return values


@router.post(
    "/login",
    status_code=status.HTTP_200_OK,
    response_model=Union[StandardResponse, ErrorResponse],
    summary="Login for users, vendors, and admins",
    responses={
        200: {
            "description": "Login successful",
            "content": {
                "application/json": {
                    "example": {
                        "data": {
                            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                            "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                            "token_type": "bearer",
                            "expires_in": 3600,
                            "role": "user"
                        },
                        "meta": {
                            "message": "Login successful.",
                            "status": "success",
                            "code": 200
                        }
                    }
                }
            }
        },
        400: {
            "description": "Invalid input",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Either phone or username must be provided.",
                        "message": "Invalid input.",
                        "error_code": "INVALID_CREDENTIALS",
                        "status": "error"
                    }
                }
            }
        },
        401: {
            "description": "Invalid credentials",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Invalid login credentials.",
                        "message": "Invalid credentials.",
                        "error_code": "INVALID_CREDENTIALS",
                        "status": "error"
                    }
                }
            }
        },
        429: {
            "description": "Too many login attempts",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Too many login attempts.",
                        "message": "Please try again later.",
                        "error_code": "RATE_LIMIT_EXCEEDED",
                        "status": "error",
                        "metadata": {"remaining_attempts": 0}
                    }
                }
            }
        }
    }
)
async def login_endpoint(
        data: LoginRequest,
        request: Request,
        client_ip: Annotated[str, Depends(extract_client_ip)],
        context: dict = Depends(check_database_connection),
) -> Union[StandardResponse, ErrorResponse]:
    """Unified login endpoint for users, vendors, and admins."""
    logger.info("Received login request", context={
        "body": data.model_dump(),
        "client_ip": client_ip,
        "request_id": data.request_id,
        "device_fingerprint": data.device_fingerprint
    })

    try:
        login_service = container.login_service()
        result = await login_service.login(
            phone=data.phone,
            username=data.username,
            password=data.password,
            client_ip=client_ip,
            language=data.response_language,
            redis=context["redis"],
            db=context["db"],
            request_id=data.request_id,
            client_version=data.client_version,
            device_fingerprint=data.device_fingerprint,
            user_agent=request.headers.get("User-Agent", "Unknown")
        )
        logger.info("Login successful", context={
            "user": data.phone or data.username,
            "client_ip": client_ip,
            "request_id": data.request_id,
            "role": result["role"]
        })
        return StandardResponse.success(
            data=result,
            message=get_message("auth.login.success", language=data.response_language),
            code=status.HTTP_200_OK
        )
    except InvalidCredentialsError as e:
        logger.error("Invalid login credentials", context={
            "error": e.message,
            "client_ip": client_ip,
            "user": data.phone or data.username,
            "error_code": e.error_code
        })
        return ErrorResponse(
            detail=e.message,
            message=e.message,
            error_code=e.error_code,
            status="error",
            metadata=e.details
        )
    except RateLimitExceededError as e:
        logger.error("Too many login attempts", context={
            "error": e.message,
            "client_ip": client_ip,
            "user": data.phone or data.username,
            "error_code": e.error_code
        })
        return ErrorResponse(
            detail=e.message,
            message=e.message,
            error_code=e.error_code,
            status="error",
            metadata=e.details
        )
    except Exception as e:
        logger.error("Unexpected login error", context={
            "error": str(e),
            "type": str(type(e)),
            "trace": traceback.format_exc(),
            "client_ip": client_ip,
            "user": data.phone or data.username,
            "request_id": data.request_id
        })
        return ErrorResponse(
            detail=str(e),
            message=get_message("server.error", language=data.response_language),
            error_code="SERVER_ERROR",
            status="error"
        )