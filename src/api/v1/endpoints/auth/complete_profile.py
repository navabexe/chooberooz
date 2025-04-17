# Path: src/api/v1/endpoints/auth/complete_profile.py
from typing import Annotated, Union
from fastapi import APIRouter, Request, Depends, status
from src.shared.config.settings import settings
from src.shared.utilities.network import extract_client_ip
from src.shared.models.responses.base import StandardResponse, ErrorResponse
from src.shared.i18n.messages import get_message
from src.api.v1.middleware.database_check import check_database_connection
from src.domain.authentication.models.complete_profile import CompleteUserProfileInput, CompleteVendorProfileInput
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.errors.base import BaseError
from src.shared.errors.domain.security import InvalidCredentialsError, UnauthorizedAccessError, RateLimitExceededError
from src.shared.utilities.constants import HttpStatus, DomainErrorCode

router = APIRouter(prefix="/api/v1", tags=[settings.AUTH_TAG])

logger = LoggingService(LogConfig())


async def call_complete_profile_service(
        data: Union[CompleteUserProfileInput, CompleteVendorProfileInput],
        request: Request,
        client_ip: str,
        context: dict
) -> dict:
    """Call profile completion service."""
    from src.infrastructure.di.container import container
    try:
        profile_service = container.complete_profile_service()
        params = {
            "temporary_token": data.temporary_token,
            "first_name": getattr(data, "first_name", None),
            "last_name": getattr(data, "last_name", None),
            "email": getattr(data, "email", None),
            "business_name": getattr(data, "business_name", None),
            "city": getattr(data, "city", None),
            "province": getattr(data, "province", None),
            "location": getattr(data, "location", None),
            "address": getattr(data, "address", None),
            "business_category_ids": getattr(data, "business_category_ids", None),
            "visibility": getattr(data, "visibility", "COLLABORATIVE"),
            "vendor_type": getattr(data, "vendor_type", None),
            "languages": getattr(data, "preferred_languages", None),
            "request": request,
            "language": data.response_language,
            "redis": context["redis"],
            "db": context["db"],
            "request_id": data.request_id,
            "client_version": data.client_version,
            "device_fingerprint": data.device_fingerprint
        }
        return await profile_service.complete_profile(**params)
    except (InvalidCredentialsError, UnauthorizedAccessError, RateLimitExceededError) as e:
        logger.error(f"Profile completion failed: {e.message}", context={
            "error": str(e),
            "client_ip": client_ip,
            "request_id": data.request_id
        })
        raise
    except Exception as e:
        logger.error("Unexpected error during profile completion", context={
            "error": str(e),
            "client_ip": client_ip,
            "request_id": data.request_id
        })
        raise BaseError(
            error_code="SERVER_ERROR",
            message=get_message("server.error", language=data.response_language),
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"error": str(e)},
            language=data.response_language
        )


@router.post(
    "/complete-user-profile",
    status_code=status.HTTP_200_OK,
    response_model=Union[StandardResponse, ErrorResponse],
    summary="Complete user profile",
    responses={
        200: {
            "description": "User profile successfully completed",
            "content": {
                "application/json": {
                    "example": {
                        "data": {
                            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                            "status": "active",
                            "notification_sent": True,
                            "phone": "+989123456789",
                            "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                        },
                        "meta": {
                            "message": "Profile completed successfully.",
                            "status": "success",
                            "code": 200
                        }
                    }
                }
            }
        },
        400: {
            "description": "Invalid input or token",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Invalid token payload.",
                        "message": "The token provided is invalid.",
                        "error_code": "INVALID_TOKEN",
                        "status": "error",
                        "metadata": {}
                    }
                }
            }
        },
        403: {
            "description": "Permission denied",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "User cannot provide vendor-specific fields.",
                        "message": "Permission denied.",
                        "error_code": "INVALID_FIELDS",
                        "status": "error",
                        "metadata": {}
                    }
                }
            }
        },
        429: {
            "description": "Too many attempts",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Too many profile completion attempts.",
                        "message": "Please try again later.",
                        "error_code": "PROFILE_RATE_LIMIT",
                        "status": "error",
                        "metadata": {}
                    }
                }
            }
        }
    }
)
async def complete_user_profile(
        data: CompleteUserProfileInput,
        request: Request,
        client_ip: Annotated[str, Depends(extract_client_ip)],
        context: dict = Depends(check_database_connection),
) -> Union[StandardResponse, ErrorResponse]:
    """
    Complete a user's profile after OTP verification.

    Args:
        data: Input data including token, names, email, and optional languages.
        request: FastAPI request object.
        client_ip: Client IP address.
        context: Database and Redis connections.

    Returns:
        StandardResponse with tokens or ErrorResponse if failed.
    """
    logger.info("Received request body", context={
        "body": data.model_dump(),
        "device_fingerprint": data.device_fingerprint
    })

    try:
        result = await call_complete_profile_service(data, request, client_ip, context)
        return StandardResponse.success(
            data=result["data"],
            message=result["message"],
            code=status.HTTP_200_OK
        )
    except (InvalidCredentialsError, UnauthorizedAccessError, RateLimitExceededError) as e:
        return ErrorResponse(
            detail=e.message,
            message=e.message,
            error_code=e.error_code,
            metadata=e.details
        )
    except Exception as e:
        logger.error("Unexpected error in complete_user_profile", context={
            "error": str(e),
            "client_ip": client_ip,
            "request_id": data.request_id
        })
        return ErrorResponse(
            detail=str(e),
            message=get_message("server.error", language=data.response_language),
            error_code="SERVER_ERROR",
            status="error"
        )


@router.post(
    "/complete-vendor-profile",
    status_code=status.HTTP_200_OK,
    response_model=Union[StandardResponse, ErrorResponse],
    summary="Complete vendor profile",
    responses={
        200: {
            "description": "Vendor profile successfully completed",
            "content": {
                "application/json": {
                    "example": {
                        "data": {
                            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                            "status": "pending",
                            "notification_sent": True,
                            "phone": "+989123456789"
                        },
                        "meta": {
                            "message": "Profile submitted for review.",
                            "status": "success",
                            "code": 200
                        }
                    }
                }
            }
        },
        400: {
            "description": "Invalid input or token",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Business name is required for vendor.",
                        "message": "Vendor profile is not eligible.",
                        "error_code": "MISSING_BUSINESS_NAME",
                        "status": "error",
                        "metadata": {}
                    }
                }
            }
        },
        403: {
            "description": "Permission denied",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Permission denied.",
                        "message": "Permission denied.",
                        "error_code": "INVALID_FIELDS",
                        "status": "error",
                        "metadata": {}
                    }
                }
            }
        },
        429: {
            "description": "Too many attempts",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Too many profile completion attempts.",
                        "message": "Please try again later.",
                        "error_code": "PROFILE_RATE_LIMIT",
                        "status": "error",
                        "metadata": {}
                    }
                }
            }
        }
    }
)
async def complete_vendor_profile(
        data: CompleteVendorProfileInput,
        request: Request,
        client_ip: Annotated[str, Depends(extract_client_ip)],
        context: dict = Depends(check_database_connection),
) -> Union[StandardResponse, ErrorResponse]:
    """
    Complete a vendor's profile after OTP verification.

    Args:
        data: Input data including token, business details, and optional fields.
        request: FastAPI request object.
        client_ip: Client IP address.
        context: Database and Redis connections.

    Returns:
        StandardResponse with tokens or ErrorResponse if failed.
    """
    logger.info("Received request body", context={
        "body": data.model_dump(),
        "device_fingerprint": data.device_fingerprint
    })

    try:
        result = await call_complete_profile_service(data, request, client_ip, context)
        return StandardResponse.success(
            data=result["data"],
            message=result["message"],
            code=status.HTTP_200_OK
        )
    except (InvalidCredentialsError, UnauthorizedAccessError, RateLimitExceededError) as e:
        return ErrorResponse(
            detail=e.message,
            message=e.message,
            error_code=e.error_code,
            metadata=e.details
        )
    except Exception as e:
        logger.error("Unexpected error in complete_vendor_profile", context={
            "error": str(e),
            "client_ip": client_ip,
            "request_id": data.request_id
        })
        return ErrorResponse(
            detail=str(e),
            message=get_message("server.error", language=data.response_language),
            error_code="SERVER_ERROR",
            status="error"
        )