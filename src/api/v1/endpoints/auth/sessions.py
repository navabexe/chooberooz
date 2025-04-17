from typing import Annotated, Literal, Optional, Union
from fastapi import APIRouter, Request, Depends, status, Query
from redis.asyncio import Redis
from src.shared.config.settings import settings
from src.shared.models.responses.base import StandardResponse, ErrorResponse
from src.shared.i18n.messages import get_message
from src.shared.utilities.network import extract_client_ip
from src.shared.security.token import get_current_user
from src.api.v1.middleware.database_check import check_database_connection
from src.infrastructure.di.container import container
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.errors.domain.security import InvalidCredentialsError, UnauthorizedAccessError
from src.shared.utilities.constants import HttpStatus, DomainErrorCode

router = APIRouter(prefix="/api/v1", tags=[settings.AUTH_TAG])

logger = LoggingService(LogConfig())


@router.get(
    "/sessions",
    status_code=status.HTTP_200_OK,
    response_model=Union[StandardResponse, ErrorResponse],
    summary="Retrieve user sessions",
    description="Retrieve a list of user sessions with optional status filtering. Admins can specify a target user ID.",
    responses={
        200: {
            "description": "List of sessions retrieved successfully",
            "content": {
                "application/json": {
                    "example": {
                        "data": {
                            "sessions": [
                                {
                                    "ip": "127.0.0.1",
                                    "created_at": "2025-04-17T13:27:04.375923+00:00",
                                    "status": "active",
                                    "jti": "41ca8e06-0fda-4f1c-b548-18c473199b3f"
                                }
                            ],
                            "notification_sent": False
                        },
                        "meta": {
                            "message": "Active sessions retrieved successfully.",
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
                        "detail": "Invalid request parameters.",
                        "message": "Invalid input.",
                        "error_code": "INVALID_CREDENTIALS",
                        "status": "error"
                    }
                }
            }
        },
        403: {
            "description": "Forbidden",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Access denied.",
                        "message": "Access denied.",
                        "error_code": "UNAUTHORIZED_ACCESS",
                        "status": "error"
                    }
                }
            }
        }
    }
)
async def get_sessions_endpoint(
        request: Request,
        current_user: Annotated[dict, Depends(get_current_user)],
        context: dict = Depends(check_database_connection),
        status: Annotated[Literal["active", "all"], Query(description="Filter sessions by status (active/all)", examples=["active", "all"])] = "active",
        language: Annotated[Literal["fa", "en", "ar"], Query(description="Response language (fa/en/ar)", examples=["fa", "en"])] = "fa",
        target_user_id: Annotated[Optional[str], Query(description="Target user ID (admin only)", examples=["6800e816c910f77b210d2c33"])] = None
) -> Union[StandardResponse, ErrorResponse]:
    """Retrieve sessions for the current user or a target user (admin only) with filtering options."""
    client_ip = await extract_client_ip(request)
    user_id = current_user["user_id"]
    user_role = current_user["role"]
    db = context["db"]

    logger.info("Received get sessions request", context={
        "user_id": user_id,
        "role": user_role,
        "target_user_id": target_user_id,
        "client_ip": client_ip,
        "status_filter": status,
        "request_id": request.headers.get("X-Request-ID")
    })

    try:
        # Determine the target user ID
        if target_user_id:
            if user_role != "admin":
                logger.error("Non-admin attempted to access another user's sessions", context={
                    "user_id": user_id,
                    "target_user_id": target_user_id,
                    "client_ip": client_ip
                })
                raise UnauthorizedAccessError(
                    resource="sessions",
                    error_code=DomainErrorCode.UNAUTHORIZED_ACCESS.value,
                    message=get_message("auth.forbidden", language=language),
                    status_code=HttpStatus.FORBIDDEN.value,
                    trace_id=logger.tracer.get_trace_id(),
                    language=language
                )
            target_id = target_user_id
        else:
            target_id = user_id

        session_service = container.session_service()
        result = await session_service.get_sessions(
            user_id=target_id,
            status_filter=status,
            language=language,
            requester_role=user_role,
            client_ip=client_ip,
            db=db
        )

        logger.info("Sessions retrieved successfully", context={
            "user_id": user_id,
            "target_user_id": target_id,
            "client_ip": client_ip,
            "status_filter": status,
            "session_count": len(result["sessions"])
        })

        message_key = "sessions.active_retrieved" if status == "active" else "sessions.all_retrieved"
        return StandardResponse.success(
            data={
                "sessions": result["sessions"],
                "notification_sent": result["notification_sent"]
            },
            message=get_message(message_key, language=language),
            code=status.HTTP_200_OK
        )

    except InvalidCredentialsError as e:
        logger.error("Invalid credentials in get sessions", context={
            "error": e.message,
            "user_id": user_id,
            "target_user_id": target_id,
            "client_ip": client_ip,
            "error_code": e.error_code
        })
        return ErrorResponse(
            detail=e.message,
            message=e.message,
            error_code=e.error_code,
            status="error",
            metadata=e.details
        )
    except UnauthorizedAccessError as e:
        logger.error("Unauthorized access in get sessions", context={
            "error": e.message,
            "user_id": user_id,
            "target_user_id": target_id,
            "client_ip": client_ip,
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
        logger.error("Unexpected error in get sessions", context={
            "error": str(e),
            "user_id": user_id,
            "target_user_id": target_id,
            "client_ip": client_ip
        })
        return ErrorResponse(
            detail=str(e),
            message=get_message("server.error", language=language),
            error_code="SERVER_ERROR",
            status="error"
        )