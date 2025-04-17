# Path: src/domain/authentication/services/complete_profile_service.py
from typing import Optional, List
from datetime import datetime, timezone
from uuid import uuid4
from bson import ObjectId
from fastapi import Request
from motor.motor_asyncio import AsyncIOMotorDatabase
from redis.asyncio import Redis
import json
from src.shared.base_service.base_service import BaseService
from src.shared.config.settings import settings
from src.shared.i18n.messages import get_message
from src.shared.security.token import decode_token, generate_access_token, generate_refresh_token
from src.shared.utilities.network import extract_client_ip
from src.domain.notification.services.notification_service import NotificationService
from src.domain.authentication.services.session_service import SessionService
from src.infrastructure.storage.nosql.repositories.user_repository import UserRepository
from src.infrastructure.storage.cache.repositories.otp_repository import OTPRepository
from src.shared.errors.domain.security import InvalidCredentialsError, UnauthorizedAccessError, RateLimitExceededError
from src.shared.utilities.time import utc_now
from src.shared.utilities.types import LanguageCode
from src.shared.utilities.constants import HttpStatus, DomainErrorCode


class CompleteProfileService(BaseService):
    """Service for completing user or vendor profiles."""

    def __init__(
            self,
            user_repo: UserRepository,
            otp_repo: OTPRepository,
            notification_service: NotificationService,
            session_service: SessionService
    ):
        super().__init__()
        self.user_repo = user_repo
        self.otp_repo = otp_repo
        self.notification_service = notification_service
        self.session_service = session_service

    async def validate_business_categories(self, category_ids: List[str], language: LanguageCode):
        """Validate business category IDs."""
        query_ids = [ObjectId(cid) for cid in category_ids if ObjectId.is_valid(cid)]
        existing = await self.user_repo.find("business_categories", {"_id": {"$in": query_ids}})
        found_ids = {str(doc["_id"]) for doc in existing}
        invalid = set(category_ids) - found_ids
        if invalid:
            raise InvalidCredentialsError(
                error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
                message=get_message("invalid.business_category", language=language),
                status_code=HttpStatus.BAD_REQUEST.value,
                trace_id=self.logger.tracer.get_trace_id(),
                details={"invalid_ids": list(invalid)},
                language=language
            )

    async def normalize_vendor_data(self, data: dict) -> dict:
        """Normalize vendor data with default values."""
        return {
            **data,
            "logo_urls": data.get("logo_urls", []),
            "banner_urls": data.get("banner_urls", []),
            "preferred_languages": data.get("preferred_languages", []),
            "account_types": data.get("account_types", []),
            "show_followers_publicly": data.get("show_followers_publicly", True),
        }

    async def complete_profile(
            self,
            temporary_token: str,
            first_name: Optional[str] = None,
            last_name: Optional[str] = None,
            email: Optional[str] = None,
            business_name: Optional[str] = None,
            city: Optional[str] = None,
            province: Optional[str] = None,
            location: Optional[dict] = None,
            address: Optional[str] = None,
            business_category_ids: Optional[List[str]] = None,
            visibility: Optional[str] = "COLLABORATIVE",
            vendor_type: Optional[str] = None,
            languages: Optional[List[str]] = None,
            request: Optional[Request] = None,
            language: LanguageCode = settings.DEFAULT_LANGUAGE,
            redis: Redis = None,
            db: AsyncIOMotorDatabase = None,
            request_id: Optional[str] = None,
            client_version: Optional[str] = None,
            device_fingerprint: Optional[str] = None
    ) -> dict:
        """Complete user or vendor profile."""
        context = {
            "entity_type": "profile",
            "entity_id": "unknown",
            "action": "completed",
            "endpoint": "/api/v1/complete-profile",
            "request_id": request_id
        }
        client_ip = await extract_client_ip(request) if request else "unknown"

        async def operation():
            # Rate limiting
            rate_limit_key = f"profile_complete_limit:{temporary_token}"
            attempts = await self.otp_repo.incr(rate_limit_key)
            await self.otp_repo.expire(rate_limit_key, settings.BLOCK_DURATION_OTP)
            if attempts > settings.MAX_PROFILE_COMPLETE_ATTEMPTS:
                raise RateLimitExceededError(
                    endpoint="complete_profile",
                    limit=settings.MAX_PROFILE_COMPLETE_ATTEMPTS,
                    error_code=DomainErrorCode.RATE_LIMIT_EXCEEDED.value,
                    message=get_message("profile.too_many", language=language),
                    status_code=HttpStatus.TOO_MANY_REQUESTS.value,
                    trace_id=self.logger.tracer.get_trace_id(),
                    details={"token": temporary_token},
                    language=language
                )

            # Validate token
            payload = await decode_token(temporary_token, token_type="temp", redis=redis)
            phone = payload.get("sub")
            role = payload.get("role")
            jti = payload.get("jti")
            context["entity_id"] = phone

            if not phone or role not in ["user", "vendor"]:
                raise UnauthorizedAccessError(
                    resource="profile_completion",
                    error_code=DomainErrorCode.UNAUTHORIZED_ACCESS.value,
                    message=get_message("token.invalid", language=language),
                    status_code=HttpStatus.UNAUTHORIZED.value,
                    trace_id=self.logger.tracer.get_trace_id(),
                    details={},
                    language=language
                )

            temp_key = f"temp_token:{jti}"
            stored_phone = await self.otp_repo.get(temp_key)
            if stored_phone != phone:
                raise InvalidCredentialsError(
                    error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
                    message=get_message("otp.expired", language=language),
                    status_code=HttpStatus.BAD_REQUEST.value,
                    trace_id=self.logger.tracer.get_trace_id(),
                    details={},
                    language=language
                )

            # Validate role-specific inputs
            if role == "user" and any(
                    [business_name, business_category_ids, city, province, location, address, vendor_type]):
                raise UnauthorizedAccessError(
                    resource="vendor_fields",
                    error_code=DomainErrorCode.UNAUTHORIZED_ACCESS.value,
                    message=get_message("auth.forbidden", language=language),
                    status_code=HttpStatus.FORBIDDEN.value,
                    trace_id=self.logger.tracer.get_trace_id(),
                    details={"invalid_fields": [k for k, v in locals().items() if
                                                v and k in ["business_name", "business_category_ids", "city",
                                                            "province", "location", "address", "vendor_type"]]},
                    language=language
                )
            if role == "vendor" and not business_name:
                raise InvalidCredentialsError(
                    error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
                    message=get_message("vendor.not_eligible", language=language),
                    status_code=HttpStatus.BAD_REQUEST.value,
                    trace_id=self.logger.tracer.get_trace_id(),
                    details={"missing_field": "business_name"},
                    language=language
                )

            # Find user
            collection = f"{role}s"
            user = await self.user_repo.find_user(collection, phone)
            if not user or user.get("status") not in ["incomplete", "pending"]:
                raise InvalidCredentialsError(
                    error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
                    message=get_message(f"{role}.not_eligible", language=language),
                    status_code=HttpStatus.BAD_REQUEST.value,
                    trace_id=self.logger.tracer.get_trace_id(),
                    details={"status": user.get("status") if user else None},
                    language=language
                )

            user_id = str(user["_id"])
            update_data = {"updated_at": utc_now(),}

            # Update user data
            if role == "user":
                if not first_name or not last_name:
                    raise InvalidCredentialsError(
                        error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
                        message=get_message("auth.profile.incomplete", language=language),
                        status_code=HttpStatus.BAD_REQUEST.value,
                        trace_id=self.logger.tracer.get_trace_id(),
                        details={
                            "missing_fields": [k for k, v in {"first_name": first_name, "last_name": last_name}.items()
                                               if not v]},
                        language=language
                    )
                update_data.update({
                    "first_name": first_name.strip(),
                    "last_name": last_name.strip(),
                    "email": email.strip().lower() if email else None,
                    "preferred_languages": languages or user.get("preferred_languages", []),
                    "status": "active"
                })

            if role == "vendor":
                if first_name:
                    update_data["first_name"] = first_name.strip()
                if last_name:
                    update_data["last_name"] = last_name.strip()
                if business_category_ids:
                    await self.validate_business_categories(business_category_ids, language)
                if visibility and visibility not in settings.VALID_VISIBILITY:
                    raise InvalidCredentialsError(
                        error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
                        message=get_message("invalid.visibility", language=language),
                        status_code=HttpStatus.BAD_REQUEST.value,
                        trace_id=self.logger.tracer.get_trace_id(),
                        details={"valid_options": settings.VALID_VISIBILITY},
                        language=language
                    )
                if vendor_type and vendor_type not in settings.VALID_VENDOR_TYPES:
                    raise InvalidCredentialsError(
                        error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
                        message=get_message("invalid.vendor_type", language=language),
                        status_code=HttpStatus.BAD_REQUEST.value,
                        trace_id=self.logger.tracer.get_trace_id(),
                        details={"valid_options": settings.VALID_VENDOR_TYPES},
                        language=language
                    )
                update_data.update({
                    "business_name": business_name.strip(),
                    "city": city.strip() if city else None,
                    "province": province.strip() if province else None,
                    "location": location,
                    "address": address.strip() if address else None,
                    "visibility": visibility,
                    "vendor_type": vendor_type,
                    "preferred_languages": languages or user.get("preferred_languages", []),
                    "business_category_ids": business_category_ids or [],
                    "status": "pending" if all(
                        [business_name, city, province, location, address, business_category_ids]) else "incomplete"
                })

            # Update user in database
            await self.user_repo.update_user(collection, user_id, update_data)
            updated_user = await self.user_repo.find_user(collection, phone)
            if not updated_user:
                raise InvalidCredentialsError(
                    error_code=DomainErrorCode.INVALID_CREDENTIALS.value,
                    message=get_message("server.error", language=language),
                    status_code=HttpStatus.BAD_REQUEST.value,
                    trace_id=self.logger.tracer.get_trace_id(),
                    details={},
                    language=language
                )

            # Clear temporary token
            await self.otp_repo.delete(temp_key)
            await self.session_service.delete_incomplete_sessions(user_id)

            # Generate tokens
            session_id = str(uuid4())
            token_lang = (languages or user.get("preferred_languages") or [language])[0]

            if role == "vendor":
                updated_user = await self.normalize_vendor_data(updated_user)

            access_token = await generate_access_token(
                user_id=user_id,
                role=role,
                session_id=session_id,
                language=token_lang,
                vendor_id=user_id if role == "vendor" else None
            )

            refresh_token = None
            if role == "user" and updated_user.get("status") == "active":
                refresh_token, refresh_jti = await generate_refresh_token(user_id, role, session_id, return_jti=True)
                session_key = f"sessions:{user_id}:{session_id}"
                session_data = {
                    "ip": client_ip,
                    "created_at": datetime.utcnow().isoformat(),
                    "device_name": "Unknown Device",
                    "device_type": "Desktop",
                    "os": "Unknown",
                    "browser": "Unknown",
                    "user_agent": request.headers.get("User-Agent", "Unknown") if request else "Unknown",
                    "location": "Unknown",
                    "status": "active",
                    "jti": session_id
                }
                # Convert values to strings for Redis compatibility
                session_data_cleaned = {k: json.dumps(v) if isinstance(v, (dict, list)) else str(v) for k, v in
                                        session_data.items()}
                await self.otp_repo.hset(session_key, mapping=session_data_cleaned)
                await self.otp_repo.expire(session_key, settings.SESSION_EXPIRY)
                await self.otp_repo.setex(
                    f"refresh_tokens:{user_id}:{refresh_jti}",
                    settings.REFRESH_TOKEN_EXPIRE_DAYS * 86400,
                    "active"
                )

            # Log audit
            audit_data = {
                "user_id": user_id,
                "role": role,
                "status": updated_user["status"],
                "ip": client_ip,
                "session_id": session_id,
                "device_fingerprint": device_fingerprint,
                "request_id": request_id,
                "client_version": client_version
            }
            await self.user_repo.log_audit(f"{role}_profile_completed", audit_data)
            self.logger.info("Profile completed", context=audit_data)

            # Send notifications
            notification_sent = await self.notification_service.send(
                receiver_id=user_id,
                receiver_type=role,
                template_key="user.profile_completed" if role == "user" else "vendor.profile_pending",
                variables={"name": first_name or business_name, "phone": phone},
                reference_type="profile",
                reference_id=user_id,
                language=language,
                return_bool=True,
                db=db
            )
            if role == "vendor" and updated_user["status"] == "pending":
                await self.notification_service.send(
                    receiver_id="admin",
                    receiver_type="admin",
                    template_key="admin.vendor_submitted",
                    variables={"vendor_name": business_name, "vendor_phone": phone},
                    reference_type="profile",
                    reference_id=user_id,
                    language=language,
                    return_bool=False,
                    db=db
                )
            elif role == "user" and updated_user["status"] == "active":
                await self.notification_service.send(
                    receiver_id="admin",
                    receiver_type="admin",
                    template_key="admin.user_joined",
                    variables={"user_name": first_name, "user_phone": phone},
                    reference_type="profile",
                    reference_id=user_id,
                    language=language,
                    return_bool=False,
                    db=db
                )

            response_data = {
                "access_token": access_token,
                "status": updated_user["status"],
                "notification_sent": notification_sent,
                "phone": phone
            }
            if refresh_token:
                response_data["refresh_token"] = refresh_token

            return {
                "data": response_data,
                "message": get_message(
                    "auth.profile.pending" if updated_user["status"] == "pending" else "auth.profile.completed",
                    language=language
                )
            }

        return await self.execute(operation, context, language)