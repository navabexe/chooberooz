# Path: src/domain/authentication/jwt_utils.py
from datetime import datetime, timezone
from typing import Optional, List
from uuid import uuid4

from passlib.exc import InvalidTokenError

from src.shared.config.settings import settings
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.domain.authentication.models.token import UserJWTProfile, VendorJWTProfile

logger = LoggingService(LogConfig())

ALLOWED_LANGUAGES = ["fa", "en", "ar"]

def get_profile_language(role: str, user_data: Optional[dict], vendor_data: Optional[dict]) -> str:
    """Extract the preferred language from user or vendor profile, defaulting to 'fa'."""
    logger.info("Extracting profile language", context={"role": role})
    profile_data = user_data if role == "user" else vendor_data
    if profile_data and "preferred_languages" in profile_data and profile_data["preferred_languages"]:
        lang = profile_data["preferred_languages"][0]
        logger.info("Found language in profile", context={"language": lang, "allowed": ALLOWED_LANGUAGES})
        return lang if lang in ALLOWED_LANGUAGES else "fa"
    logger.info("No language found in profile, defaulting to 'fa'", context={})
    return "fa"

def build_jwt_payload(
    *,
    token_type: str,
    role: str,
    subject_id: str,
    phone: Optional[str] = None,
    status: Optional[str] = None,
    phone_verified: Optional[bool] = None,
    scopes: Optional[List[str]] = None,
    session_id: Optional[str] = None,
    user_data: Optional[dict] = None,
    vendor_data: Optional[dict] = None,
    vendor_id: Optional[str] = None,
    expires_in: int = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    issuer: str = "senama-auth",
    audience: Optional[List[str]] = None,
    amr: Optional[List[str]] = None,
    jti: Optional[str] = None,
    language: Optional[str] = "fa",
) -> dict:
    """Build a standardized JWT payload with the provided claims."""
    logger.info("Building JWT payload", context={
        "token_type": token_type,
        "role": role,
        "subject_id": subject_id,
        "expires_in": expires_in
    })

    now = int(datetime.now(timezone.utc).timestamp())
    exp = now + expires_in
    logger.info("Calculated timestamps", context={"iat": now, "exp": exp})

    effective_language = get_profile_language(role, user_data, vendor_data) or language
    logger.info("Determined effective language", context={"language": effective_language})

    jti = jti or str(uuid4())
    logger.info("Generated or used JTI", context={"jti": jti})

    effective_audience = audience or default_audience(token_type, role)
    logger.info("Set audience", context={"audience": effective_audience})

    payload = {
        "iss": issuer,
        "aud": effective_audience,
        "sub": subject_id,
        "jti": jti,
        "role": role,
        "token_type": token_type,
        "iat": now,
        "exp": exp,
        "language": effective_language,
    }
    logger.info("Initialized base payload", context={"payload": payload})

    if phone:
        payload["phone"] = phone
        logger.info("Added phone to payload", context={"phone": phone})
    if session_id:
        payload["session_id"] = session_id
        logger.info("Added session_id to payload", context={"session_id": session_id})
    if status is not None:
        payload["status"] = status
        logger.info("Added status to payload", context={"status": status})
    if phone_verified is not None:
        payload["phone_verified"] = phone_verified
        logger.info("Added phone_verified to payload", context={"phone_verified": phone_verified})
    if scopes:
        payload["scopes"] = scopes
        logger.info("Added scopes to payload", context={"scopes": scopes})
    if amr:
        payload["amr"] = amr
        logger.info("Added amr to payload", context={"amr": amr})
    if vendor_id:
        payload["vendor_id"] = vendor_id
        logger.info("Added vendor_id to payload", context={"vendor_id": vendor_id})

    if token_type in ["access", "refresh"]:
        if role == "user" and user_data:
            try:
                user_profile = UserJWTProfile(**user_data).model_dump()
                payload["user_profile"] = user_profile
                logger.info("Added user profile to payload", context={"user_profile": user_profile})
            except Exception as e:
                logger.error("Failed to add user profile", context={"error": str(e), "user_data": user_data})
                raise InvalidTokenError(
                    error_code="INVALID_TOKEN_PROFILE",
                    message=f"Failed to build user profile: {str(e)}",
                    status_code=400,
                    trace_id=logger.tracer.get_trace_id(),
                    details={"error": str(e)},
                    language="en"
                )
        elif role == "vendor" and vendor_data:
            try:
                logger.info("Attempting to build vendor profile", context={"vendor_data": vendor_data})
                vendor_profile = VendorJWTProfile(**vendor_data).model_dump()
                payload["vendor_profile"] = vendor_profile
                logger.info("Added vendor profile to payload", context={"vendor_profile": vendor_profile})
            except Exception as e:
                logger.error("Failed to add vendor profile", context={"error": str(e), "vendor_data": vendor_data})
                raise InvalidTokenError(
                    error_code="INVALID_TOKEN_PROFILE",
                    message=f"Failed to build vendor profile: {str(e)}",
                    status_code=400,
                    trace_id=logger.tracer.get_trace_id(),
                    details={"error": str(e)},
                    language="en"
                )

    logger.info("Completed JWT payload", context={"payload": payload})
    return payload

def default_audience(token_type: str, role: Optional[str] = None) -> List[str]:
    """Return the default audience based on token type and role."""
    logger.info("Determining default audience", context={"token_type": token_type, "role": role})
    if token_type == "access":
        audience = ["api", "vendor-panel"] if role == "vendor" else ["api"]
        logger.info("Set audience for access token", context={"audience": audience})
        return audience
    elif token_type == "refresh":
        audience = ["auth-service"]
        logger.info("Set audience for refresh token", context={"audience": audience})
        return audience
    elif token_type == "temp":
        audience = ["auth-temp"]
        logger.info("Set audience for temp token", context={"audience": audience})
        return audience
    else:
        logger.error("Unknown token type for audience", context={"token_type": token_type})
        raise InvalidTokenError(
            error_code="INVALID_TOKEN_TYPE",
            message=f"Unknown token type: {token_type}",
            status_code=400,
            trace_id=logger.tracer.get_trace_id(),
            details={"token_type": token_type},
            language="en"
        )