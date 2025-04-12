from datetime import datetime, timezone
from typing import Optional, List
from uuid import uuid4

from src.shared.config.settings import settings
from src.shared.utilities.logging import log_info, log_error
from src.domain.authentication.models.token import UserJWTProfile, VendorJWTProfile


ALLOWED_LANGUAGES = ["fa", "en", "ar"]


def get_profile_language(role: str, user_data: Optional[dict], vendor_data: Optional[dict]) -> str:
    """Extract the preferred language from user or vendor profile, defaulting to 'fa'."""
    log_info("Extracting profile language", extra={"role": role})
    profile_data = user_data if role == "user" else vendor_data
    if profile_data and "preferred_languages" in profile_data and profile_data["preferred_languages"]:
        lang = profile_data["preferred_languages"][0]
        log_info("Found language in profile", extra={"language": lang, "allowed": ALLOWED_LANGUAGES})
        return lang if lang in ALLOWED_LANGUAGES else "fa"
    log_info("No language found in profile, defaulting to 'fa'")
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
    log_info("Building JWT payload", extra={
        "token_type": token_type,
        "role": role,
        "subject_id": subject_id,
        "expires_in": expires_in
    })

    now = int(datetime.now(timezone.utc).timestamp())
    exp = now + expires_in
    log_info("Calculated timestamps", extra={"iat": now, "exp": exp})

    effective_language = get_profile_language(role, user_data, vendor_data) or language
    log_info("Determined effective language", extra={"language": effective_language})

    jti = jti or str(uuid4())
    log_info("Generated or used JTI", extra={"jti": jti})

    effective_audience = audience or default_audience(token_type, role)
    log_info("Set audience", extra={"audience": effective_audience})

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
    log_info("Initialized base payload", extra={"payload": payload})

    if phone:
        payload["phone"] = phone
        log_info("Added phone to payload", extra={"phone": phone})
    if session_id:
        payload["session_id"] = session_id
        log_info("Added session_id to payload", extra={"session_id": session_id})
    if status is not None:
        payload["status"] = status
        log_info("Added status to payload", extra={"status": status})
    if phone_verified is not None:
        payload["phone_verified"] = phone_verified
        log_info("Added phone_verified to payload", extra={"phone_verified": phone_verified})
    if scopes:
        payload["scopes"] = scopes
        log_info("Added scopes to payload", extra={"scopes": scopes})
    if amr:
        payload["amr"] = amr
        log_info("Added amr to payload", extra={"amr": amr})
    if vendor_id:
        payload["vendor_id"] = vendor_id
        log_info("Added vendor_id to payload", extra={"vendor_id": vendor_id})

    if token_type in ["access", "refresh"]:
        if role == "user" and user_data:
            try:
                user_profile = UserJWTProfile(**user_data).model_dump()
                payload["user_profile"] = user_profile
                log_info("Added user profile to payload", extra={"user_profile": user_profile})
            except Exception as e:
                log_error("Failed to add user profile", extra={"error": str(e), "user_data": user_data})
                raise
        elif role == "vendor" and vendor_data:
            try:
                log_info("Attempting to build vendor profile", extra={"vendor_data": vendor_data})
                vendor_profile = VendorJWTProfile(**vendor_data).model_dump()
                payload["vendor_profile"] = vendor_profile
                log_info("Added vendor profile to payload", extra={"vendor_profile": vendor_profile})
            except Exception as e:
                log_error("Failed to add vendor profile", extra={"error": str(e), "vendor_data": vendor_data})
                raise

    log_info("Completed JWT payload", extra={"payload": payload})
    return payload


def default_audience(token_type: str, role: Optional[str] = None) -> List[str]:
    """Return the default audience based on token type and role."""
    log_info("Determining default audience", extra={"token_type": token_type, "role": role})
    if token_type == "access":
        audience = ["api", "vendor-panel"] if role == "vendor" else ["api"]
        log_info("Set audience for access token", extra={"audience": audience})
        return audience
    elif token_type == "refresh":
        audience = ["auth-service"]
        log_info("Set audience for refresh token", extra={"audience": audience})
        return audience
    elif token_type == "temp":
        audience = ["auth-temp"]
        log_info("Set audience for temp token", extra={"audience": audience})
        return audience
    else:
        log_error("Unknown token type for audience", extra={"token_type": token_type})
        raise ValueError(f"Unknown token type: {token_type}")