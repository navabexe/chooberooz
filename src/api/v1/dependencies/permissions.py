# Path: src/infrastructure/security/permissions.py
from src.shared.security.permissions_loader import get_scopes_for_role
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.errors.domain.security import UnauthorizedAccessError, InvalidTokenError
from src.shared.utilities.constants import HttpStatus, DomainErrorCode

logger = LoggingService(LogConfig())


async def check_permissions(role: str, required_scope: str, vendor_status: str = None):
    """
    Check if the given role has the required permission scope.

    Args:
        role: The role to check permissions for.
        required_scope: The required permission scope (e.g., "write:otp").
        vendor_status: Optional vendor status for vendor-specific permissions.

    Returns:
        str: The role if permissions are sufficient.

    Raises:
        UnauthorizedAccessError: If the role lacks the required scope.
        InvalidTokenError: If permission check fails due to invalid data.
    """
    try:
        scopes = get_scopes_for_role(role, vendor_status)
        logger.info("Checking permissions", context={"role": role, "required_scope": required_scope, "scopes": scopes})
        if required_scope not in scopes:
            raise UnauthorizedAccessError(
                resource=required_scope,
                error_code=DomainErrorCode.UNAUTHORIZED_ACCESS.value,
                message="Insufficient permissions",
                status_code=HttpStatus.FORBIDDEN.value,
                trace_id=logger.tracer.get_trace_id(),
                details={"role": role, "required_scope": required_scope},
                language="en"
            )
        return role
    except Exception as e:
        logger.error("Failed to check permissions", context={"error": str(e), "role": role})
        raise InvalidTokenError(
            error_code="INVALID_PERMISSION_DATA",
            message="Invalid role or permission data",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"error": str(e), "role": role},
            language="en"
        )