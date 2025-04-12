from fastapi import HTTPException, status
from src.shared.security.permissions_loader import get_scopes_for_role
from src.shared.utilities.logging import log_info, log_error

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
        HTTPException: If the role lacks the required scope or if permission check fails.
    """
    try:
        scopes = get_scopes_for_role(role, vendor_status)
        log_info("Checking permissions", extra={"role": role, "required_scope": required_scope, "scopes": scopes})
        if required_scope not in scopes:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
        return role
    except Exception as e:
        log_error("Failed to check permissions", extra={"error": str(e), "role": role})
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid role or permission data")