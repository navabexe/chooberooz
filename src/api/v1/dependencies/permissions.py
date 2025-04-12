# src/api/v1/dependencies/permissions.py
from fastapi import HTTPException, status
from src.shared.security.permissions_loader import get_scopes_for_role
from src.shared.utilities.logging import log_info

async def check_permissions(role: str, required_scope: str, vendor_status: str = None):
    """Check if the role has the required permission scope."""
    scopes = get_scopes_for_role(role, vendor_status)
    log_info("Checking permissions", extra={"role": role, "required_scope": required_scope, "scopes": scopes})
    if required_scope not in scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient permissions")
    return role