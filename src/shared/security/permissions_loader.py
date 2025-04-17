# Path: src/shared/security/permissions_loader.py
from functools import lru_cache
from typing import Optional, List, Dict
import yaml
from src.shared.config.settings import settings
from src.shared.i18n.messages import get_message
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig
from src.shared.errors.base import BaseError
from src.shared.errors.domain.security import UnauthorizedAccessError
from src.shared.utilities.types import LanguageCode
from src.shared.utilities.constants import HttpStatus, DomainErrorCode

logger = LoggingService(LogConfig())

PERMISSIONS_PATH = settings.BASE_DIR / "src" / "shared" / "security" / "permissions_map.yaml"

@lru_cache()
def load_permissions_map() -> Dict[str, dict]:
    """Load permissions map from YAML file."""
    if not PERMISSIONS_PATH.exists():
        logger.error("Permissions file not found", context={"path": str(PERMISSIONS_PATH)})
        raise BaseError(
            error_code="FILE_NOT_FOUND",
            message=f"Permissions file not found at: {PERMISSIONS_PATH}",
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"path": str(PERMISSIONS_PATH)},
            language="en"
        )

    try:
        with PERMISSIONS_PATH.open("r", encoding="utf-8") as f:
            permissions = yaml.safe_load(f)
            if not isinstance(permissions, dict):
                logger.error("Invalid permissions file format", context={"path": str(PERMISSIONS_PATH)})
                raise BaseError(
                    error_code="INVALID_PERMISSIONS_FORMAT",
                    message="Permissions file must contain a valid dictionary",
                    status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
                    trace_id=logger.tracer.get_trace_id(),
                    details={"path": str(PERMISSIONS_PATH)},
                    language="en"
                )
            logger.info("Permissions map loaded", context={"path": str(PERMISSIONS_PATH)})
            return permissions
    except yaml.YAMLError as e:
        logger.error("Failed to parse permissions map", context={"path": str(PERMISSIONS_PATH), "error": str(e)})
        raise BaseError(
            error_code="INVALID_PERMISSIONS_YAML",
            message=f"Failed to parse permissions YAML: {str(e)}",
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"path": str(PERMISSIONS_PATH), "error": str(e)},
            language="en"
        )
    except Exception as e:
        logger.error("Failed to load permissions map", context={"path": str(PERMISSIONS_PATH), "error": str(e)})
        raise BaseError(
            error_code="PERMISSIONS_LOAD_FAILED",
            message=f"Failed to load permissions: {str(e)}",
            status_code=HttpStatus.INTERNAL_SERVER_ERROR.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"path": str(PERMISSIONS_PATH), "error": str(e)},
            language="en"
        )

def get_scopes_for_role(role: str, vendor_status: Optional[str] = None) -> List[str]:
    """Get permission scopes for a role."""
    permissions = load_permissions_map()

    if role == "vendor":
        vendor_perms = permissions.get("vendor", {})
        if not isinstance(vendor_perms, dict):
            logger.error("Invalid vendor permissions format", context={"role": role})
            return []
        scopes = vendor_perms.get(vendor_status or "pending", [])
    else:
        scopes = permissions.get(role, [])

    if not isinstance(scopes, list):
        logger.error("Scopes not in list format", context={"role": role, "vendor_status": vendor_status})
        return []

    return scopes

def check_permissions(role: str, action: str, resource: str, vendor_status: Optional[str] = None, language: LanguageCode = "en") -> None:
    """Check if role has permission for action on resource."""
    scopes = get_scopes_for_role(role, vendor_status)
    required_scope = f"{action}:{resource}"

    if "*" in scopes:
        return

    if required_scope not in scopes:
        logger.warning("Access denied", context={
            "role": role,
            "status": vendor_status,
            "action": action,
            "resource": resource,
            "required_scope": required_scope
        })
        raise UnauthorizedAccessError(
            resource=required_scope,
            error_code=DomainErrorCode.UNAUTHORIZED_ACCESS.value,
            message=get_message("access.denied", language=language),
            status_code=HttpStatus.FORBIDDEN.value,
            trace_id=logger.tracer.get_trace_id(),
            details={"role": role, "required_scope": required_scope},
            language=language
        )