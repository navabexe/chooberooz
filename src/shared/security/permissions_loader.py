from functools import lru_cache
from typing import Optional, List, Dict

import yaml

from src.shared.config.settings import settings
from src.shared.utilities.logging import log_error, log_info


PERMISSIONS_PATH = settings.BASE_DIR / "src" / "shared" / "security" / "permissions_map.yaml"


@lru_cache()
def load_permissions_map() -> Dict[str, dict]:
    if not PERMISSIONS_PATH.exists():
        log_error("Permissions file not found", extra={"path": str(PERMISSIONS_PATH)})
        raise FileNotFoundError(f"Permissions file not found at: {PERMISSIONS_PATH}")

    try:
        with PERMISSIONS_PATH.open("r", encoding="utf-8") as f:
            permissions = yaml.safe_load(f)
            if not isinstance(permissions, dict):
                log_error("Invalid permissions file format", extra={"path": str(PERMISSIONS_PATH)})
                raise ValueError("Permissions file must contain a valid dictionary")
            log_info("Permissions map loaded", extra={"path": str(PERMISSIONS_PATH)})
            return permissions
    except yaml.YAMLError as e:
        log_error("Failed to parse permissions map", extra={"path": str(PERMISSIONS_PATH), "error": str(e)})
        raise ValueError(f"Failed to parse permissions YAML: {str(e)}")
    except Exception as e:
        log_error("Failed to load permissions map", extra={"path": str(PERMISSIONS_PATH), "error": str(e)})
        raise


def get_scopes_for_role(role: str, vendor_status: Optional[str] = None) -> List[str]:
    permissions = load_permissions_map()

    if role == "vendor":
        vendor_perms = permissions.get("vendor", {})
        if not isinstance(vendor_perms, dict):
            log_error("Invalid vendor permissions format", extra={"role": role})
            return []
        scopes = vendor_perms.get(vendor_status or "pending", [])
    else:
        scopes = permissions.get(role, [])

    if not isinstance(scopes, list):
        log_error("Scopes not in list format", extra={"role": role, "vendor_status": vendor_status})
        return []

    return scopes