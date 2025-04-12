import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.shared.config.settings import settings

# File output path
BASE_LOG_DIR = Path(__file__).resolve().parent.parent.parent / "logs"
BASE_LOG_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = BASE_LOG_DIR / f"senama_{datetime.now().strftime('%Y%m%d')}.log"

# Colors for terminal logs
COLOR_MAP = {
    "DEBUG": "\033[94m",  # Blue
    "INFO": "\033[92m",  # Green
    "WARNING": "\033[93m",  # Yellow
    "ERROR": "\033[91m",  # Red
    "CRITICAL": "\033[95m",  # Magenta
    "ENDC": "\033[0m"
}


class SafeFormatter(logging.Formatter):
    def format(self, record):
        if not hasattr(record, "context"):
            record.context = {}
        return super().format(record)


class ColorFormatter(SafeFormatter):
    def format(self, record):
        levelname = record.levelname
        color = COLOR_MAP.get(levelname, "")
        endc = COLOR_MAP["ENDC"]
        record.levelname = f"{color}{levelname}{endc}"
        return super().format(record)


# Create logger
logger = logging.getLogger("senama")
logger.setLevel(logging.DEBUG if settings.ENVIRONMENT == "development" else logging.INFO)
logger.propagate = False

# Console handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(ColorFormatter('[%(asctime)s] %(levelname)s | %(message)s | context=%(context)s'))
logger.addHandler(console_handler)

# File handler
file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
file_handler.setFormatter(SafeFormatter('[%(asctime)s] %(levelname)s | %(message)s | context=%(context)s'))
logger.addHandler(file_handler)


# Public Logging Functions
def _extra_context(extra: Optional[dict] = None):
    return {"context": extra or {}}


def create_log_data(
    entity_type: str,
    entity_id: str,
    action: str,
    ip: str,
    request_id: str = None,
    client_version: str = None,
    device_fingerprint: str = None,
    extra_data: dict = None
) -> dict:
    log_data = {
        "entity_type": entity_type,
        "entity_id": entity_id,
        "action": action,
        "ip": ip,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "client_version": client_version,
        "device_fingerprint": device_fingerprint
    }
    if extra_data:
        log_data.update(extra_data)
    if settings.ENVIRONMENT == "development" and extra_data:
        log_data["raw_data"] = extra_data
    return log_data


def log_debug(message: str, extra: Optional[dict] = None):
    logger.debug(message, extra=_extra_context(extra))


def log_info(message: str, extra: Optional[dict] = None):
    logger.info(message, extra=_extra_context(extra))


def log_warning(message: str, extra: Optional[dict] = None):
    logger.warning(message, extra=_extra_context(extra))


def log_error(message: str, extra: Optional[dict] = None, exc_info: bool = False):
    logger.error(message, extra=_extra_context(extra), exc_info=exc_info)


def log_critical(message: str, extra: Optional[dict] = None, exc_info: bool = False):
    logger.critical(message, extra=_extra_context(extra), exc_info=exc_info)