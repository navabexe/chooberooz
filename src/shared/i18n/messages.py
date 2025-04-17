import json
from pathlib import Path

from src.shared.utilities.types import LanguageCode
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig

logger = LoggingService(LogConfig())


def get_message(error_code: str, language: LanguageCode) -> str:
    """Get localized message for error code."""
    file_path = Path(__file__).parent / f"{language}.json"
    logger.info("Loading i18n file", context={"file_path": str(file_path), "error_code": error_code})
    try:
        with file_path.open(encoding="utf-8") as f:
            messages = json.load(f)
        message = messages.get(error_code, "")
        if not message:
            logger.warning("Message not found for error code", context={"error_code": error_code, "language": language})
        return message
    except FileNotFoundError:
        logger.error("i18n file not found", context={"file_path": str(file_path), "language": language})
        return ""
    except Exception as e:
        logger.error("Error loading i18n file", context={"file_path": str(file_path), "error": str(e)})
        return ""