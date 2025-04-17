# Path: src/shared/i18n/messages.py
import json
from pathlib import Path

from src.shared.utilities.types import LanguageCode


def get_message(error_code: str, language: LanguageCode) -> str:
    """Get localized message for error code."""
    file_path = Path(__file__).parent / f"{language}.json"
    try:
        with file_path.open(encoding="utf-8") as f:
            messages = json.load(f)
        return messages.get(error_code, "")
    except FileNotFoundError:
        return ""