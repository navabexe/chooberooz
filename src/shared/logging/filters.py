# Path: src/shared/logging/filters.py
import logging

from src.shared.utilities.helpers import sanitize_data


class SensitiveDataFilter(logging.Filter):
    """Filter to mask sensitive data in logs."""

    SENSITIVE_FIELDS = {
        "credit_card",
        "password",
        "token",
        "api_key",
        "phone_number",
        "email"
    }

    def filter(self, record: logging.LogRecord) -> bool:
        """Mask sensitive fields in log record."""
        if hasattr(record, "context") and isinstance(record.context, dict):
            for key, value in record.context.items():
                if key.lower() in self.SENSITIVE_FIELDS and isinstance(value, str):
                    record.context[key] = sanitize_data(value)
        return True