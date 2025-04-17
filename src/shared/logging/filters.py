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
        if hasattr(record, "extra_context") and isinstance(record.extra_context, dict):
            for key, value in record.extra_context.items():
                if key.lower() in self.SENSITIVE_FIELDS and isinstance(value, str):
                    record.extra_context[key] = sanitize_data(value)
        return True