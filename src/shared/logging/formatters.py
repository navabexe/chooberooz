# Path: src/shared/logging/formatters.py
import json
import logging
from datetime import datetime
from typing import Any, Dict
from uuid import UUID
from colorama import Fore, Style, init
from src.shared.utilities.time import utc_now

# Initialize colorama for Windows compatibility
init()

class JsonFormatter(logging.Formatter):
    """Formatter for JSON-structured logs."""

    def _serialize_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Convert non-serializable objects in context to JSON-compatible types."""
        serialized = {}
        for key, value in context.items():
            if isinstance(value, UUID):
                serialized[key] = str(value)
            elif isinstance(value, datetime):
                serialized[key] = value.isoformat() + "Z"
            elif isinstance(value, (dict, list, str, int, float, bool, type(None))):
                serialized[key] = value
            else:
                serialized[key] = str(value)
        return serialized

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": utc_now().isoformat() + "Z",
            "level": record.levelname,
            "message": record.getMessage(),
            "trace_id": str(record.trace_id) if record.trace_id else None,
            "span_id": str(record.span_id) if record.span_id else None,
            "context": self._serialize_context(getattr(record, "context", {})),
            "module": record.module,
            "funcName": record.funcName,
            "lineno": record.lineno
        }
        return json.dumps(log_data, ensure_ascii=False)


class ConsoleFormatter(logging.Formatter):
    """Formatter for human-readable console logs with color."""

    # Define colors for each log level
    LEVEL_COLORS = {
        "DEBUG": Fore.CYAN,
        "INFO": Fore.WHITE,
        "WARNING": Fore.YELLOW,
        "ERROR": Fore.RED,
        "CRITICAL": Fore.MAGENTA + Style.BRIGHT
    }

    def format(self, record: logging.LogRecord) -> str:
        """Format log record for console output with color."""
        timestamp = utc_now().isoformat() + "Z"
        level = record.levelname
        message = record.getMessage()
        trace_id = str(record.trace_id) if record.trace_id else "-"
        context = getattr(record, "context", {})
        context_str = f" | context={context}" if context else ""

        # Apply color based on log level
        color = self.LEVEL_COLORS.get(level, Fore.WHITE)
        formatted_message = f"{color}[{timestamp}] {level} | {message} | trace_id={trace_id}{context_str}{Style.RESET_ALL}"
        return formatted_message