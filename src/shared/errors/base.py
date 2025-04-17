# Path: src/shared/errors/base.py
from typing import Optional, Dict, Any
from ..utilities.types import TraceId, ErrorDetails, LanguageCode
from ..utilities.helpers import generate_trace_id


class BaseError(Exception):
    """Base class for custom errors."""

    def __init__(
            self,
            error_code: str,
            message: str,
            status_code: int,
            trace_id: Optional[TraceId] = None,
            details: Optional[ErrorDetails] = None,
            language: LanguageCode = "en"
    ):
        self.error_code = error_code
        self.message = message
        self.status_code = status_code
        self.trace_id = trace_id or generate_trace_id()
        self.details = details or {}
        self.language = language
        super().__init__(self.message)

    def model_dump(self) -> Dict[str, Any]:
        """Serialize error to JSON-compatible dict."""
        return {
            "error_code": self.error_code,
            "message": self.message,
            "status_code": self.status_code,
            "trace_id": self.trace_id,
            "details": self.details,
            "language": self.language
        }