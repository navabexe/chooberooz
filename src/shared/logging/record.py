# Path: src/shared/logging/record.py
import logging
from typing import Any, Dict, Optional
from src.shared.utilities.types import TraceId


class CustomLogRecord(logging.LogRecord):
    """Custom LogRecord with additional attributes for trace_id, span_id, and context."""

    def __init__(self, name: str, level: int, pathname: str, lineno: int,
                 msg: Any, args: tuple, exc_info: Any, func: str = None, sinfo: str = None,
                 **kwargs) -> None:
        super().__init__(name, level, pathname, lineno, msg, args, exc_info, func, sinfo)
        self.trace_id: Optional[TraceId] = kwargs.get("trace_id", None)
        self.span_id: Optional[str] = kwargs.get("span_id", None)
        self.context: Dict[str, Any] = kwargs.get("context", {})