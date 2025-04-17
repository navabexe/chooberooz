import logging
from typing import Optional, Dict, Any
from .config import LogConfig
from .handlers import LogHandlerFactory
from .tracers import Tracer
from ..utilities.types import TraceId
from ..utilities.constants import LogLevel


class LoggingService:
    """Central service for structured logging operations."""

    def __init__(self, config: LogConfig, tracer: Tracer = None):
        """Initialize logging service with configuration and tracer."""
        self.logger = logging.getLogger("marketplace")
        self.logger.setLevel(getattr(logging, config.level))
        self.tracer = tracer or Tracer()

        # Clear existing handlers
        self.logger.handlers.clear()

        # Add new handlers
        for handler in LogHandlerFactory.get_handlers(config):
            self.logger.addHandler(handler)

        # Debug log to check tracer initialization
        self.logger.debug(f"Tracer initialized with trace_id: {self.tracer.get_trace_id()}")

    def set_log_level(self, level: str) -> None:
        """Change the logging level dynamically."""
        if level not in LogLevel.__members__:
            raise ValueError(f"Invalid log level: {level}. Valid levels: {list(LogLevel.__members__)}")
        log_level = getattr(logging, level)
        self.logger.setLevel(log_level)
        for handler in self.logger.handlers:
            handler.setLevel(level)
        self.info(f"Log level changed to {level}", context={"new_level": level})

    def log(
            self,
            level: str,
            message: str,
            context: Optional[Dict[str, Any]] = None,
            trace_id: Optional[TraceId] = None
    ) -> None:
        """Log message with specified level and context."""
        extra = {
            "extra_context": context or {},
            "extra_trace_id": trace_id or self.tracer.get_trace_id(),
            "extra_span_id": self.tracer.get_span_id()
        }
        log_level = getattr(logging, level)
        self.logger.log(log_level, message, extra=extra)

    def debug(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Log debug message."""
        self.log(LogLevel.DEBUG.value, message, context)

    def info(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Log info message."""
        self.log(LogLevel.INFO.value, message, context)

    def warning(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Log warning message."""
        self.log(LogLevel.WARNING.value, message, context)

    def error(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Log error message."""
        self.log(LogLevel.ERROR.value, message, context)

    def critical(self, message: str, context: Optional[Dict[str, Any]] = None) -> None:
        """Log critical message."""
        self.log(LogLevel.CRITICAL.value, message, context)