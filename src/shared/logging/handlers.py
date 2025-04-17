# Path: src/shared/logging/handlers.py
import logging
import logging.handlers
from pathlib import Path
import sys
from .config import LogConfig
from .formatters import JsonFormatter, ConsoleFormatter
from .filters import SensitiveDataFilter


class LogHandlerFactory:
    """Factory for creating log handlers."""

    @staticmethod
    def create_console_handler(config: LogConfig) -> logging.Handler:
        """Create console handler."""
        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setLevel(config.level)
        handler.setFormatter(ConsoleFormatter())
        handler.addFilter(SensitiveDataFilter())
        return handler

    @staticmethod
    def create_file_handler(config: LogConfig) -> logging.Handler:
        """Create rotating file handler."""
        Path(config.file_path).parent.mkdir(parents=True, exist_ok=True)
        handler = logging.handlers.RotatingFileHandler(
            filename=config.file_path,
            maxBytes=config.max_file_size,
            backupCount=config.backup_count,
            encoding="utf-8"
        )
        handler.setLevel(config.level)
        handler.setFormatter(JsonFormatter())
        handler.addFilter(SensitiveDataFilter())
        return handler

    @classmethod
    def get_handlers(cls, config: LogConfig) -> list[logging.Handler]:
        """
        Get all enabled handlers.

        Args:
            config: Logging configuration.

        Returns:
            List of enabled log handlers.

        Note:
            Elasticsearch handler is disabled. To enable, implement create_elasticsearch_handler.
        """
        handlers = []
        if config.enable_console:
            handlers.append(cls.create_console_handler(config))
        if config.enable_file:
            handlers.append(cls.create_file_handler(config))
        # Elasticsearch handler disabled due to missing dependency
        return handlers