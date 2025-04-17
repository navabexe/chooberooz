# Path: src/shared/logging/config.py
from pydantic import BaseModel
from pathlib import Path
from ..utilities.constants import LogLevel


class LogConfig(BaseModel):
    """Configuration for logging service."""

    level: LogLevel = LogLevel.INFO.value  # Default log level
    enable_console: bool = True
    enable_file: bool = True
    enable_elasticsearch: bool = False  # Disabled by default
    file_path: str = str(Path("logs/app.log"))
    max_file_size: int = 10 * 1024 * 1024  # 10 MB
    backup_count: int = 5

    class Config:
        arbitrary_types_allowed = True
        use_enum_values = True