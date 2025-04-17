# Path: src/shared/utilities/types.py
from typing import Dict, Any, Union, Literal
from uuid import UUID

# Type for error codes (e.g., "PRODUCT_NOT_FOUND")
ErrorCode = str

# Type for trace IDs (UUID for distributed tracing)
TraceId = UUID

# Type for error details (flexible key-value pairs)
ErrorDetails = Dict[str, Any]

# Type for log levels
LogLevel = Union["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

# Type for language codes (e.g., "fa", "en")
LanguageCode = Literal["fa", "en"]