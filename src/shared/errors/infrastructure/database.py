# Path: src/shared/errors/infrastructure/database.py
from ..base import BaseError
from ...utilities.constants import InfraErrorCode, HttpStatus
from ...utilities.helpers import generate_trace_id
from ...utilities.types import TraceId, ErrorDetails, LanguageCode


class DatabaseConnectionError(BaseError):
    """Error when database connection fails."""

    def __init__(
            self,
            db_type: str,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=InfraErrorCode.DATABASE_CONNECTION.value,
            message=f"Failed to connect to {db_type} database.",
            status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"db_type": db_type},
            language=language
        )


class QueryTimeoutError(BaseError):
    """Error when database query times out."""

    def __init__(
            self,
            db_type: str,
            query: str,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=InfraErrorCode.QUERY_TIMEOUT.value,
            message=f"Query timeout for {db_type} database.",
            status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"db_type": db_type, "query": query},
            language=language
        )


class MongoError(BaseError):
    """Error for MongoDB-specific issues."""

    def __init__(
            self,
            operation: str,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=InfraErrorCode.MONGO_ERROR.value,
            message=f"MongoDB error during {operation}.",
            status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"operation": operation},
            language=language
        )


class CacheError(BaseError):
    """Error for cache-related issues."""

    def __init__(
            self,
            operation: str,
            error_code: str,
            message: str,
            status_code: int,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=error_code,
            message=message,
            status_code=status_code,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"operation": operation},
            language=language
        )