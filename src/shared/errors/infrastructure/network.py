# Path: src/shared/errors/infrastructure/network.py
from ..base import BaseError
from ...utilities.constants import InfraErrorCode, HttpStatus
from ...utilities.helpers import generate_trace_id
from ...utilities.types import TraceId, ErrorDetails, LanguageCode


class NetworkTimeoutError(BaseError):
    """Error when network request times out."""

    def __init__(
            self,
            endpoint: str,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=InfraErrorCode.NETWORK_TIMEOUT.value,
            message=f"Network timeout for {endpoint}.",
            status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"endpoint": endpoint},
            language=language
        )


class ConnectionError(BaseError):
    """Error when network connection fails."""

    def __init__(
            self,
            endpoint: str,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=InfraErrorCode.CONNECTION_ERROR.value,
            message=f"Failed to connect to {endpoint}.",
            status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"endpoint": endpoint},
            language=language
        )