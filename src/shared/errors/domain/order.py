# Path: src/shared/errors/domain/order.py
from ..base import BaseError
from ...utilities.constants import DomainErrorCode, HttpStatus
from ...utilities.helpers import generate_trace_id
from ...utilities.types import TraceId, ErrorDetails, LanguageCode


class OrderNotFoundError(BaseError):
    """Error when an order is not found."""

    def __init__(
            self,
            order_id: str,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=DomainErrorCode.ORDER_NOT_FOUND.value,
            message=f"Order with ID {order_id} not found.",
            status_code=HttpStatus.NOT_FOUND.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"order_id": order_id},
            language=language
        )


class OrderLimitExceededError(BaseError):
    """Error when order limit is exceeded."""

    def __init__(
            self,
            user_id: str,
            max_orders: int,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=DomainErrorCode.ORDER_LIMIT_EXCEEDED.value,
            message=f"Order limit exceeded for user {user_id}.",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"user_id": user_id, "max_orders": max_orders},
            language=language
        )


class InvalidOrderError(BaseError):
    """Error when order data is invalid."""

    def __init__(
            self,
            field: str,
            value: any,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=DomainErrorCode.INVALID_ORDER.value,
            message=f"Invalid order data for field {field}.",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"field": field, "value": value},
            language=language
        )