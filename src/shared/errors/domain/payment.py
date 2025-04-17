# Path: src/shared/errors/domain/payment.py
from ..base import BaseError
from ...utilities.constants import DomainErrorCode, HttpStatus
from ...utilities.helpers import generate_trace_id
from ...utilities.types import TraceId, ErrorDetails, LanguageCode


class InvalidPaymentError(BaseError):
    """Error when payment data is invalid."""

    def __init__(
            self,
            field: str,
            value: any,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=DomainErrorCode.INVALID_PAYMENT.value,
            message=f"Invalid payment data for field {field}.",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"field": field, "value": value},
            language=language
        )


class PaymentDeclinedError(BaseError):
    """Error when payment is declined by gateway."""

    def __init__(
            self,
            transaction_id: str,
            reason: str,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=DomainErrorCode.PAYMENT_DECLINED.value,
            message=f"Payment declined for transaction {transaction_id}.",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"transaction_id": transaction_id, "reason": reason},
            language=language
        )


class PaymentTimeoutError(BaseError):
    """Error when payment times out."""

    def __init__(
            self,
            transaction_id: str,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=DomainErrorCode.PAYMENT_TIMEOUT.value,
            message=f"Payment timed out for transaction {transaction_id}.",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"transaction_id": transaction_id},
            language=language
        )