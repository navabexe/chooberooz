# Path: src/shared/errors/infrastructure/external.py
from ..base import BaseError
from ...utilities.constants import InfraErrorCode, HttpStatus
from ...utilities.helpers import generate_trace_id
from ...utilities.types import TraceId, ErrorDetails, LanguageCode


class PaymentGatewayError(BaseError):
    """Error when payment gateway fails."""

    def __init__(
            self,
            gateway: str,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=InfraErrorCode.PAYMENT_GATEWAY.value,
            message=f"Payment gateway {gateway} failed.",
            status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"gateway": gateway},
            language=language
        )


class SmsServiceError(BaseError):
    """Error when SMS service fails."""

    def __init__(
            self,
            provider: str,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=InfraErrorCode.SMS_SERVICE.value,
            message=f"SMS service {provider} failed.",
            status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"provider": provider},
            language=language
        )


class EmailServiceError(BaseError):
    """Error when email service fails."""

    def __init__(
            self,
            provider: str,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=InfraErrorCode.EMAIL_SERVICE.value,
            message=f"Email service {provider} failed.",
            status_code=HttpStatus.SERVICE_UNAVAILABLE.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"provider": provider},
            language=language
        )