# Path: src/shared/errors/domain/catalog.py
from ..base import BaseError
from ...utilities.constants import DomainErrorCode, HttpStatus
from ...utilities.helpers import generate_trace_id
from ...utilities.types import TraceId, ErrorDetails, LanguageCode


class ProductNotFoundError(BaseError):
    """Error when a product is not found."""

    def __init__(
            self,
            product_id: str,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=DomainErrorCode.PRODUCT_NOT_FOUND.value,
            message=f"Product with ID {product_id} not found.",
            status_code=HttpStatus.NOT_FOUND.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"product_id": product_id},
            language=language
        )


class InsufficientStockError(BaseError):
    """Error when product stock is insufficient."""

    def __init__(
            self,
            product_id: str,
            requested_quantity: int,
            available_quantity: int,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=DomainErrorCode.INSUFFICIENT_STOCK.value,
            message=f"Insufficient stock for product {product_id}.",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {
                "product_id": product_id,
                "requested_quantity": requested_quantity,
                "available_quantity": available_quantity
            },
            language=language
        )


class InvalidProductDataError(BaseError):
    """Error when product data is invalid."""

    def __init__(
            self,
            field: str,
            value: any,
            trace_id: TraceId = None,
            details: ErrorDetails = None,
            language: LanguageCode = "en"
    ):
        super().__init__(
            error_code=DomainErrorCode.INVALID_PRODUCT_DATA.value,
            message=f"Invalid product data for field {field}.",
            status_code=HttpStatus.BAD_REQUEST.value,
            trace_id=trace_id or generate_trace_id(),
            details=details or {"field": field, "value": value},
            language=language
        )