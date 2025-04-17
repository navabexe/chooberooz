# Path: src/shared/logging/tracers.py
import uuid

from src.shared.utilities.helpers import generate_trace_id
from src.shared.utilities.types import TraceId


class Tracer:
    """Manager for trace and span IDs."""

    def __init__(self, trace_id: TraceId = None):
        """Initialize tracer with optional trace ID."""
        self.trace_id = trace_id or generate_trace_id()
        self.span_id = str(uuid.uuid4())

    def get_trace_id(self) -> TraceId:
        """Get current trace ID."""
        return self.trace_id

    def get_span_id(self) -> str:
        """Get current span ID."""
        return self.span_id

    def new_span(self) -> str:
        """Generate new span ID."""
        self.span_id = str(uuid.uuid4())
        return self.span_id

    def to_dict(self) -> dict:
        """Convert tracer to dict for logging."""
        return {
            "trace_id": str(self.trace_id),
            "span_id": self.span_id
        }
