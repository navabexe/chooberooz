import uuid
import time

from src.shared.utilities.types import TraceId


# Generate unique trace ID for distributed tracing
def generate_trace_id() -> TraceId:
    return uuid.uuid4()

# Get current timestamp in ISO format
def get_current_timestamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

# Sanitize sensitive data (e.g., mask credit card)
def sanitize_data(data: str) -> str:
    if len(data) > 4:
        return "****" + data[-4:]
    return data