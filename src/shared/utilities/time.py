from datetime import datetime, timedelta, timezone
from typing import Optional


def utc_now() -> datetime:
    """Returns current UTC time as aware datetime."""
    return datetime.now(timezone.utc)


def from_timestamp(ts: float) -> datetime:
    """Converts UNIX timestamp to aware datetime."""
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def is_expired(expiration_ts: float) -> bool:
    """Returns True if the given timestamp is in the past."""
    return utc_now().timestamp() > expiration_ts


def add_minutes(base: Optional[datetime], minutes: int) -> datetime:
    """Adds minutes to given datetime (or now)."""
    base_time = base or utc_now()
    return base_time + timedelta(minutes=minutes)


def add_days(base: Optional[datetime], days: int) -> datetime:
    """Adds days to given datetime (or now)."""
    base_time = base or utc_now()
    return base_time + timedelta(days=days)