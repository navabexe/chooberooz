import hashlib
import json
import re
import secrets
import uuid
from datetime import UTC, datetime

import unicodedata
from bson import ObjectId


def slugify(text: str) -> str:
    """Converts text to lowercase slug, removes symbols and replaces spaces with hyphens."""
    text = unicodedata.normalize("NFKD", text)
    text = text.encode("ascii", "ignore").decode("ascii")
    text = re.sub(r"[^a-zA-Z0-9\s-]", "", text).lower()
    text = re.sub(r"[\s_-]+", "-", text).strip("-")
    return text


def normalize_name(name: str) -> str:
    """Strips, title-cases, and removes duplicate spaces from a name."""
    return re.sub(r"\s+", " ", name.strip()).title()


def truncate(text: str, max_len: int) -> str:
    """Truncate text to a maximum length with ellipsis if needed."""
    return text if len(text) <= max_len else text[:max_len - 3].rstrip() + "..."


def generate_token(prefix: str = "token", user_id: str = None, ttl: int = 300) -> str:
    """Generates a secure hashed token using SHA256 with timestamp and UUID."""
    now = datetime.now(UTC).isoformat()
    random_str = secrets.token_hex(8)
    base = f"{prefix}-{user_id or ''}-{now}-{random_str}-{str(uuid.uuid4())}"
    return hashlib.sha256(base.encode()).hexdigest()


def generate_otp_code(length: int = 6) -> str:
    """Generates a numeric OTP code of given length."""
    return ''.join(secrets.choice("0123456789") for _ in range(length))


def generate_random_string(length: int = 32) -> str:
    """Generates a random alphanumeric string of given length using secrets."""
    return secrets.token_urlsafe(length)[:length]


def decode_value(value):
    """Decode bytes to str if necessary, otherwise return as-is."""
    if isinstance(value, bytes):
        return value.decode()
    return value


def safe_json_dumps(data):
    """Safely convert any complex object to JSON string."""
    def default_serializer(obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        if isinstance(obj, set):
            return list(obj)
        return str(obj)

    return json.dumps(data, default=default_serializer, ensure_ascii=False)