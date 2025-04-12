import re

import phonenumbers


# Email Validation
EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
)


def is_valid_email(email: str) -> bool:
    """Validates an email address using regex."""
    return bool(EMAIL_REGEX.fullmatch(email.strip()))


# Phone Validation
def validate_and_format_phone(phone: str) -> str:
    """Validates and formats a phone number to E.164 standard."""
    try:
        parsed = phonenumbers.parse(phone)
        if not phonenumbers.is_valid_number(parsed):
            raise ValueError("Invalid phone number")
        return phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
    except phonenumbers.NumberParseException:
        raise ValueError("Phone number must be in international format (e.g., +989123456789)")