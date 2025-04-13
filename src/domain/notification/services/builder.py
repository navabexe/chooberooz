from typing import Literal

from src.shared.i18n.messages import get_message
from src.shared.utilities.logging import log_info, log_error, log_warning
from src.domain.notification.services.templates.sample_templates import TEMPLATE_VARIABLES


SUPPORTED_LANGUAGES = ["fa", "en"]
DEFAULT_TEMPLATE = {
    "title": "Notification Error",
    "body": "Unable to process notification due to missing template: {template_key}"
}


async def build_notification_content(
    template_key: str,
    language: Literal["fa", "en"] = "fa",
    variables: dict = None
) -> dict:
    """Build notification content from template key with variable substitution."""
    if language not in SUPPORTED_LANGUAGES:
        log_warning("Unsupported language, falling back to default", extra={"language": language})
        language = "fa"

    if template_key not in TEMPLATE_VARIABLES:
        log_warning("Unknown template key, using default", extra={"template_key": template_key})
        return {
            "title": DEFAULT_TEMPLATE["title"],
            "body": DEFAULT_TEMPLATE["body"].format(template_key=template_key)
        }

    variables = variables or {}
    title_key = f"notification.{template_key}.title"
    body_key = f"notification.{template_key}.body"

    try:
        required_vars = TEMPLATE_VARIABLES.get(template_key, {})
        missing_vars = [var for var in required_vars if var not in variables]
        if missing_vars:
            error_msg = f"Missing variables for {template_key}: {missing_vars}"
            log_error("Missing variables in template", extra={
                "template_key": template_key,
                "missing": missing_vars
            })
            raise ValueError(error_msg)

        title = get_message(title_key, lang=language).format(**variables)
        default_vars = {"phone": "unknown", "purpose": "general", "otp": "N/A"}
        body_vars = {**default_vars, **variables}
        body = get_message(body_key, lang=language).format(**body_vars)

        log_info("Notification content built", extra={
            "template_key": template_key,
            "language": language,
            "variables": variables
        })
        return {"title": title, "body": body}

    except (KeyError, ValueError) as e:
        log_error("Template processing failed, using default", extra={
            "template_key": template_key,
            "language": language,
            "variables": variables,
            "error": str(e),
            "error_type": type(e).__name__
        })
        return {
            "title": DEFAULT_TEMPLATE["title"],
            "body": DEFAULT_TEMPLATE["body"].format(template_key=template_key)
        }