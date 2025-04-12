from typing import Literal

from src.shared.i18n.messages import get_message
from src.shared.utilities.logging import log_info, log_error
from src.domain.notification.services.templates.sample_templates import TEMPLATE_VARIABLES


SUPPORTED_LANGUAGES = ["fa", "en"]


async def build_notification_content(
    template_key: str,
    language: Literal["fa", "en"] = "fa",
    variables: dict = None
) -> dict:
    """Build notification content from template key with variable substitution."""
    if language not in SUPPORTED_LANGUAGES:
        language = "fa"

    variables = variables or {}
    title_key = f"notification.{template_key}.title"
    body_key = f"notification.{template_key}.body"

    try:
        required_vars = TEMPLATE_VARIABLES.get(template_key, {})
        missing_vars = [var for var in required_vars if var not in variables]
        if missing_vars:
            error_msg = f"Missing variables for {template_key}: {missing_vars}"
            log_error("Missing variables in template", extra={"template_key": template_key, "missing": missing_vars})
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

    except KeyError as e:
        error_msg = f"Template {template_key} missing variable {str(e)} for language {language}"
        log_error("Template key not found", extra={"template_key": template_key, "error": str(e)})
        raise ValueError(error_msg)
    except Exception as e:
        error_msg = f"Failed to build content for {template_key}: {str(e)}"
        log_error("Failed to build notification content", extra={"error": str(e)})
        raise