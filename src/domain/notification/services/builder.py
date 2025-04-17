# Path: src/domain/notification/services/notification_content.py
from typing import Literal
from src.domain.notification.services.templates.sample_templates import TEMPLATE_VARIABLES
from src.shared.i18n.messages import get_message
from src.shared.logging.service import LoggingService
from src.shared.logging.config import LogConfig

SUPPORTED_LANGUAGES = ["fa", "en"]
DEFAULT_TEMPLATE = {
    "title": "Notification Error",
    "body": "Unable to process notification due to missing template: {template_key}"
}

logger = LoggingService(LogConfig())

async def build_notification_content(
    template_key: str,
    language: Literal["fa", "en"] = "en",
    variables: dict = None
) -> dict:
    """Build notification content from template key with variable substitution."""
    if language not in SUPPORTED_LANGUAGES:
        logger.warning("Unsupported language, falling back to default", context={"language": language})
        language = "en"

    if template_key not in TEMPLATE_VARIABLES:
        logger.warning("Unknown template key, using default", context={"template_key": template_key})
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
            logger.error("Missing variables in template", context={
                "template_key": template_key,
                "missing": missing_vars
            })
            raise ValueError(error_msg)

        title = get_message(title_key, language=language).format(**variables)
        default_vars = {"phone": "unknown", "purpose": "general", "otp": "N/A"}
        body_vars = {**default_vars, **variables}
        body = get_message(body_key, language=language).format(**body_vars)

        logger.info("Notification content built", context={
            "template_key": template_key,
            "language": language,
            "variables": variables
        })
        return {"title": title, "body": body}

    except (KeyError, ValueError) as e:
        logger.error("Template processing failed, using default", context={
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