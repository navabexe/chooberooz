# path: src/shared/utilities/language.py
from fastapi import Request
from src.shared.config.settings import settings

def extract_language(request: Request) -> str:
    lang = request.query_params.get("response_language")
    if lang:
        return lang

    header_lang = request.headers.get("accept-language")
    if header_lang:
        return header_lang.split(",")[0].strip()

    return settings.DEFAULT_LANGUAGE
