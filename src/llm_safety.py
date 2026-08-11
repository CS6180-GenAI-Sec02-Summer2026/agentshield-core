"""Redaction and size controls applied before data reaches a model provider."""

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

SENSITIVE_KEY = re.compile(
    r"(?:api[_-]?key|password|passwd|secret|token|authorization|credential|private[_-]?key)",
    re.IGNORECASE,
)
SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)\b(api[_ -]?key|password|passwd|secret|token|authorization|credential)"
    r"\s*[:=]\s*([^\s,;]+)"
)
BEARER_TOKEN = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")


def redact_for_model(value: Any) -> Any:
    """Recursively redact credential values while retaining security context."""
    if isinstance(value, Mapping):
        redacted = {}
        for key, item in value.items():
            key_text = str(key)
            redacted[key_text] = (
                f"<redacted:{key_text}>"
                if SENSITIVE_KEY.search(key_text)
                else redact_for_model(item)
            )
        return redacted
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [redact_for_model(item) for item in value]
    if isinstance(value, str):
        text = BEARER_TOKEN.sub("Bearer <redacted>", value)
        return SENSITIVE_ASSIGNMENT.sub(
            lambda match: f"{match.group(1)}=<redacted>",
            text,
        )
    return value


def prompt_json(value: Any, max_chars: int) -> str:
    """Serialize redacted input and enforce a hard provider-input size limit."""
    payload = json.dumps(redact_for_model(value), ensure_ascii=True, sort_keys=True, default=str)
    if len(payload) > max_chars:
        raise ValueError(
            f"Model input is {len(payload)} characters; configured maximum is {max_chars}."
        )
    return payload
