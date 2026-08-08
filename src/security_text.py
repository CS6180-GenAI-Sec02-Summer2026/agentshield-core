"""Shared text helpers for security checks."""

from collections.abc import Iterable
import re

from src.security_patterns import (
    DEFAULT_INTERNAL_EMAIL_DOMAINS,
    INTERNAL_TARGET_INDICATORS,
)


CREDENTIAL_VALUE_RE = re.compile(
    r"\b(api[_-]?key|auth[_-]?token|client[_-]?secret|credential|"
    r"database_url|db[_-]?password|license(?:[_-]?key)?|password|passwd|"
    r"private[_-]?key|secret|session[_-]?tokens?|token)\b\s*[:=]",
    re.IGNORECASE,
)


def flatten_to_string(value: object) -> str:
    """Flatten nested data into a single searchable string."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        return " ".join(f"{key} {flatten_to_string(item)}" for key, item in value.items())
    if isinstance(value, list):
        return " ".join(flatten_to_string(item) for item in value)
    return str(value)


def matched_patterns(value: object, patterns: Iterable[str]) -> list[str]:
    """Return configured patterns found in the flattened value."""
    value_lower = flatten_to_string(value).lower()
    return [pattern for pattern in patterns if pattern.lower() in value_lower]


def matched_credential_values(value: object) -> list[str]:
    """Return credential-like keys that appear to include concrete values."""
    text = flatten_to_string(value)
    return sorted({match.group(1).lower().replace("-", "_") for match in CREDENTIAL_VALUE_RE.finditer(text)})


def matches_any_pattern(value: object, patterns: Iterable[str]) -> bool:
    """Return whether any configured pattern appears in the flattened value."""
    return bool(matched_patterns(value, patterns))


def is_public_repository(arguments: object) -> bool:
    """Return whether GitHub issue arguments target a public repository."""
    if not isinstance(arguments, dict):
        return False

    visibility = str(arguments.get("repo_visibility", "")).lower()
    if visibility == "public":
        return True

    repo = str(arguments.get("repo", "")).lower()
    return any(marker in repo for marker in ("/public", "public-", "public_"))


def is_external_target(
    target: object,
    internal_domains: Iterable[str] | None = None,
    internal_indicators: Iterable[str] | None = None,
) -> bool:
    """Return whether a URL or address is outside known internal targets."""
    if not target or not isinstance(target, str):
        return False

    target_lower = target.lower()
    if "@" in target_lower and "://" not in target_lower:
        return bool(external_recipients(target, internal_domains))

    indicators = tuple(INTERNAL_TARGET_INDICATORS)
    if internal_indicators:
        indicators += tuple(internal_indicators)
    if internal_domains:
        indicators += tuple(internal_domains)

    return not any(indicator.lower() in target_lower for indicator in indicators)


def external_recipients(
    recipients: object,
    internal_domains: Iterable[str] | None = None,
) -> list[str]:
    """Return recipients that do not end with a known internal domain."""
    if not recipients:
        return []
    if isinstance(recipients, str):
        recipients = [recipients]
    elif isinstance(recipients, dict) or not isinstance(recipients, Iterable):
        return []

    domains = tuple(
        domain.lower().strip()
        for domain in (internal_domains or DEFAULT_INTERNAL_EMAIL_DOMAINS)
    )
    return [
        recipient
        for recipient in recipients
        if isinstance(recipient, str)
        and recipient.strip()
        and not any(recipient.lower().strip().endswith(domain) for domain in domains)
    ]
