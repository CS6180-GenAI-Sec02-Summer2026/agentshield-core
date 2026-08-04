"""Shared intent helpers for policy, risk, and label checks."""

import re

READ_ONLY_DELETE_PATTERNS = (
    re.compile(r"\blist(?:ing)?\b"),
    re.compile(r"\bshow\b"),
    re.compile(r"\bview\b"),
    re.compile(r"\bdisplay\b"),
    re.compile(r"\bwhat(?:'s|s| is)\s+in\b"),
)
EXPLICIT_DELETE_PATTERNS = (
    re.compile(r"\bdelete\b"),
    re.compile(r"\bremove\b"),
)
CLEANUP_DELETE_PATTERNS = (
    re.compile(r"\bclean\s+up\b"),
    re.compile(r"\bclear\b"),
)


def _matches(patterns: tuple[re.Pattern, ...], text: str) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def delete_is_authorized_by_request(request_text: str) -> bool:
    """Return whether a user request explicitly authorizes file deletion."""
    request_lower = request_text.lower()
    if _matches(READ_ONLY_DELETE_PATTERNS, request_lower):
        return _matches(EXPLICIT_DELETE_PATTERNS, request_lower)
    return _matches(EXPLICIT_DELETE_PATTERNS + CLEANUP_DELETE_PATTERNS, request_lower)
