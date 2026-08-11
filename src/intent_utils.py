"""Shared intent helpers for policy, risk, and label checks."""

import re


def _keyword_pattern(keyword: str) -> re.Pattern:
    escaped = re.escape(keyword).replace(r"\ ", r"\s+")
    return re.compile(rf"(?<![A-Za-z0-9_]){escaped}(?![A-Za-z0-9_])")


TOOL_INTENT_KEYWORDS = {
    "send_email": ("send", "email", "mail", "forward", "reply", "write to"),
    "read_file": ("read", "open", "view", "show", "look at", "display"),
    "write_file": (
        "write",
        "save",
        "create file",
        "create a file",
        "update file",
        "edit file",
        "overwrite",
    ),
    "create_calendar_event": (
        "add a calendar event",
        "create a calendar event",
        "create a meeting",
        "schedule",
        "schedule a meeting",
        "book",
        "block one hour",
        "block time",
        "invite",
        "appointment",
    ),
    "create_task": ("task", "todo", "reminder", "assign", "create task"),
    "create_github_issue": ("issue", "bug", "ticket", "github", "report"),
    "send_http_request": (
        "http",
        "request",
        "api",
        "fetch",
        "post",
        "get",
        "call",
        "submit",
        "upload",
        "sync",
        "check",
        "look up",
        "verify",
        "process",
        "handle",
    ),
}

TOOL_INTENT_PATTERNS = {
    tool_name: tuple(_keyword_pattern(keyword) for keyword in keywords)
    for tool_name, keywords in TOOL_INTENT_KEYWORDS.items()
}

READ_ONLY_DELETE_PATTERNS = (
    re.compile(r"\blist(?:ing)?\b"),
    re.compile(r"\bshow\b"),
    re.compile(r"\bview\b"),
    re.compile(r"\bdisplay\b"),
    re.compile(r"\bwhat(?:'s|s| is)\s+in\b"),
)
READ_ONLY_REQUEST_KEYWORDS = (
    "check",
    "display",
    "extract",
    "fetch",
    "get",
    "list",
    "look up",
    "read",
    "show",
    "summarize",
    "view",
)
READ_ONLY_REQUEST_PATTERNS = (
    *(_keyword_pattern(keyword) for keyword in READ_ONLY_REQUEST_KEYWORDS),
    re.compile(r"\bwhat(?:'s|s| is)\b"),
)
EXPLICIT_DELETE_PATTERNS = (
    re.compile(r"\bdelete\b"),
    re.compile(r"\bremove\b"),
)
CLEANUP_DELETE_PATTERNS = (
    re.compile(r"\bclean(?:\s+|-)?up\b"),
    re.compile(r"\bclear\b"),
    re.compile(r"\btake\s+care\b"),
    re.compile(r"\bdeal\s+with\b"),
)
READ_ONLY_EMAIL_PATTERNS = (
    re.compile(r"\b(read|summarize|check|show|open)\b.*\b(email|inbox)\b"),
    re.compile(r"\blatest\s+email\b"),
)
EXPLICIT_EMAIL_ACTION_PATTERNS = (
    re.compile(r"\b(send|forward|reply)\b"),
    re.compile(r"\bemail\b"),
    re.compile(r"\bwrite\s+to\b"),
)


def _matches(patterns: tuple[re.Pattern, ...], text: str) -> bool:
    return any(pattern.search(text) for pattern in patterns)


def delete_is_authorized_by_request(request_text: str) -> bool:
    """Return whether a user request explicitly authorizes file deletion."""
    request_lower = request_text.lower()
    if _matches(READ_ONLY_DELETE_PATTERNS, request_lower):
        return _matches(EXPLICIT_DELETE_PATTERNS, request_lower)
    return _matches(EXPLICIT_DELETE_PATTERNS + CLEANUP_DELETE_PATTERNS, request_lower)


def request_is_read_only(request_text: str) -> bool:
    """Return whether the user request asks only to inspect or retrieve data."""
    return _matches(READ_ONLY_REQUEST_PATTERNS, request_text.lower())


def tool_is_authorized_by_request(tool_name: str, request_text: str) -> bool:
    """Return whether the user's request authorizes the proposed tool."""
    if tool_name == "delete_file":
        return delete_is_authorized_by_request(request_text)
    if tool_name == "send_email":
        request_lower = request_text.lower()
        if _matches(READ_ONLY_EMAIL_PATTERNS, request_lower):
            return _matches(
                EXPLICIT_EMAIL_ACTION_PATTERNS, request_lower
            ) and not request_lower.startswith(("read ", "summarize ", "check ", "show ", "open "))
    patterns = TOOL_INTENT_PATTERNS.get(tool_name, ())
    return _matches(patterns, request_text.lower())
