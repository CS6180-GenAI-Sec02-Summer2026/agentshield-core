"""Shared intent helpers for policy, risk, and label checks."""

READ_ONLY_DELETE_TERMS = ("list", "listing", "show", "view", "display", "what's in", "whats in")
EXPLICIT_DELETE_TERMS = ("delete", "remove")
CLEANUP_DELETE_TERMS = ("clean up", "clear")


def delete_is_authorized_by_request(request_lower: str) -> bool:
    """Return whether a user request explicitly authorizes file deletion."""
    if any(term in request_lower for term in READ_ONLY_DELETE_TERMS):
        return any(term in request_lower for term in EXPLICIT_DELETE_TERMS)
    return any(term in request_lower for term in EXPLICIT_DELETE_TERMS + CLEANUP_DELETE_TERMS)
