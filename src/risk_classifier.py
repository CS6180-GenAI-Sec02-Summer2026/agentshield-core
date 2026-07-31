"""
AgentShield Risk Classifier v0.1

Classifies proposed tool calls by risk category and severity level.
Used by the Firewall Agent to assess threat level before making decisions.

Risk Levels:
    - critical: Immediate security threat (data exfiltration, credential theft)
    - high: Dangerous action requiring intervention (file deletion, unauthorized access)
    - medium: Potentially risky, needs review (sensitive data sharing, external participants)
    - low: Normal operation, no risk detected

Risk Categories:
    - prompt_injection: External context attempts to override user intent
    - data_exfiltration: Attempt to send private/sensitive data to external targets
    - unauthorized_action: Tool call not requested or approved by the user
    - credential_exposure: Secrets, API keys, or passwords being transmitted
    - none: No risk detected
"""

from dataclasses import dataclass, asdict
from typing import Optional

from src.intent_utils import delete_is_authorized_by_request


@dataclass
class RiskAssessment:
    """Structured output from the risk classifier."""
    risk_level: str  # critical, high, medium, low
    risk_categories: list[str]  # list of detected risk categories
    risk_score: float
    risk_factors: list[str]  # human-readable reasons for the risk level
    tool_name: str
    requires_approval: bool

    def to_dict(self) -> dict:
        return asdict(self)


# ============================================================
# Pattern definitions
# ============================================================

SECRET_PATTERNS = [
    "api_key", "api-key", "apikey", "password", "passwd",
    "secret", "token", "access_token", "auth_token",
    "private_key", "credential", "aws_secret",
    "openai_api_key", "database_url", "connection_string",
    "bearer", "authorization",
]

INJECTION_PATTERNS = [
    "ignore previous instructions",
    "ignore your previous instructions",
    "ignore above instructions",
    "ignore all instructions",
    "disregard your instructions",
    "override your instructions",
    "forget your rules",
    "new instructions:",
    "system prompt:",
    "you are now",
    "instead, do the following",
    "do not follow your original",
    "ignore all prior",
    "bypass security",
    "act as if",
    "pretend you are",
]

SENSITIVE_CONTENT_PATTERNS = [
    "revenue", "salary", "password", "ssn", "credit card",
    "confidential", "secret", "internal only", "proprietary",
    "social security", "bank account", "tax id",
]

INTERNAL_REFERENCE_PATTERNS = [
    "internal.", "vpc-", "10.0.", "192.168.", "172.16.",
    "database_url", "connection_string", "private_key",
    "intranet", ".internal.com", ".corp.",
]

FILE_CONTENT_INDICATORS = [
    "file_content", "file_data", "read_file", "attachment",
    "contents of", "extracted from",
]

# ============================================================
# Detection helpers
# ============================================================

def _flatten_to_string(obj) -> str:
    """Flatten any object into a searchable string."""
    if isinstance(obj, str):
        return obj
    elif isinstance(obj, dict):
        return " ".join(f"{k} {_flatten_to_string(v)}" for k, v in obj.items())
    elif isinstance(obj, list):
        return " ".join(_flatten_to_string(v) for v in obj)
    return str(obj)


def _has_pattern_match(text: str, patterns: list[str]) -> list[str]:
    """Return list of matched patterns found in text."""
    text_lower = text.lower()
    return [p for p in patterns if p.lower() in text_lower]


def _is_external_target(target: str, internal_domains: Optional[list[str]] = None) -> bool:
    """Check if a target URL or email is external."""
    if not target or not isinstance(target, str):
        return False

    internal_indicators = ["localhost", "127.0.0.1", "internal.", ".company.com", ".corp."]
    if internal_domains:
        internal_indicators.extend(internal_domains)

    target_lower = target.lower()
    return not any(ind in target_lower for ind in internal_indicators)


def _get_external_recipients(recipients, internal_domains: Optional[list[str]] = None) -> list[str]:
    """Return list of external recipients."""
    if not recipients:
        return []
    if isinstance(recipients, str):
        recipients = [recipients]
    
    domains = internal_domains or ["@company.com", "@internal.org"]
    external = []
    for r in recipients:
        if isinstance(r, str) and not any(r.endswith(d) for d in domains):
            external.append(r)
    return external


# ============================================================
# Risk detection functions
# ============================================================

def detect_prompt_injection(example: dict) -> tuple[bool, list[str]]:
    """Detect prompt injection patterns in external context."""
    external_context = example.get("external_context", "")
    if not external_context:
        return False, []

    context_str = _flatten_to_string(external_context)
    matched = _has_pattern_match(context_str, INJECTION_PATTERNS)

    if matched:
        return True, [f"Prompt injection pattern detected: '{m}'" for m in matched]
    return False, []


def detect_data_exfiltration(example: dict) -> tuple[bool, list[str]]:
    """Detect attempts to send private data to external targets."""
    proposed = example.get("proposed_tool_call", {})
    tool_name = proposed.get("tool_name", "")
    arguments = proposed.get("arguments", {})
    args_str = _flatten_to_string(arguments)
    factors = []

    if tool_name == "send_email":
        has_file_content = bool(_has_pattern_match(args_str, FILE_CONTENT_INDICATORS))
        recipient = arguments.get("to", "")
        external = _get_external_recipients(recipient)
        if has_file_content and external:
            factors.append(f"File content detected in email to external recipient(s): {external}")

    if tool_name in ["create_calendar_event", "create_task"]:
        sensitive_matches = _has_pattern_match(args_str, SENSITIVE_CONTENT_PATTERNS)
        participants = arguments.get("participants", [])
        visibility = arguments.get("visibility", "")
        external_participants = _get_external_recipients(participants)
        
        if sensitive_matches and (external_participants or visibility == "public"):
            factors.append(
                f"Sensitive content ({sensitive_matches}) shared with "
                f"external participants or public visibility"
            )

    if tool_name == "create_github_issue":
        internal_matches = _has_pattern_match(args_str, INTERNAL_REFERENCE_PATTERNS)
        repo_visibility = arguments.get("repo_visibility", "private")
        if internal_matches and repo_visibility == "public":
            factors.append(f"Internal references ({internal_matches}) in public GitHub issue")

    return bool(factors), factors


def detect_credential_exposure(example: dict) -> tuple[bool, list[str]]:
    """Detect secrets or credentials being sent to external targets."""
    proposed = example.get("proposed_tool_call", {})
    tool_name = proposed.get("tool_name", "")
    arguments = proposed.get("arguments", {})
    args_str = _flatten_to_string(arguments)

    if tool_name not in ["send_email", "send_http_request"]:
        return False, []

    secret_matches = _has_pattern_match(args_str, SECRET_PATTERNS)
    if not secret_matches:
        return False, []

    target = arguments.get("url") or arguments.get("to", "")
    if isinstance(target, list):
        target = " ".join(target)

    if _is_external_target(target):
        return True, [f"Credential patterns ({secret_matches}) being sent to external target: {target}"]

    return False, []


def detect_unauthorized_action(example: dict) -> tuple[bool, list[str]]:
    """Detect tool calls that don't match user intent."""
    proposed = example.get("proposed_tool_call", {})
    tool_name = proposed.get("tool_name", "")
    user_request = example.get("user_request", "").lower()
    arguments = proposed.get("arguments", {})
    factors = []

    if tool_name == "delete_file":
        user_intended = delete_is_authorized_by_request(user_request)
    else:
        intent_map = {
            "send_email": ["send", "email", "mail", "forward", "reply", "write to"],
            "read_file": ["read", "open", "view", "show", "look at", "display"],
            "write_file": ["write", "save", "create file", "update file", "edit file"],
            "create_calendar_event": ["calendar", "schedule", "meeting", "event", "appointment"],
            "create_task": ["task", "todo", "reminder", "assign", "create task"],
            "create_github_issue": ["issue", "bug", "ticket", "github", "report"],
            "send_http_request": ["http", "request", "api", "fetch", "post", "get", "call"],
        }
        expected_keywords = intent_map.get(tool_name, [])
        user_intended = any(kw in user_request for kw in expected_keywords)

    if not user_intended:
        factors.append(
            f"Tool '{tool_name}' does not match user's stated intent: '{example.get('user_request', '')}'"
        )

    if tool_name == "send_http_request":
        url = arguments.get("url", "")
        if url and url.lower() not in user_request:
            factors.append(f"Target URL '{url}' was not mentioned in user request")

    if tool_name == "delete_file":
        target = arguments.get("file_path") or arguments.get("path") or arguments.get("targets", "unknown")
        factors.append(f"File deletion requires explicit approval: {target}")

    targets = arguments.get("targets", [])
    if isinstance(targets, list) and len(targets) > 1:
        factors.append(f"Bulk operation affecting {len(targets)} resources")

    return bool(factors), factors


# ============================================================
# Main classifier
# ============================================================

def classify_risk(example: dict) -> RiskAssessment:
    """
    Classify the risk level of a proposed tool call.
    
    Runs all detection functions and aggregates results into
    a single RiskAssessment.
    """
    proposed = example.get("proposed_tool_call", {})
    tool_name = proposed.get("tool_name", "unknown")

    all_categories = []
    all_factors = []

    # Run all detectors
    injection_detected, injection_factors = detect_prompt_injection(example)
    if injection_detected:
        all_categories.append("prompt_injection")
        all_factors.extend(injection_factors)

    exfil_detected, exfil_factors = detect_data_exfiltration(example)
    if exfil_detected:
        all_categories.append("data_exfiltration")
        all_factors.extend(exfil_factors)

    cred_detected, cred_factors = detect_credential_exposure(example)
    if cred_detected:
        all_categories.append("credential_exposure")
        all_factors.extend(cred_factors)

    unauth_detected, unauth_factors = detect_unauthorized_action(example)
    if unauth_detected:
        all_categories.append("unauthorized_action")
        all_factors.extend(unauth_factors)

    # Determine risk level based on categories and severity
    if not all_categories:
        risk_level = "low"
        risk_score = 0.1
        all_categories = ["none"]
        all_factors = ["No risk indicators detected"]
        requires_approval = False

    elif "prompt_injection" in all_categories or "credential_exposure" in all_categories:
        risk_level = "critical"
        risk_score = 0.95
        requires_approval = False  # Should be blocked, not just approved

    elif "data_exfiltration" in all_categories:
        # Data exfil with external target is critical, otherwise high
        if any("external" in f.lower() for f in all_factors):
            risk_level = "critical"
            risk_score = 0.9
        else:
            risk_level = "high"
            risk_score = 0.75
        requires_approval = False

    elif "unauthorized_action" in all_categories:
        # File deletion and bulk ops are high, others medium
        if any("deletion" in f.lower() or "bulk" in f.lower() for f in all_factors):
            risk_level = "high"
            risk_score = 0.7
            requires_approval = True
        else:
            risk_level = "medium"
            risk_score = 0.5
            requires_approval = True

    else:
        risk_level = "medium"
        risk_score = 0.5
        requires_approval = True

    return RiskAssessment(
        risk_level=risk_level,
        risk_categories=all_categories,
        risk_score=risk_score,
        risk_factors=all_factors,
        tool_name=tool_name,
        requires_approval=requires_approval,
    )
