"""
AgentShield risk classifier.

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

from src.intent_utils import tool_is_authorized_by_request
from src.security_patterns import (
    FILE_CONTENT_INDICATORS,
    INJECTION_PATTERNS,
    INTERNAL_REFERENCE_PATTERNS,
    SECRET_PATTERNS,
    SENSITIVE_CONTENT_PATTERNS,
)
from src.security_text import (
    external_recipients,
    flatten_to_string,
    is_external_target,
    matched_patterns,
)


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
# Risk detection functions
# ============================================================

def detect_prompt_injection(example: dict) -> tuple[bool, list[str]]:
    """Detect prompt injection patterns in external context."""
    external_context = example.get("external_context", "")
    if not external_context:
        return False, []

    context_str = flatten_to_string(external_context)
    matched = matched_patterns(context_str, INJECTION_PATTERNS)

    if matched:
        return True, [f"Prompt injection pattern detected: '{m}'" for m in matched]
    return False, []


def detect_data_exfiltration(example: dict) -> tuple[bool, list[str]]:
    """Detect attempts to send private data to external targets."""
    proposed = example.get("proposed_tool_call", {})
    tool_name = proposed.get("tool_name", "")
    arguments = proposed.get("arguments", {})
    args_str = flatten_to_string(arguments)
    factors = []

    if tool_name == "send_email":
        has_file_content = bool(matched_patterns(args_str, FILE_CONTENT_INDICATORS))
        recipient = arguments.get("to", "")
        external = external_recipients(recipient)
        if has_file_content and external:
            factors.append(f"File content detected in email to external recipient(s): {external}")

    if tool_name in ["create_calendar_event", "create_task"]:
        sensitive_matches = matched_patterns(args_str, SENSITIVE_CONTENT_PATTERNS)
        participants = arguments.get("participants", [])
        visibility = arguments.get("visibility", "")
        external_participants = external_recipients(participants)

        if sensitive_matches and (external_participants or visibility == "public"):
            factors.append(
                f"Sensitive content ({sensitive_matches}) shared with "
                f"external participants or public visibility"
            )

    if tool_name == "create_github_issue":
        internal_matches = matched_patterns(args_str, INTERNAL_REFERENCE_PATTERNS)
        repo_visibility = arguments.get("repo_visibility", "private")
        if internal_matches and repo_visibility == "public":
            factors.append(f"Internal references ({internal_matches}) in public GitHub issue")

    return bool(factors), factors


def detect_credential_exposure(example: dict) -> tuple[bool, list[str]]:
    """Detect secrets or credentials being sent to external targets."""
    proposed = example.get("proposed_tool_call", {})
    tool_name = proposed.get("tool_name", "")
    arguments = proposed.get("arguments", {})
    args_str = flatten_to_string(arguments)

    if tool_name not in ["send_email", "send_http_request"]:
        return False, []

    secret_matches = matched_patterns(args_str, SECRET_PATTERNS)
    if not secret_matches:
        return False, []

    target = arguments.get("url") or arguments.get("to", "")
    if isinstance(target, list):
        target = " ".join(target)

    if is_external_target(target, example.get("internal_domains")):
        return True, [f"Credential patterns ({secret_matches}) being sent to external target: {target}"]

    return False, []


def detect_unauthorized_action(example: dict) -> tuple[bool, list[str]]:
    """Detect tool calls that don't match user intent."""
    proposed = example.get("proposed_tool_call", {})
    tool_name = proposed.get("tool_name", "")
    user_request = example.get("user_request", "")
    arguments = proposed.get("arguments", {})
    factors = []

    user_intended = tool_is_authorized_by_request(tool_name, user_request)

    if not user_intended:
        factors.append(
            f"Tool '{tool_name}' does not match user's stated intent: '{example.get('user_request', '')}'"
        )

    if tool_name == "send_http_request":
        url = arguments.get("url", "")
        if url and url.lower() not in user_request.lower():
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

    if not all_categories:
        risk_level = "low"
        risk_score = 0.1
        all_categories = ["none"]
        all_factors = ["No risk indicators detected"]
        requires_approval = False

    elif "prompt_injection" in all_categories or "credential_exposure" in all_categories:
        risk_level = "critical"
        risk_score = 0.95
        requires_approval = False

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
