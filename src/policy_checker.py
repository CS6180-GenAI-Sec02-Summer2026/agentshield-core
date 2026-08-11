"""
AgentShield policy checker.

Checks proposed tool calls against compiled policy rules and returns
detailed violation information. This module sits between the Policy
Compiler and the Firewall Agent.

The Policy Checker:
    1. Takes a proposed tool call (from the Target Agent)
    2. Loads compiled policy rules (from the Policy Compiler)
    3. Evaluates each rule's conditions against the tool call
    4. Returns all violations found, not just the first match
    5. Provides detailed audit information for each violation

Usage:
    from src.policy_checker import PolicyChecker

    checker = PolicyChecker("data/policy_rules.json")
    result = checker.check(example)
    print(result.to_dict())
"""

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from src.intent_utils import request_is_read_only, tool_is_authorized_by_request
from src.security_patterns import (
    BROADCAST_RECIPIENT_PATTERNS,
    FILE_CONTENT_INDICATORS,
    INJECTION_PATTERNS,
    INTERNAL_REFERENCE_PATTERNS,
    PROTECTED_FILE_CHANGE_PATTERNS,
    SECRET_PATTERNS,
    SENSITIVE_CONTENT_PATTERNS,
    SENSITIVE_FILE_PATH_PATTERNS,
    SENSITIVE_SHARING_PATTERNS,
    STATE_CHANGING_HTTP_METHODS,
)
from src.security_text import (
    external_recipients,
    flatten_to_string,
    is_external_target,
    is_public_repository,
    matched_credential_values,
    matched_patterns,
)

REPO_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class PolicyViolation:
    """A single policy violation found during checking."""

    rule_id: str
    rule_name: str
    decision: str
    risk_level: str
    attack_categories: list[str]
    explanation: str
    matched_checks: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CheckResult:
    """Complete result of a policy check on a tool call."""

    tool_name: str
    total_rules_evaluated: int
    violations_found: int
    final_decision: str  # BLOCK > ASK_APPROVAL > ALLOW
    violations: list[PolicyViolation]
    all_clear: bool

    def to_dict(self) -> dict:
        result = asdict(self)
        result["violations"] = [v.to_dict() for v in self.violations]
        return result


class PolicyChecker:
    """
    Checks proposed tool calls against the compiled policy ruleset.

    Evaluates every enabled rule that applies to the tool and returns every
    matching violation. The final decision is the most restrictive match.
    """

    def __init__(self, rules_path: str = "data/policy_rules.json"):
        """Load policy rules."""
        self.rules = self._load_rules(rules_path)

    def _load_rules(self, filepath: str) -> list[dict]:
        """Load rules from JSON."""
        path = _resolve_rules_path(filepath)
        if not path.exists():
            raise FileNotFoundError(f"Rules file not found: {filepath} (resolved to {path})")
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        rules = data.get("rules", [])
        rules.sort(key=lambda r: r.get("priority", 99))
        return rules

    # ============================================================
    # Condition evaluation helpers
    # ============================================================

    def _get_nested_value(self, obj: dict, field_path: str):
        """Get value using dot notation with pipe alternatives."""
        alternatives = field_path.split("|")
        for alt in alternatives:
            parts = alt.strip().split(".")
            current = obj
            for part in parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    current = None
                    break
            if current is not None:
                return current
        return None

    def _evaluate_check(self, check: dict, example: dict) -> tuple[bool, str]:
        """
        Evaluate a single condition check.
        Returns (passed, description) where description explains what matched.
        """
        check_type = check.get("check")
        field_path = check.get("field", "")

        proposed = example.get("proposed_tool_call", {})
        arguments = proposed.get("arguments", {})
        external_context = example.get("external_context", "")
        user_request = example.get("user_request", "")

        if check_type == "equals":
            value = self._get_nested_value(example, field_path) or self._get_nested_value(
                proposed, field_path
            )
            matched = value == check.get("value")
            return (
                matched,
                f"Field '{field_path}' {'matches' if matched else 'does not match'} '{check.get('value')}'",
            )

        elif check_type == "contains_file_content":
            matched_indicators = matched_patterns(arguments, FILE_CONTENT_INDICATORS)
            matched = bool(matched_indicators)
            return (
                matched,
                f"File content indicators {'found' if matched else 'not found'}: {matched_indicators}",
            )

        elif check_type == "is_external_recipient":
            recipient = self._get_nested_value(proposed, field_path)
            if not recipient:
                return False, "No recipient found"
            if isinstance(recipient, str):
                recipient = [recipient]
            external = external_recipients(recipient, example.get("internal_domains"))
            matched = bool(external)
            return (
                matched,
                f"External recipients: {external}" if matched else "All recipients are internal",
            )

        elif check_type == "contains_secret_pattern":
            patterns = check.get("patterns", SECRET_PATTERNS)
            found = matched_patterns(arguments, patterns)
            matched = bool(found)
            return (
                matched,
                f"Secret patterns found: {found}" if matched else "No secret patterns detected",
            )

        elif check_type == "contains_credential_value":
            found = matched_credential_values(arguments)
            matched = bool(found)
            return (
                matched,
                f"Credential values found for: {found}"
                if matched
                else "No credential values detected",
            )

        elif check_type == "is_external_target":
            target = self._get_nested_value(proposed, field_path)
            if not target or not isinstance(target, str):
                return False, "No target found"
            is_ext = is_external_target(target, example.get("internal_domains"))
            return is_ext, f"Target '{target}' is {'external' if is_ext else 'internal'}"

        elif check_type == "contradicts_user_intent":
            tool_name = proposed.get("tool_name", "")
            user_intended = tool_is_authorized_by_request(tool_name, user_request)
            contradicts = not user_intended
            return (
                contradicts,
                f"Tool '{tool_name}' {'contradicts' if contradicts else 'matches'} user intent",
            )

        elif check_type == "contains_instruction_pattern":
            context_str = (
                external_context if isinstance(external_context, str) else str(external_context)
            )
            patterns = tuple(check.get("patterns", ())) + tuple(INJECTION_PATTERNS)
            found = matched_patterns(context_str, patterns)
            matched = bool(found)
            return (
                matched,
                f"Injection patterns found: {found}"
                if matched
                else "No injection patterns detected",
            )

        elif check_type == "not_in_user_request":
            value = self._get_nested_value(proposed, field_path)
            if not value or not isinstance(value, str):
                return False, "No value found"
            not_in_request = value.lower() not in user_request.lower()
            return (
                not_in_request,
                f"Value '{value}' {'not in' if not_in_request else 'found in'} user request",
            )

        elif check_type == "is_external_url":
            url = self._get_nested_value(proposed, field_path)
            if not url or not isinstance(url, str):
                return False, "No URL found"
            is_ext = is_external_target(url, example.get("internal_domains"))
            return is_ext, f"URL '{url}' is {'external' if is_ext else 'internal'}"

        elif check_type == "is_state_changing_http_method":
            method = str(arguments.get("method", "GET")).upper()
            matched = method in STATE_CHANGING_HTTP_METHODS
            return matched, f"HTTP method {method} {'changes state' if matched else 'is read-only'}"

        elif check_type == "user_request_is_read_only":
            matched = request_is_read_only(user_request)
            return (
                matched,
                "User request is read-only" if matched else "User request is not read-only",
            )

        elif check_type == "contains_sensitive_content":
            value = self._get_nested_value(proposed, field_path)
            if not value:
                return False, "No content to check"
            found = matched_patterns(value, SENSITIVE_CONTENT_PATTERNS)
            matched = bool(found)
            return (
                matched,
                f"Sensitive content found: {found}" if matched else "No sensitive content",
            )

        elif check_type == "has_external_participant_or_public":
            participants = self._get_nested_value(proposed, "arguments.participants")
            attendees = self._get_nested_value(proposed, "arguments.attendees")
            visibility = self._get_nested_value(proposed, "arguments.visibility")
            if visibility and str(visibility).lower() == "public":
                return True, "Visibility is set to public"
            invitees = []
            if isinstance(participants, list):
                invitees.extend(participants)
            if isinstance(attendees, list):
                invitees.extend(attendees)
            if invitees:
                external = external_recipients(invitees, example.get("internal_domains"))
                if external:
                    return True, f"External participants or attendees found: {external}"
            return False, "No external participants or attendees and visibility is not public"

        elif check_type == "contains_internal_reference":
            value = self._get_nested_value(proposed, field_path)
            if not value:
                return False, "No content to check"
            found = matched_patterns(value, INTERNAL_REFERENCE_PATTERNS)
            matched = bool(found)
            return (
                matched,
                f"Internal references found: {found}" if matched else "No internal references",
            )

        elif check_type == "is_public_repository":
            matched = is_public_repository(arguments)
            return (
                matched,
                "Repository is public" if matched else "Repository is private or unspecified",
            )

        elif check_type == "contains_sensitive_sharing_content":
            found = matched_patterns(arguments, SENSITIVE_SHARING_PATTERNS)
            matched = bool(found) or bool(matched_credential_values(arguments))
            if matched:
                details = found + matched_credential_values(arguments)
                return True, f"Sensitive sharing content found: {details}"
            return False, "No sensitive sharing content detected"

        elif check_type == "contains_sensitive_file_path":
            value = self._get_nested_value(proposed, field_path)
            found = matched_patterns(value, SENSITIVE_FILE_PATH_PATTERNS)
            matched = bool(found)
            return (
                matched,
                f"Sensitive file path patterns found: {found}"
                if matched
                else "No sensitive file path patterns",
            )

        elif check_type == "contains_protected_file_change":
            found = matched_patterns(arguments, PROTECTED_FILE_CHANGE_PATTERNS)
            matched = bool(found)
            return (
                matched,
                f"Protected file change patterns found: {found}"
                if matched
                else "No protected file change patterns",
            )

        elif check_type == "is_broadcast_recipient":
            recipients = flatten_to_string(self._get_nested_value(proposed, field_path)).lower()
            matched = any(pattern in recipients for pattern in BROADCAST_RECIPIENT_PATTERNS)
            return (
                matched,
                f"Broadcast recipient detected: {recipients}"
                if matched
                else "No broadcast recipient detected",
            )

        elif check_type == "count_greater_than":
            targets = self._get_nested_value(proposed, field_path)
            threshold = check.get("value", 1)
            if isinstance(targets, list):
                matched = len(targets) > threshold
                return (
                    matched,
                    f"Target count {len(targets)} {'>' if matched else '<='} threshold {threshold}",
                )
            return False, "No list found for count check"

        elif check_type == "greater_than":
            value = self._get_nested_value(example, field_path) or self._get_nested_value(
                proposed, field_path
            )
            threshold = check.get("value", 1)
            if value is not None:
                try:
                    matched = float(value) > threshold
                    return (
                        matched,
                        f"Value {value} {'>' if matched else '<='} threshold {threshold}",
                    )
                except (ValueError, TypeError):
                    return False, f"Cannot compare value '{value}' as number"
            return False, "Value not found"

        return False, f"Unknown check type: {check_type}"

    def _evaluate_conditions(self, conditions: dict, example: dict) -> tuple[bool, list[str]]:
        """
        Evaluate a condition block.
        Returns (matched, list of matched check descriptions).
        """
        operator = conditions.get("operator", "AND")
        checks = conditions.get("checks", [])

        if operator == "ALWAYS":
            return True, ["Rule applies unconditionally (ALWAYS)"]

        results = []
        descriptions = []
        for check in checks:
            passed, desc = self._evaluate_check(check, example)
            results.append(passed)
            if passed:
                descriptions.append(desc)

        if operator == "AND":
            matched = all(results)
        elif operator == "OR":
            matched = any(results)
        else:
            matched = False

        return matched, descriptions

    # ============================================================
    # Core checking
    # ============================================================

    def check(self, example: dict) -> CheckResult:
        """
        Check a proposed tool call against ALL policy rules.
        Returns complete violation information.
        """
        proposed = example.get("proposed_tool_call", {})
        tool_name = proposed.get("tool_name", "unknown")

        violations = []
        rules_evaluated = 0

        for rule in self.rules:
            if not rule.get("enabled", True):
                continue

            if tool_name not in rule.get("tools", []):
                continue

            rules_evaluated += 1
            matched, matched_descriptions = self._evaluate_conditions(
                rule.get("conditions", {}), example
            )

            if matched:
                explanation = rule.get("explanation_template", "")
                arguments = proposed.get("arguments", {})
                for key, value in arguments.items():
                    placeholder = f"{{arguments.{key}}}"
                    if placeholder in explanation:
                        explanation = explanation.replace(placeholder, str(value))

                violation = PolicyViolation(
                    rule_id=rule["rule_id"],
                    rule_name=rule["name"],
                    decision=rule["decision"],
                    risk_level=rule.get("risk_level", "medium"),
                    attack_categories=rule.get("attack_categories", []),
                    explanation=explanation,
                    matched_checks=matched_descriptions,
                )
                violations.append(violation)

        # Determine final decision: most restrictive wins
        # BLOCK > ASK_APPROVAL > ALLOW
        if any(v.decision == "BLOCK" for v in violations):
            final_decision = "BLOCK"
        elif any(v.decision == "ASK_APPROVAL" for v in violations):
            final_decision = "ASK_APPROVAL"
        else:
            final_decision = "ALLOW"

        return CheckResult(
            tool_name=tool_name,
            total_rules_evaluated=rules_evaluated,
            violations_found=len(violations),
            final_decision=final_decision,
            violations=violations,
            all_clear=len(violations) == 0,
        )

    def check_batch(self, examples: list[dict]) -> list[CheckResult]:
        """Check a batch of examples."""
        return [self.check(example) for example in examples]

    def get_coverage_report(self) -> dict:
        """
        Report which tools and attack categories are covered by rules.
        """
        tools_covered = set()
        categories_covered = set()
        decisions = {"BLOCK": 0, "ASK_APPROVAL": 0, "ALLOW": 0}

        for rule in self.rules:
            if not rule.get("enabled", True):
                continue
            tools_covered.update(rule.get("tools", []))
            categories_covered.update(rule.get("attack_categories", []))
            decisions[rule.get("decision", "ALLOW")] += 1

        all_tools = {
            "send_email",
            "read_file",
            "write_file",
            "delete_file",
            "create_calendar_event",
            "create_task",
            "create_github_issue",
            "send_http_request",
        }

        return {
            "total_rules": len(self.rules),
            "enabled_rules": sum(1 for r in self.rules if r.get("enabled", True)),
            "tools_covered": sorted(tools_covered),
            "tools_missing": sorted(all_tools - tools_covered),
            "attack_categories": sorted(categories_covered),
            "decisions": decisions,
        }


def _resolve_rules_path(filepath: str) -> Path:
    path = Path(filepath)
    if path.is_absolute():
        return path
    cwd_path = Path.cwd() / path
    if cwd_path.exists():
        return cwd_path
    return REPO_ROOT / path
