"""
AgentShield Firewall Agent v0.1

The core decision engine that intercepts proposed tool calls,
evaluates them against policy rules, classifies risk, and returns
a structured decision with audit explanation.

Usage:
    from firewall_agent import FirewallAgent

    agent = FirewallAgent("data/policy_rules.json")
    result = agent.evaluate(example)
    print(result.to_dict())
"""

import json
import sys
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional

from src.risk_classifier import classify_risk, RiskAssessment


@dataclass
class AuditEntry:
    """Structured audit log entry for a firewall decision."""
    timestamp: str
    example_id: str
    user_request: str
    tool_name: str
    tool_arguments: dict
    decision: str  # ALLOW, BLOCK, ASK_APPROVAL
    risk_assessment: dict
    matched_rule: Optional[str]
    matched_rule_name: Optional[str]
    explanation: str
    external_context_present: bool

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FirewallDecision:
    """Complete firewall decision output."""
    example_id: str
    decision: str  # ALLOW, BLOCK, ASK_APPROVAL
    risk_level: str
    risk_score: float
    risk_categories: list[str]
    matched_rule: Optional[str]
    matched_rule_name: Optional[str]
    explanation: str
    audit: AuditEntry

    def to_dict(self) -> dict:
        return asdict(self)


class FirewallAgent:
    """
    AgentShield Firewall Agent.
    
    Loads policy rules, evaluates proposed tool calls against them,
    uses the risk classifier for threat assessment, and produces
    structured decisions with audit trails.
    """

    def __init__(self, rules_path: str = "data/policy_rules.json"):
        """Initialize the firewall with policy rules."""
        self.rules = self._load_rules(rules_path)
        self.default_decision = "ALLOW"
        self.decision_log: list[FirewallDecision] = []

    def _load_rules(self, filepath: str) -> list[dict]:
        """Load policy rules from JSON file."""
        path = Path(filepath)
        if not path.exists():
            print(f"Warning: Rules file not found at {filepath}. Using empty ruleset.")
            return []
        with open(path, "r") as f:
            data = json.load(f)
        self.default_decision = data.get("default_decision", "ALLOW")
        rules = data.get("rules", [])
        # Sort by priority
        rules.sort(key=lambda r: r.get("priority", 99))
        return rules

    # ============================================================
    # Condition evaluation (mirrors label_validator.py logic)
    # ============================================================

    def _flatten_arguments(self, arguments: dict) -> str:
        """Flatten all argument values into a single string."""
        if not isinstance(arguments, dict):
            return str(arguments)
        parts = []
        for key, value in arguments.items():
            if isinstance(value, str):
                parts.append(value)
            elif isinstance(value, list):
                parts.extend(str(v) for v in value)
            elif isinstance(value, dict):
                parts.append(self._flatten_arguments(value))
            else:
                parts.append(str(value))
        return " ".join(parts)

    def _get_nested_value(self, obj: dict, field_path: str):
        """Get value using dot notation with pipe-separated alternatives."""
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

    def _evaluate_check(self, check: dict, example: dict) -> bool:
        """Evaluate a single condition check."""
        check_type = check.get("check")
        field_path = check.get("field", "")

        proposed = example.get("proposed_tool_call", {})
        arguments = proposed.get("arguments", {})
        external_context = example.get("external_context", "")
        user_request = example.get("user_request", "")

        if check_type == "equals":
            value = (
                self._get_nested_value(example, field_path)
                or self._get_nested_value(proposed, field_path)
            )
            return value == check.get("value")

        elif check_type == "contains_file_content":
            args_str = self._flatten_arguments(arguments)
            indicators = ["file_content", "file_data", "read_file", "attachment"]
            return any(ind in args_str.lower() for ind in indicators)

        elif check_type == "is_external_recipient":
            recipient = self._get_nested_value(proposed, field_path)
            if not recipient:
                return False
            if isinstance(recipient, str):
                recipient = [recipient]
            internal_domains = example.get(
                "internal_domains", ["@company.com", "@internal.org"]
            )
            return any(
                not any(r.endswith(d) for d in internal_domains) for r in recipient
            )

        elif check_type == "contains_secret_pattern":
            args_str = self._flatten_arguments(arguments)
            patterns = check.get("patterns", [])
            return any(p.lower() in args_str.lower() for p in patterns)

        elif check_type == "is_external_target":
            target = self._get_nested_value(proposed, field_path)
            if not target or not isinstance(target, str):
                return False
            internal = ["localhost", "127.0.0.1", "internal.", ".company.com"]
            return not any(ind in target.lower() for ind in internal)

        elif check_type == "contradicts_user_intent":
            tool_name = proposed.get("tool_name", "")
            request_lower = user_request.lower()
            intent_map = {
                "send_email": ["send", "email", "mail", "forward", "reply"],
                "read_file": ["read", "open", "view", "show", "look at"],
                "write_file": ["write", "save", "create file", "update file"],
                "delete_file": ["delete", "remove", "clean up"],
                "create_calendar_event": ["calendar", "schedule", "meeting", "event"],
                "create_task": ["task", "todo", "reminder", "assign"],
                "create_github_issue": ["issue", "bug", "ticket", "github"],
                "send_http_request": ["http", "request", "api", "fetch", "post", "get"],
            }
            expected_keywords = intent_map.get(tool_name, [])
            return not any(kw in request_lower for kw in expected_keywords)

        elif check_type == "contains_instruction_pattern":
            context_str = (
                external_context
                if isinstance(external_context, str)
                else str(external_context)
            )
            patterns = check.get("patterns", [])
            return any(p.lower() in context_str.lower() for p in patterns)

        elif check_type == "not_in_user_request":
            target_url = self._get_nested_value(proposed, field_path)
            if not target_url or not isinstance(target_url, str):
                return False
            return target_url.lower() not in user_request.lower()

        elif check_type == "is_external_url":
            url = self._get_nested_value(proposed, field_path)
            if not url or not isinstance(url, str):
                return False
            internal = ["localhost", "127.0.0.1", "internal.", ".company.com"]
            return not any(ind in url.lower() for ind in internal)

        elif check_type == "contains_sensitive_content":
            value = self._get_nested_value(proposed, field_path)
            if not value:
                return False
            sensitive = [
                "revenue", "salary", "password", "ssn", "credit card",
                "confidential", "secret", "internal only", "proprietary",
            ]
            return any(p in str(value).lower() for p in sensitive)

        elif check_type == "has_external_participant_or_public":
            participants = self._get_nested_value(
                proposed, "arguments.participants"
            )
            visibility = self._get_nested_value(proposed, "arguments.visibility")
            if visibility and str(visibility).lower() == "public":
                return True
            if participants and isinstance(participants, list):
                internal_domains = example.get(
                    "internal_domains", ["@company.com", "@internal.org"]
                )
                return any(
                    not any(p.endswith(d) for d in internal_domains)
                    for p in participants
                    if isinstance(p, str)
                )
            return False

        elif check_type == "contains_internal_reference":
            value = self._get_nested_value(proposed, field_path)
            if not value:
                return False
            internal = [
                "internal.", "vpc-", "10.0.", "192.168.", "database_url",
                "connection_string", "private_key", "intranet",
            ]
            return any(p in str(value).lower() for p in internal)

        elif check_type == "count_greater_than":
            targets = self._get_nested_value(proposed, field_path)
            threshold = check.get("value", 1)
            if isinstance(targets, list):
                return len(targets) > threshold
            return False

        elif check_type == "greater_than":
            value = (
                self._get_nested_value(example, field_path)
                or self._get_nested_value(proposed, field_path)
            )
            threshold = check.get("value", 1)
            if value is not None:
                try:
                    return float(value) > threshold
                except (ValueError, TypeError):
                    return False
            return False

        return False

    def _evaluate_conditions(self, conditions: dict, example: dict) -> bool:
        """Evaluate a condition block with AND/OR/ALWAYS operators."""
        operator = conditions.get("operator", "AND")
        checks = conditions.get("checks", [])

        if operator == "ALWAYS":
            return True

        results = [self._evaluate_check(check, example) for check in checks]

        if operator == "AND":
            return all(results)
        elif operator == "OR":
            return any(results)
        return False

    # ============================================================
    # Core evaluation
    # ============================================================

    def _match_rule(self, example: dict) -> tuple[Optional[dict], str]:
        """
        Find the first matching policy rule for an example.
        Returns (matched_rule, decision).
        """
        proposed = example.get("proposed_tool_call", {})
        tool_name = proposed.get("tool_name", "")

        for rule in self.rules:
            if not rule.get("enabled", True):
                continue

            if tool_name not in rule.get("tools", []):
                continue

            if self._evaluate_conditions(rule.get("conditions", {}), example):
                return rule, rule["decision"]

        return None, self.default_decision

    def _generate_explanation(
        self,
        rule: Optional[dict],
        decision: str,
        risk: RiskAssessment,
        example: dict,
    ) -> str:
        """Generate a human-readable audit explanation."""
        proposed = example.get("proposed_tool_call", {})
        tool_name = proposed.get("tool_name", "unknown")
        arguments = proposed.get("arguments", {})

        if rule:
            # Use rule's explanation template
            explanation = rule.get("explanation_template", "")
            # Simple template variable replacement
            for key, value in arguments.items():
                placeholder = f"{{arguments.{key}}}"
                if placeholder in explanation:
                    explanation = explanation.replace(placeholder, str(value))
            return explanation

        if decision == "ALLOW":
            return (
                f"Action allowed: {tool_name} call passed all policy checks. "
                f"Risk level: {risk.risk_level}. No policy violations detected."
            )

        # Fallback for decisions without a matched rule
        return (
            f"Decision: {decision} for {tool_name}. "
            f"Risk level: {risk.risk_level}. "
            f"Risk factors: {'; '.join(risk.risk_factors)}"
        )

    def evaluate(self, example: dict) -> FirewallDecision:
        """
        Evaluate a single proposed tool call.
        
        This is the main entry point. Takes a dataset example,
        runs it through policy rules and risk classification,
        and returns a complete FirewallDecision.
        """
        example_id = example.get("id", "unknown")
        proposed = example.get("proposed_tool_call", {})
        tool_name = proposed.get("tool_name", "unknown")
        arguments = proposed.get("arguments", {})
        user_request = example.get("user_request", "")
        external_context = example.get("external_context", "")

        # Step 1: Classify risk
        risk = classify_risk(example)

        # Step 2: Match against policy rules
        matched_rule, decision = self._match_rule(example)

        # Step 3: Generate explanation
        explanation = self._generate_explanation(
            matched_rule, decision, risk, example
        )

        # Step 4: Build audit entry
        audit = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            example_id=example_id,
            user_request=user_request,
            tool_name=tool_name,
            tool_arguments=arguments,
            decision=decision,
            risk_assessment=risk.to_dict(),
            matched_rule=matched_rule["rule_id"] if matched_rule else None,
            matched_rule_name=matched_rule["name"] if matched_rule else None,
            explanation=explanation,
            external_context_present=bool(external_context),
        )

        # Step 5: Build decision
        firewall_decision = FirewallDecision(
            example_id=example_id,
            decision=decision,
            risk_level=risk.risk_level,
            risk_score=risk.risk_score,
            risk_categories=risk.risk_categories,
            matched_rule=matched_rule["rule_id"] if matched_rule else None,
            matched_rule_name=matched_rule["name"] if matched_rule else None,
            explanation=explanation,
            audit=audit,
        )

        # Store in log
        self.decision_log.append(firewall_decision)

        return firewall_decision

    def evaluate_batch(self, examples: list[dict]) -> list[FirewallDecision]:
        """Evaluate a batch of examples."""
        return [self.evaluate(example) for example in examples]

    def get_decision_summary(self) -> dict:
        """Get a summary of all decisions made so far."""
        if not self.decision_log:
            return {"total": 0, "decisions": {}, "risk_levels": {}}

        decisions = {}
        risk_levels = {}
        for d in self.decision_log:
            decisions[d.decision] = decisions.get(d.decision, 0) + 1
            risk_levels[d.risk_level] = risk_levels.get(d.risk_level, 0) + 1

        return {
            "total": len(self.decision_log),
            "decisions": decisions,
            "risk_levels": risk_levels,
        }

    def export_audit_log(self, filepath: str):
        """Export the full audit log to a JSON file."""
        log_data = {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "total_decisions": len(self.decision_log),
            "summary": self.get_decision_summary(),
            "entries": [d.audit.to_dict() for d in self.decision_log],
        }
        with open(filepath, "w") as f:
            json.dump(log_data, f, indent=2)
        print(f"Audit log exported to {filepath} ({len(self.decision_log)} entries)")