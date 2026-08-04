"""
AgentShield firewall decision engine.

Intercepts proposed tool calls, evaluates them against compiled policy rules,
classifies risk, and returns structured decisions with detailed audit
explanations.

Usage:
    from src.firewall_agent import FirewallAgent

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
from src.policy_checker import PolicyChecker, CheckResult, PolicyViolation


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
    policy_violations: list[dict]
    rules_evaluated: int

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
    violations_count: int
    audit: AuditEntry

    def to_dict(self) -> dict:
        return asdict(self)


class FirewallAgent:
    """
    Evaluates proposed tool calls using policy and risk signals.

    Produces the final firewall decision plus a structured audit trail.
    """

    def __init__(self, rules_path: str = "data/policy_rules.json"):
        """Initialize the firewall with policy rules."""
        self.policy_checker = PolicyChecker(rules_path)
        self.rules = self.policy_checker.rules
        self.default_decision = "ALLOW"
        self.decision_log: list[FirewallDecision] = []

    # ============================================================
    # Explanation generation
    # ============================================================

    def _generate_explanation(
        self,
        check_result: CheckResult,
        risk: RiskAssessment,
        example: dict,
    ) -> str:
        """
        Generate a detailed human-readable audit explanation.

        Combines policy violation details with risk assessment
        to produce a clear justification for the decision.
        """
        proposed = example.get("proposed_tool_call", {})
        tool_name = proposed.get("tool_name", "unknown")
        decision = check_result.final_decision

        if check_result.all_clear:
            return (
                f"ALLOWED: '{tool_name}' call passed all {check_result.total_rules_evaluated} "
                f"policy checks. Risk level: {risk.risk_level} (score: {risk.risk_score:.2f}). "
                f"No policy violations detected."
            )

        parts = []

        if decision == "BLOCK":
            parts.append(f"BLOCKED: '{tool_name}' call violated {check_result.violations_found} policy rule(s).")
        elif decision == "ASK_APPROVAL":
            parts.append(f"APPROVAL REQUIRED: '{tool_name}' call triggered {check_result.violations_found} policy rule(s).")

        for i, violation in enumerate(check_result.violations):
            parts.append(
                f"  [{violation.rule_id}] {violation.rule_name}: {violation.explanation}"
            )
            if violation.matched_checks:
                for check_desc in violation.matched_checks:
                    parts.append(f"    - Evidence: {check_desc}")

        parts.append(
            f"  Risk assessment: {risk.risk_level} (score: {risk.risk_score:.2f}), "
            f"categories: {', '.join(risk.risk_categories)}"
        )

        if risk.risk_factors:
            parts.append(f"  Risk factors: {'; '.join(risk.risk_factors)}")

        return "\n".join(parts)

    # ============================================================
    # Core evaluation
    # ============================================================

    def evaluate(self, example: dict) -> FirewallDecision:
        """
        Evaluate a single proposed tool call.

        Pipeline:
            1. Risk classification (assess threat level)
            2. Policy checking (evaluate ALL rules, find ALL violations)
            3. Decision (most restrictive violation wins)
            4. Explanation generation (detailed audit trail)
            5. Audit entry creation
        """
        example_id = example.get("id", "unknown")
        proposed = example.get("proposed_tool_call", {})
        tool_name = proposed.get("tool_name", "unknown")
        arguments = proposed.get("arguments", {})
        user_request = example.get("user_request", "")
        external_context = example.get("external_context", "")

        # Step 1: Classify risk
        risk = classify_risk(example)

        # Step 2: Check against ALL policy rules
        check_result = self.policy_checker.check(example)

        # Step 3: Decision is from the policy checker (most restrictive wins)
        decision = check_result.final_decision

        # Step 4: Generate detailed explanation
        explanation = self._generate_explanation(check_result, risk, example)

        # Keep the highest-priority violation in the legacy matched_rule fields.
        primary_violation = None
        if check_result.violations:
            primary_violation = check_result.violations[0]

        # Step 5: Build audit entry
        audit = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            example_id=example_id,
            user_request=user_request,
            tool_name=tool_name,
            tool_arguments=arguments,
            decision=decision,
            risk_assessment=risk.to_dict(),
            matched_rule=primary_violation.rule_id if primary_violation else None,
            matched_rule_name=primary_violation.rule_name if primary_violation else None,
            explanation=explanation,
            external_context_present=bool(external_context),
            policy_violations=[v.to_dict() for v in check_result.violations],
            rules_evaluated=check_result.total_rules_evaluated,
        )

        firewall_decision = FirewallDecision(
            example_id=example_id,
            decision=decision,
            risk_level=risk.risk_level,
            risk_score=risk.risk_score,
            risk_categories=risk.risk_categories,
            matched_rule=primary_violation.rule_id if primary_violation else None,
            matched_rule_name=primary_violation.rule_name if primary_violation else None,
            explanation=explanation,
            violations_count=check_result.violations_found,
            audit=audit,
        )

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

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(log_data, f, indent=2)
        print(f"Audit log exported to {filepath} ({len(self.decision_log)} entries)")

    def get_policy_coverage(self) -> dict:
        """Get policy coverage report from the checker."""
        return self.policy_checker.get_coverage_report()
