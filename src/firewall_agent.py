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
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

from src.agent_runtime import AgentLLMRuntime, offline_runtime
from src.llm_client import LLMError, LLMResponseValidationError
from src.llm_models import LLMAuditExplanation
from src.llm_safety import prompt_json, redact_for_model
from src.policy_checker import CheckResult, PolicyChecker
from src.risk_classifier import RiskAssessment, assess_risk


@dataclass
class AuditEntry:
    """Structured audit log entry for a firewall decision."""

    timestamp: str
    example_id: str
    user_request: str
    tool_name: str
    tool_arguments: dict
    decision: str
    risk_assessment: dict
    matched_rule: str | None
    matched_rule_name: str | None
    explanation: str
    external_context_present: bool
    policy_violations: list[dict]
    rules_evaluated: int
    canonical_explanation: str
    explanation_mode: str
    llm: dict | None
    quality_judge: dict | None = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FirewallDecision:
    """Complete firewall decision output."""

    example_id: str
    decision: str
    risk_level: str
    risk_score: float
    risk_categories: list[str]
    matched_rule: str | None
    matched_rule_name: str | None
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

    AUDIT_SYSTEM_PROMPT = """
You are the AgentShield Audit Explanation Agent. Explain the supplied final
firewall decision in clear, concise language using only the supplied policy and
risk evidence. The deterministic policy decision is authoritative: do not
change it, add unlisted rule IDs, or invent facts. Return only the
schema-constrained response.
""".strip()
    AUDIT_PROMPT_VERSION = "audit-explanation-v2"

    def __init__(
        self,
        rules_path: str = "data/policy_rules.json",
        runtime: AgentLLMRuntime | None = None,
    ):
        """Initialize the firewall with policy rules."""
        self.runtime = runtime or offline_runtime()
        self.policy_checker = PolicyChecker(rules_path)
        self.rules = self.policy_checker.rules
        self.default_decision = "ALLOW"
        self.decision_log: list[FirewallDecision] = []

    # ============================================================
    # Explanation generation
    # ============================================================

    def _generate_canonical_explanation(
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
            parts.append(
                f"BLOCKED: '{tool_name}' call violated {check_result.violations_found} policy rule(s)."
            )
        elif decision == "ASK_APPROVAL":
            parts.append(
                f"APPROVAL REQUIRED: '{tool_name}' call triggered {check_result.violations_found} policy rule(s)."
            )

        for violation in check_result.violations:
            parts.append(f"  [{violation.rule_id}] {violation.rule_name}: {violation.explanation}")
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

    def evaluate(
        self,
        example: dict,
        use_llm: bool | None = None,
    ) -> FirewallDecision:
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

        risk = assess_risk(example, self.runtime, use_llm)

        check_result = self.policy_checker.check(example)

        decision = check_result.final_decision

        canonical_explanation = self._generate_canonical_explanation(check_result, risk, example)
        explanation, explanation_mode, explanation_llm = self._generate_audit_explanation(
            example=example,
            check_result=check_result,
            risk=risk,
            canonical_explanation=canonical_explanation,
            use_llm=use_llm,
        )

        primary_violation = None
        if check_result.violations:
            primary_violation = check_result.violations[0]

        audit = AuditEntry(
            timestamp=datetime.now(timezone.utc).isoformat(),
            example_id=example_id,
            user_request=redact_for_model(user_request),
            tool_name=tool_name,
            tool_arguments=redact_for_model(arguments),
            decision=decision,
            risk_assessment=redact_for_model(risk.to_dict()),
            matched_rule=primary_violation.rule_id if primary_violation else None,
            matched_rule_name=primary_violation.rule_name if primary_violation else None,
            explanation=redact_for_model(explanation),
            external_context_present=bool(external_context),
            policy_violations=redact_for_model(
                [violation.to_dict() for violation in check_result.violations]
            ),
            rules_evaluated=check_result.total_rules_evaluated,
            canonical_explanation=redact_for_model(canonical_explanation),
            explanation_mode=explanation_mode,
            llm=explanation_llm,
        )

        firewall_decision = FirewallDecision(
            example_id=example_id,
            decision=decision,
            risk_level=risk.risk_level,
            risk_score=risk.risk_score,
            risk_categories=risk.risk_categories,
            matched_rule=primary_violation.rule_id if primary_violation else None,
            matched_rule_name=primary_violation.rule_name if primary_violation else None,
            explanation=redact_for_model(explanation),
            violations_count=check_result.violations_found,
            audit=audit,
        )

        self.decision_log.append(firewall_decision)
        return firewall_decision

    def _generate_audit_explanation(
        self,
        *,
        example: dict,
        check_result: CheckResult,
        risk: RiskAssessment,
        canonical_explanation: str,
        use_llm: bool | None,
    ) -> tuple[str, str, dict | None]:
        should_use_llm = self.runtime.enabled("audit") if use_llm is None else use_llm
        if not should_use_llm:
            return canonical_explanation, "offline_rules", None

        violations = [violation.to_dict() for violation in check_result.violations]
        expected_rule_ids = {violation["rule_id"] for violation in violations}
        try:
            response = self.runtime.generate(
                agent_name="audit",
                purpose="firewall_audit_explanation",
                prompt_version=self.AUDIT_PROMPT_VERSION,
                system_instruction=self.AUDIT_SYSTEM_PROMPT,
                prompt=prompt_json(
                    {
                        "user_request": example.get("user_request", ""),
                        "external_context": example.get("external_context"),
                        "proposed_tool_call": example.get("proposed_tool_call", {}),
                        "final_decision": check_result.final_decision,
                        "policy_violations": violations,
                        "risk_assessment": risk.to_dict(),
                        "canonical_explanation": canonical_explanation,
                    },
                    self.runtime.settings.max_input_chars,
                ),
                response_model=LLMAuditExplanation,
            )
            output = response.output
            if output.decision != check_result.final_decision:
                raise LLMResponseValidationError(
                    "Audit Explanation Agent changed the authoritative firewall decision."
                )
            if not set(output.referenced_rule_ids).issubset(expected_rule_ids):
                raise LLMResponseValidationError(
                    "Audit Explanation Agent referenced a rule that did not match."
                )
            return output.explanation, "llm_explanation", response.metadata.to_dict()
        except LLMError:
            if not self.runtime.fallback_to_offline:
                raise
            return canonical_explanation, "offline_fallback", {"fallback": "offline"}

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
