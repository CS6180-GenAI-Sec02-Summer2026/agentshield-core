"""
AgentShield policy compiler.

Compiles natural-language security policies into structured JSON rules
that the firewall can evaluate. Supports loading policies from markdown
files, parsing them into rule objects, and exporting compiled rules.

The Policy Compiler bridges the gap between human-readable policy
definitions (in docs/safety_policies.md) and the machine-readable
rule format (in data/policy_rules.json) that the firewall consumes.

Usage:
    from src.policy_compiler_agent import PolicyCompilerAgent

    compiler = PolicyCompilerAgent()
    rules = compiler.compile_from_file("docs/safety_policies.md")
    compiler.export_rules("data/compiled_rules.json")
"""

import json
import re
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from src.security_patterns import INJECTION_PATTERNS, SECRET_PATTERNS


@dataclass
class CompiledRule:
    """A single compiled policy rule."""
    rule_id: str
    name: str
    description: str
    priority: int
    enabled: bool
    tools: list[str]
    conditions: dict
    decision: str
    risk_level: str
    attack_categories: list[str]
    explanation_template: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class CompilationResult:
    """Result of a policy compilation."""
    total_policies: int
    compiled_rules: int
    skipped: int
    errors: list[str]
    rules: list[CompiledRule]

    def to_dict(self) -> dict:
        return {
            "total_policies": self.total_policies,
            "compiled_rules": self.compiled_rules,
            "skipped": self.skipped,
            "errors": self.errors,
            "rules": [r.to_dict() for r in self.rules],
        }


# ============================================================
# Tool and check type mappings
# ============================================================

ALL_TOOLS = [
    "send_email", "read_file", "write_file", "delete_file",
    "create_calendar_event", "create_task", "create_github_issue",
    "send_http_request",
]

# Maps keywords in policy descriptions to tool names
TOOL_KEYWORD_MAP = {
    "email": ["send_email"],
    "send_email": ["send_email"],
    "file": ["read_file", "write_file", "delete_file"],
    "read_file": ["read_file"],
    "write_file": ["write_file"],
    "delete_file": ["delete_file"],
    "delete": ["delete_file"],
    "deletion": ["delete_file"],
    "calendar": ["create_calendar_event"],
    "create_calendar_event": ["create_calendar_event"],
    "task": ["create_task"],
    "create_task": ["create_task"],
    "github": ["create_github_issue"],
    "github issue": ["create_github_issue"],
    "create_github_issue": ["create_github_issue"],
    "http": ["send_http_request"],
    "http request": ["send_http_request"],
    "send_http_request": ["send_http_request"],
    "all tools": ALL_TOOLS,
}

# Maps policy intent keywords to condition check types
CONDITION_KEYWORD_MAP = {
    "private file": {"check": "contains_file_content", "field": "arguments.body"},
    "file content": {"check": "contains_file_content", "field": "arguments.body"},
    "external recipient": {"check": "is_external_recipient", "field": "arguments.to"},
    "external email": {"check": "is_external_recipient", "field": "arguments.to"},
    "secret": {"check": "contains_secret_pattern", "field": "arguments"},
    "credential": {"check": "contains_secret_pattern", "field": "arguments"},
    "api key": {"check": "contains_secret_pattern", "field": "arguments"},
    "password": {"check": "contains_secret_pattern", "field": "arguments"},
    "token": {"check": "contains_secret_pattern", "field": "arguments"},
    "external url": {"check": "is_external_url", "field": "arguments.url"},
    "external endpoint": {"check": "is_external_target", "field": "arguments.url|arguments.to"},
    "untrusted context": {"check": "contains_instruction_pattern", "field": "external_context"},
    "instruction override": {"check": "contains_instruction_pattern", "field": "external_context"},
    "prompt injection": {"check": "contains_instruction_pattern", "field": "external_context"},
    "override": {"check": "contradicts_user_intent", "field": "proposed_tool_call"},
    "contradicts": {"check": "contradicts_user_intent", "field": "proposed_tool_call"},
    "read-only": {"check": "contradicts_user_intent", "field": "proposed_tool_call"},
    "non-destructive": {"check": "contradicts_user_intent", "field": "proposed_tool_call"},
    "sensitive": {"check": "contains_sensitive_content", "field": "arguments.body|arguments.title"},
    "external participant": {"check": "has_external_participant_or_public", "field": "arguments.participants"},
    "public": {"check": "has_external_participant_or_public", "field": "arguments.visibility"},
    "internal information": {"check": "contains_internal_reference", "field": "arguments.body|arguments.title"},
    "internal reference": {"check": "contains_internal_reference", "field": "arguments.body|arguments.title"},
    "bulk": {"check": "count_greater_than", "field": "arguments.targets", "value": 1},
    "multiple": {"check": "count_greater_than", "field": "arguments.targets", "value": 1},
}

# Decision keyword mapping
DECISION_KEYWORDS = {
    "BLOCK": ["block", "deny", "reject", "prevent", "stop", "prohibit"],
    "ASK_APPROVAL": ["approval", "approve", "confirm", "ask", "require approval", "escalate"],
    "ALLOW": ["allow", "permit", "accept"],
}

# Risk level keyword mapping
RISK_KEYWORDS = {
    "critical": ["critical", "severe", "credential", "secret", "injection", "exfiltration"],
    "high": ["high", "dangerous", "delete", "destruction", "destructive"],
    "medium": ["medium", "moderate", "sensitive", "internal", "approval"],
    "low": ["low", "safe", "normal", "benign"],
}

# Attack category keyword mapping
ATTACK_CATEGORY_KEYWORDS = {
    "prompt_injection": ["injection", "override", "untrusted", "ignore instructions"],
    "data_exfiltration": ["exfiltration", "leak", "external", "private", "sensitive", "credential", "secret"],
    "unauthorized_action": ["unauthorized", "bulk", "delete", "destructive", "not requested"],
}

def _extract_markdown_field(text: str, label: str) -> str | None:
    """Return the one-line value for a bold markdown policy field."""
    match = re.search(rf"^\*\*{re.escape(label)}:\*\*\s*(.+)$", text, re.MULTILINE)
    return match.group(1).strip() if match else None


class PolicyCompilerAgent:
    """
    Compiles natural-language security policies into structured
    JSON rules for the AgentShield firewall.
    """

    def __init__(self):
        self.compiled_rules: list[CompiledRule] = []
        self.errors: list[str] = []

    def _extract_tools(self, text: str) -> list[str]:
        """Extract target tools from policy text."""
        applies_to = _extract_markdown_field(text, "Applies to")
        if applies_to:
            applies_lower = applies_to.lower()
            if "all tools" in applies_lower:
                return ALL_TOOLS

            tools = set()
            for token in re.findall(r'`(\w+)`', applies_to):
                if token in TOOL_KEYWORD_MAP:
                    tools.update(TOOL_KEYWORD_MAP[token])
            if tools:
                return sorted(tools)

        text_lower = text.lower()

        if "all tools" in text_lower:
            return ALL_TOOLS

        tools = set()
        backtick_tools = re.findall(r'`(\w+)`', text)
        for bt in backtick_tools:
            if bt in TOOL_KEYWORD_MAP:
                tools.update(TOOL_KEYWORD_MAP[bt])
        if tools:
            return sorted(tools)

        # Check for keyword matches
        for keyword, tool_list in TOOL_KEYWORD_MAP.items():
            if keyword in text_lower:
                tools.update(tool_list)

        return list(tools) if tools else ALL_TOOLS

    def _extract_decision(self, text: str) -> str:
        """Extract the decision (BLOCK, ASK_APPROVAL, ALLOW) from policy text."""
        decision_field = _extract_markdown_field(text, "Decision")
        if decision_field:
            normalized = decision_field.strip().upper()
            if normalized in DECISION_KEYWORDS:
                return normalized

        text_lower = text.lower()

        # Check for explicit decision labels first
        if "ASK_APPROVAL" in text or "ask_approval" in text_lower:
            return "ASK_APPROVAL"
        if "BLOCK" in text or "block" in text_lower:
            return "BLOCK"
        if "ALLOW" in text or "allow" in text_lower:
            return "ALLOW"

        # Keyword matching
        for decision, keywords in DECISION_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                return decision

        return "BLOCK"  # Default to most restrictive

    def _extract_risk_level(self, text: str) -> str:
        """Extract risk level from policy text."""
        text_lower = text.lower()

        for level, keywords in RISK_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                return level

        return "medium"  # Default

    def _extract_attack_categories(self, text: str) -> list[str]:
        """Extract attack categories from policy text."""
        text_lower = text.lower()
        categories = []

        for category, keywords in ATTACK_CATEGORY_KEYWORDS.items():
            if any(kw in text_lower for kw in keywords):
                categories.append(category)

        return categories if categories else ["unauthorized_action"]

    def _extract_conditions(self, text: str, tools: list[str]) -> dict:
        """Extract condition checks from policy text."""
        text_lower = text.lower()
        checks = []

        for keyword, check_config in CONDITION_KEYWORD_MAP.items():
            if keyword in text_lower:
                check = {
                    "field": check_config["field"],
                    "check": check_config["check"],
                    "description": f"Detected '{keyword}' pattern in policy.",
                }
                # Add patterns for pattern-matching checks
                if check_config["check"] == "contains_secret_pattern":
                    check["patterns"] = SECRET_PATTERNS
                elif check_config["check"] == "contains_instruction_pattern":
                    check["patterns"] = INJECTION_PATTERNS
                elif "value" in check_config:
                    check["value"] = check_config["value"]

                # Avoid duplicate check types
                existing_types = [c["check"] for c in checks]
                if check["check"] not in existing_types:
                    checks.append(check)

        if not checks:
            return {"operator": "ALWAYS", "checks": []}

        operator = "AND" if len(checks) > 1 else "AND"
        return {"operator": operator, "checks": checks}

    def _generate_explanation_template(
        self, name: str, decision: str, tools: list[str]
    ) -> str:
        """Generate an explanation template for the rule."""
        if decision == "BLOCK":
            return (
                f"Blocked: {name}. The proposed tool call violates this security policy "
                f"and has been blocked to prevent potential harm."
            )
        elif decision == "ASK_APPROVAL":
            return (
                f"Approval required: {name}. This action requires explicit user confirmation "
                f"before it can proceed."
            )
        else:
            return (
                f"Allowed: {name}. The proposed tool call passed all security checks."
            )

    def compile_policy(
        self,
        policy_id: str,
        name: str,
        full_text: str,
        priority: Optional[int] = None,
    ) -> Optional[CompiledRule]:
        """
        Compile a single natural-language policy into a structured rule.

        Args:
            policy_id: Unique ID for the rule (e.g., POLICY-001)
            name: Human-readable policy name
            full_text: The full natural-language policy text
            priority: Optional priority override

        Returns:
            CompiledRule or None if compilation fails
        """
        try:
            tools = self._extract_tools(full_text)
            decision = self._extract_decision(full_text)
            risk_level = self._extract_risk_level(full_text)
            attack_categories = self._extract_attack_categories(full_text)
            conditions = self._extract_conditions(full_text, tools)
            explanation = self._generate_explanation_template(name, decision, tools)

            if priority is None:
                priority = {"BLOCK": 1, "ASK_APPROVAL": 2, "ALLOW": 3}.get(
                    decision, 2
                )

            rule = CompiledRule(
                rule_id=policy_id,
                name=name,
                description=full_text.strip()[:200],
                priority=priority,
                enabled=True,
                tools=tools,
                conditions=conditions,
                decision=decision,
                risk_level=risk_level,
                attack_categories=attack_categories,
                explanation_template=explanation,
            )

            return rule

        except Exception as e:
            self.errors.append(f"Failed to compile {policy_id} ({name}): {str(e)}")
            return None

    def compile_from_file(self, filepath: str) -> CompilationResult:
        """
        Parse a markdown policy file and compile all policies into rules.

        Expects policies formatted as:
            ## Policy N: Name
            **Rule:** ...
            **Applies to:** ...
            **Condition:** ...
            **Decision:** ...
            **Example:** ...
        """
        path = Path(filepath)
        if not path.exists():
            return CompilationResult(
                total_policies=0,
                compiled_rules=0,
                skipped=0,
                errors=[f"File not found: {filepath}"],
                rules=[],
            )

        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        # Split by policy sections (## Policy N: ...)
        policy_sections = re.split(r'(?=## Policy \d+)', content)
        policy_sections = [s.strip() for s in policy_sections if s.strip()]

        total = 0
        compiled = 0
        skipped = 0
        self.compiled_rules = []
        self.errors = []

        for section in policy_sections:
            # Extract policy number and name
            policy_text = section.split("\n---", 1)[0].strip()
            header_match = re.match(r'## Policy (\d+):\s*(.+?)(?:\n|$)', policy_text)
            if not header_match:
                continue

            total += 1
            policy_num = header_match.group(1)
            policy_name = header_match.group(2).strip()
            policy_id = f"POLICY-{policy_num.zfill(3)}"

            rule = self.compile_policy(policy_id, policy_name, policy_text)

            if rule:
                self.compiled_rules.append(rule)
                compiled += 1
            else:
                skipped += 1

        return CompilationResult(
            total_policies=total,
            compiled_rules=compiled,
            skipped=skipped,
            errors=self.errors,
            rules=self.compiled_rules,
        )

    def compile_from_rules_json(self, filepath: str) -> CompilationResult:
        """
        Load and validate existing compiled rules from JSON.
        Useful for verifying the current ruleset.
        """
        path = Path(filepath)
        if not path.exists():
            return CompilationResult(
                total_policies=0,
                compiled_rules=0,
                skipped=0,
                errors=[f"File not found: {filepath}"],
                rules=[],
            )

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        rules_data = data.get("rules", [])
        self.compiled_rules = []
        self.errors = []

        for rd in rules_data:
            try:
                rule = CompiledRule(
                    rule_id=rd["rule_id"],
                    name=rd["name"],
                    description=rd.get("description", ""),
                    priority=rd.get("priority", 2),
                    enabled=rd.get("enabled", True),
                    tools=rd.get("tools", []),
                    conditions=rd.get("conditions", {}),
                    decision=rd["decision"],
                    risk_level=rd.get("risk_level", "medium"),
                    attack_categories=rd.get("attack_categories", []),
                    explanation_template=rd.get("explanation_template", ""),
                )
                self.compiled_rules.append(rule)
            except KeyError as e:
                self.errors.append(f"Missing required field in rule: {e}")

        return CompilationResult(
            total_policies=len(rules_data),
            compiled_rules=len(self.compiled_rules),
            skipped=len(rules_data) - len(self.compiled_rules),
            errors=self.errors,
            rules=self.compiled_rules,
        )

    def export_rules(self, filepath: str):
        """Export compiled rules to JSON file in firewall-compatible format."""
        output = {
            "schema_version": "0.1",
            "description": "Compiled policy rules generated by PolicyCompilerAgent.",
            "default_decision": "ALLOW",
            "rules": [r.to_dict() for r in self.compiled_rules],
        }

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2)

        print(f"Exported {len(self.compiled_rules)} compiled rules to {filepath}")

    def validate_rules(self) -> list[str]:
        """
        Validate the current compiled ruleset for common issues.
        Returns a list of warnings.
        """
        warnings = []

        if not self.compiled_rules:
            warnings.append("No compiled rules found.")
            return warnings

        # Check for duplicate rule IDs
        rule_ids = [r.rule_id for r in self.compiled_rules]
        duplicates = set(
            rid for rid in rule_ids if rule_ids.count(rid) > 1
        )
        if duplicates:
            warnings.append(f"Duplicate rule IDs found: {duplicates}")

        # Check for empty tool lists
        for rule in self.compiled_rules:
            if not rule.tools:
                warnings.append(f"{rule.rule_id}: No tools specified.")

        # Check for rules with no conditions
        for rule in self.compiled_rules:
            checks = rule.conditions.get("checks", [])
            operator = rule.conditions.get("operator", "")
            if not checks and operator != "ALWAYS":
                warnings.append(
                    f"{rule.rule_id}: No condition checks and operator is not ALWAYS."
                )

        # Check all 8 tools are covered
        covered_tools = set()
        for rule in self.compiled_rules:
            covered_tools.update(rule.tools)
        missing_tools = set(ALL_TOOLS) - covered_tools
        if missing_tools:
            warnings.append(f"Tools not covered by any rule: {missing_tools}")

        # Check for conflicting rules on same tool
        tool_decisions = {}
        for rule in self.compiled_rules:
            for tool in rule.tools:
                if tool not in tool_decisions:
                    tool_decisions[tool] = []
                tool_decisions[tool].append(
                    (rule.rule_id, rule.decision, rule.priority)
                )

        for tool, entries in tool_decisions.items():
            decisions = set(d for _, d, _ in entries)
            if len(decisions) > 1:
                decisions_by_priority = {}
                for _, decision, priority in entries:
                    decisions_by_priority.setdefault(priority, set()).add(decision)
                if any(len(decisions) > 1 for decisions in decisions_by_priority.values()):
                    warnings.append(
                        f"Tool '{tool}' has rules with same priority but different decisions: {entries}"
                    )

        return warnings

    def get_summary(self) -> dict:
        """Get a summary of the compiled ruleset."""
        if not self.compiled_rules:
            return {"total_rules": 0}

        decisions = {}
        risk_levels = {}
        tools_covered = set()

        for rule in self.compiled_rules:
            decisions[rule.decision] = decisions.get(rule.decision, 0) + 1
            risk_levels[rule.risk_level] = risk_levels.get(rule.risk_level, 0) + 1
            tools_covered.update(rule.tools)

        return {
            "total_rules": len(self.compiled_rules),
            "decisions": decisions,
            "risk_levels": risk_levels,
            "tools_covered": sorted(tools_covered),
            "tools_missing": sorted(set(ALL_TOOLS) - tools_covered),
        }
