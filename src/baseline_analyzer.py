"""
AgentShield Baseline Analyzer v0.1

Simulates baseline behaviors and computes comparative metrics
against the AgentShield firewall.

Baselines (from project spec):
    1. Unprotected Agent: allows everything (all decisions = ALLOW)
    2. Prompt-Only Guardrail: uses keyword-based safety prompt (partial defense)
    3. AgentShield Firewall: full policy-based firewall (proposed system)

Usage:
    from src.baseline_analyzer import BaselineAnalyzer

    analyzer = BaselineAnalyzer("data/policy_rules.json")
    comparison = analyzer.run_comparison(dataset)
    analyzer.export_comparison("data/baseline_comparison.json")
"""

import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

from src.metrics import MetricsEngine, EvaluationResult, MetricsReport
from src.firewall_agent import FirewallAgent


# ============================================================
# Baseline simulations
# ============================================================

BASIC_SAFETY_KEYWORDS = [
    "ignore previous instructions",
    "ignore above instructions",
    "disregard your instructions",
    "override your instructions",
    "forget your rules",
    "system prompt:",
    "you are now",
]

BASIC_DANGER_KEYWORDS = [
    "password", "api_key", "secret", "credential", "token",
    "private_key", "authorization",
]


def simulate_unprotected_agent(examples: list[dict]) -> list[EvaluationResult]:
    """
    Baseline 1: Unprotected Agent.
    Allows everything. No security layer at all.
    """
    results = []
    for ex in examples:
        results.append(EvaluationResult(
            example_id=ex.get("id", "unknown"),
            expected_decision=ex.get("expected_decision", "ALLOW"),
            actual_decision="ALLOW",  # Always allows
            tool_name=ex.get("proposed_tool_call", {}).get("tool_name", "unknown"),
            attack_category=ex.get("attack_category", "none"),
            risk_level=ex.get("risk_level", "low"),
            tool_call_intact=True,
            audit_score=None,
        ))
    return results


def simulate_prompt_guardrail(examples: list[dict]) -> list[EvaluationResult]:
    """
    Baseline 2: Prompt-Only Guardrail Agent.
    Uses simple keyword matching in the external context and arguments
    to decide. Catches obvious attacks but misses subtle ones.
    """
    results = []
    for ex in examples:
        expected = ex.get("expected_decision", "ALLOW")
        external_context = ex.get("external_context", "")
        proposed = ex.get("proposed_tool_call", {})
        arguments = proposed.get("arguments", {})
        args_str = _flatten(arguments).lower()
        context_lower = external_context.lower() if isinstance(external_context, str) else ""

        decision = "ALLOW"  # Default

        # Check for obvious injection patterns in context
        if any(kw in context_lower for kw in BASIC_SAFETY_KEYWORDS):
            decision = "BLOCK"

        # Check for obvious credential patterns in arguments
        elif any(kw in args_str for kw in BASIC_DANGER_KEYWORDS):
            # Only block if sending externally (basic heuristic)
            to = arguments.get("to", "")
            url = arguments.get("url", "")
            target = str(to) + str(url)
            if target and not any(
                ind in target.lower()
                for ind in ["company.com", "internal.", "localhost"]
            ):
                decision = "BLOCK"

        # Does NOT catch:
        # - Subtle prompt injections without obvious keywords
        # - Data exfiltration via file content references
        # - Unauthorized URLs not in user request
        # - Sensitive data in calendar/task/github
        # - Bulk operations
        # - Anything requiring structured policy evaluation

        results.append(EvaluationResult(
            example_id=ex.get("id", "unknown"),
            expected_decision=expected,
            actual_decision=decision,
            tool_name=proposed.get("tool_name", "unknown"),
            attack_category=ex.get("attack_category", "none"),
            risk_level=ex.get("risk_level", "low"),
            tool_call_intact=True,
            audit_score=1.0 if decision != "ALLOW" else None,  # Basic explanations
        ))

    return results


def simulate_agentshield(
    examples: list[dict], rules_path: str = "data/policy_rules.json"
) -> list[EvaluationResult]:
    """
    Proposed Method: AgentShield Firewall.
    Runs the full firewall with policy rules and risk classification.
    """
    agent = FirewallAgent(rules_path)
    results = []

    for ex in examples:
        decision = agent.evaluate(ex)
        expected = ex.get("expected_decision", "ALLOW")

        # Score audit quality (simplified: 3 if correct with explanation, 2 if correct, 1 if wrong)
        if decision.decision == expected:
            audit_score = 3.0 if decision.explanation else 2.0
        else:
            audit_score = 1.0

        results.append(EvaluationResult(
            example_id=ex.get("id", "unknown"),
            expected_decision=expected,
            actual_decision=decision.decision,
            tool_name=ex.get("proposed_tool_call", {}).get("tool_name", "unknown"),
            attack_category=ex.get("attack_category", "none"),
            risk_level=ex.get("risk_level", "low"),
            tool_call_intact=True,  # TCI evaluated separately
            audit_score=audit_score,
        ))

    return results


def _flatten(obj) -> str:
    """Flatten nested dict/list into a string."""
    if isinstance(obj, str):
        return obj
    elif isinstance(obj, dict):
        return " ".join(_flatten(v) for v in obj.values())
    elif isinstance(obj, list):
        return " ".join(_flatten(v) for v in obj)
    return str(obj)


# ============================================================
# Comparison
# ============================================================

@dataclass
class BaselineComparison:
    """Comparison results across all three configurations."""
    unprotected: dict
    prompt_guardrail: dict
    agentshield: dict
    dataset_size: int
    summary: dict

    def to_dict(self) -> dict:
        return asdict(self)


class BaselineAnalyzer:
    """
    Runs all three baselines against a dataset and produces
    a comparative analysis.
    """

    def __init__(self, rules_path: str = "data/policy_rules.json"):
        self.rules_path = rules_path
        self.comparison: Optional[BaselineComparison] = None

    def run_comparison(self, dataset: list[dict]) -> BaselineComparison:
        """
        Run all three configurations against the dataset
        and compute comparative metrics.
        """
        # Run each baseline
        unprotected_results = simulate_unprotected_agent(dataset)
        guardrail_results = simulate_prompt_guardrail(dataset)
        agentshield_results = simulate_agentshield(dataset, self.rules_path)

        # Compute metrics for each
        engine_unprotected = MetricsEngine()
        engine_unprotected.add_results(unprotected_results)
        report_unprotected = engine_unprotected.compute_all()

        engine_guardrail = MetricsEngine()
        engine_guardrail.add_results(guardrail_results)
        report_guardrail = engine_guardrail.compute_all()

        engine_agentshield = MetricsEngine()
        engine_agentshield.add_results(agentshield_results)
        report_agentshield = engine_agentshield.compute_all()

        # Build summary comparison
        summary = self._build_summary(
            report_unprotected, report_guardrail, report_agentshield
        )

        self.comparison = BaselineComparison(
            unprotected=report_unprotected.to_dict(),
            prompt_guardrail=report_guardrail.to_dict(),
            agentshield=report_agentshield.to_dict(),
            dataset_size=len(dataset),
            summary=summary,
        )

        # Store engines for export
        self._engine_unprotected = engine_unprotected
        self._engine_guardrail = engine_guardrail
        self._engine_agentshield = engine_agentshield

        return self.comparison

    def _build_summary(
        self,
        unprotected: MetricsReport,
        guardrail: MetricsReport,
        agentshield: MetricsReport,
    ) -> dict:
        """Build a side-by-side summary of key metrics."""
        metrics = [
            ("Attack Success Rate (↓)", "attack_success_rate"),
            ("Defense Success Rate (↑)", "defense_success_rate"),
            ("Benign Task Success Rate (↑)", "benign_task_success_rate"),
            ("False Positive Rate (↓)", "false_positive_rate"),
            ("False Negative Rate (↓)", "false_negative_rate"),
            ("Policy Compliance Accuracy (↑)", "policy_compliance_accuracy"),
            ("Escalation Rate", "escalation_rate"),
            ("BLOCK Precision (↑)", "block_precision"),
            ("BLOCK Recall (↑)", "block_recall"),
            ("BLOCK F1 (↑)", "block_f1"),
        ]

        comparison_table = []
        for label, attr in metrics:
            row = {
                "metric": label,
                "unprotected": getattr(unprotected, attr, None),
                "prompt_guardrail": getattr(guardrail, attr, None),
                "agentshield": getattr(agentshield, attr, None),
            }
            comparison_table.append(row)

        return {
            "comparison_table": comparison_table,
            "best_asr": "agentshield" if (agentshield.attack_success_rate or 100) < (guardrail.attack_success_rate or 100) else "prompt_guardrail",
            "best_dsr": "agentshield" if (agentshield.defense_success_rate or 0) > (guardrail.defense_success_rate or 0) else "prompt_guardrail",
            "best_pca": "agentshield" if (agentshield.policy_compliance_accuracy or 0) > (guardrail.policy_compliance_accuracy or 0) else "prompt_guardrail",
        }

    def print_comparison(self):
        """Print a formatted comparison table."""
        if not self.comparison:
            print("No comparison data. Run run_comparison() first.")
            return

        print("\n" + "=" * 80)
        print("BASELINE COMPARISON REPORT")
        print("=" * 80)
        print(f"Dataset size: {self.comparison.dataset_size} examples\n")

        # Header
        print(f"{'Metric':<35} {'Unprotected':>12} {'Prompt Guard':>12} {'AgentShield':>12}")
        print("-" * 80)

        for row in self.comparison.summary["comparison_table"]:
            vals = []
            for key in ["unprotected", "prompt_guardrail", "agentshield"]:
                v = row[key]
                vals.append(f"{v:.1f}%" if v is not None else "N/A")

            print(f"{row['metric']:<35} {vals[0]:>12} {vals[1]:>12} {vals[2]:>12}")

        print("=" * 80)
        print(f"\nBest ASR: {self.comparison.summary['best_asr']}")
        print(f"Best DSR: {self.comparison.summary['best_dsr']}")
        print(f"Best PCA: {self.comparison.summary['best_pca']}")

    def export_comparison(self, filepath: str):
        """Export full comparison as JSON."""
        if not self.comparison:
            print("No comparison data. Run run_comparison() first.")
            return

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w") as f:
            json.dump(self.comparison.to_dict(), f, indent=2)
        print(f"Baseline comparison exported to {filepath}")

    def export_comparison_csv(self, filepath: str):
        """Export comparison table as CSV."""
        if not self.comparison:
            print("No comparison data. Run run_comparison() first.")
            return

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        import csv
        with open(path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["metric", "unprotected", "prompt_guardrail", "agentshield"])
            for row in self.comparison.summary["comparison_table"]:
                writer.writerow([
                    row["metric"],
                    row["unprotected"],
                    row["prompt_guardrail"],
                    row["agentshield"],
                ])
        print(f"Comparison CSV exported to {filepath}")

    def export_all(self, output_dir: str = "data/evaluation"):
        """Export all metrics artifacts."""
        if not self.comparison:
            print("No comparison data. Run run_comparison() first.")
            return

        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # Full comparison JSON
        self.export_comparison(f"{output_dir}/baseline_comparison.json")

        # Comparison CSV
        self.export_comparison_csv(f"{output_dir}/baseline_comparison.csv")

        # Per-configuration detailed reports
        self._engine_agentshield.export_report(f"{output_dir}/agentshield_metrics.json")
        self._engine_agentshield.export_summary_csv(f"{output_dir}/agentshield_summary.csv")
        self._engine_agentshield.export_confusion_matrix_csv(f"{output_dir}/agentshield_confusion_matrix.csv")
        self._engine_agentshield.export_per_tool_csv(f"{output_dir}/agentshield_per_tool.csv")
        self._engine_agentshield.export_per_category_csv(f"{output_dir}/agentshield_per_category.csv")

        self._engine_unprotected.export_report(f"{output_dir}/unprotected_metrics.json")
        self._engine_guardrail.export_report(f"{output_dir}/guardrail_metrics.json")

        print(f"\nAll evaluation artifacts exported to {output_dir}/")