"""Repeatable experiment workflow for AgentShield."""

import json
import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.baseline_analyzer import BaselineAnalyzer
from src.orchestrator import AgentShieldOrchestrator
from src.scenario_store import load_scenarios


@dataclass
class ExperimentResult:
    exported_at: str
    dataset_names: list[str] | None
    scenario_count: int
    orchestration: dict[str, Any]
    baseline_comparison: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ExperimentRunner:
    """Run AgentShield workflow and baseline comparison on stored scenarios."""

    def __init__(self, rules_path: str = "data/policy_rules.json"):
        self.rules_path = rules_path

    def run(self, dataset_names: list[str] | None = None) -> ExperimentResult:
        scenarios = load_scenarios(dataset_names)
        orchestrator = AgentShieldOrchestrator(self.rules_path)
        orchestration = orchestrator.run_batch(scenarios=scenarios)

        analyzer = BaselineAnalyzer(self.rules_path)
        baseline_comparison = analyzer.run_comparison(scenarios).to_dict()

        return ExperimentResult(
            exported_at=datetime.now(timezone.utc).isoformat(),
            dataset_names=dataset_names,
            scenario_count=len(scenarios),
            orchestration=orchestration,
            baseline_comparison=baseline_comparison,
        )

    def export(self, output_path: str, dataset_names: list[str] | None = None) -> dict[str, Any]:
        result = self.run(dataset_names).to_dict()
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        self.export_summary_csv(path.with_suffix(".csv"), result)
        return result

    def export_summary_csv(self, output_path: str | Path, result: dict[str, Any]) -> None:
        """Export a compact one-row experiment summary for reports/dashboards."""
        path = Path(output_path)
        metrics = result["orchestration"].get("metrics") or {}
        summary = result["orchestration"].get("summary") or {}
        baseline = result["baseline_comparison"].get("summary", {})

        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(
                handle,
                lineterminator="\n",
                fieldnames=[
                    "scenario_count",
                    "decisions",
                    "policy_compliance_accuracy",
                    "attack_success_rate",
                    "defense_success_rate",
                    "best_asr",
                    "best_dsr",
                    "best_pca",
                ],
            )
            writer.writeheader()
            writer.writerow({
                "scenario_count": result["scenario_count"],
                "decisions": json.dumps(summary.get("decisions", {}), sort_keys=True),
                "policy_compliance_accuracy": metrics.get("policy_compliance_accuracy"),
                "attack_success_rate": metrics.get("attack_success_rate"),
                "defense_success_rate": metrics.get("defense_success_rate"),
                "best_asr": baseline.get("best_asr"),
                "best_dsr": baseline.get("best_dsr"),
                "best_pca": baseline.get("best_pca"),
            })


def main() -> None:
    runner = ExperimentRunner()
    result = runner.export("data/evaluation/experiment_run.json")
    print(
        "Experiment complete: "
        f"{result['scenario_count']} scenarios -> data/evaluation/experiment_run.json and .csv"
    )


if __name__ == "__main__":
    main()
