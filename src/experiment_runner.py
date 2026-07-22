"""Repeatable experiment workflow for AgentShield."""

import json
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
        return result


def main() -> None:
    runner = ExperimentRunner()
    result = runner.export("data/evaluation/experiment_run.json")
    print(
        "Experiment complete: "
        f"{result['scenario_count']} scenarios -> data/evaluation/experiment_run.json"
    )


if __name__ == "__main__":
    main()
