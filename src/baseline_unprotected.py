"""Unprotected baseline runner for AgentShield experiments."""

from dataclasses import asdict
import json
from pathlib import Path
from typing import Any

from src.baseline_analyzer import simulate_unprotected_agent
from src.metrics import MetricsEngine
from src.scenario_store import load_scenarios


def run_unprotected_baseline(dataset_names: list[str] | None = None) -> dict[str, Any]:
    """Run the no-security baseline and return results plus metrics."""
    scenarios = load_scenarios(dataset_names)
    results = simulate_unprotected_agent(scenarios)
    engine = MetricsEngine()
    engine.add_results(results)
    return {
        "baseline": "unprotected",
        "total": len(results),
        "metrics": asdict(engine.compute_all()),
        "results": [asdict(result) for result in results],
    }


def export_unprotected_baseline(
    output_path: str = "data/evaluation/unprotected_baseline_run.json",
    dataset_names: list[str] | None = None,
) -> dict[str, Any]:
    """Run and export the unprotected baseline."""
    result = run_unprotected_baseline(dataset_names)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main() -> None:
    result = export_unprotected_baseline()
    print(f"Unprotected baseline complete: {result['total']} scenarios.")


if __name__ == "__main__":
    main()
