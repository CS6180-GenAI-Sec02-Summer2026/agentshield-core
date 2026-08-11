"""Prompt-only guardrail baseline runner for AgentShield experiments."""

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from src.baseline_analyzer import simulate_prompt_guardrail
from src.metrics import MetricsEngine
from src.scenario_store import load_scenarios


def run_prompt_guardrail_baseline(dataset_names: list[str] | None = None) -> dict[str, Any]:
    """Run the prompt-only safety baseline and return results plus metrics."""
    scenarios = load_scenarios(dataset_names)
    results = simulate_prompt_guardrail(scenarios)
    engine = MetricsEngine()
    engine.add_results(results)
    return {
        "baseline": "prompt_guardrail",
        "total": len(results),
        "metrics": asdict(engine.compute_all()),
        "results": [asdict(result) for result in results],
    }


def export_prompt_guardrail_baseline(
    output_path: str = "data/evaluation/prompt_guardrail_baseline_run.json",
    dataset_names: list[str] | None = None,
) -> dict[str, Any]:
    """Run and export the prompt-only guardrail baseline."""
    result = run_prompt_guardrail_baseline(dataset_names)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def main() -> None:
    result = export_prompt_guardrail_baseline()
    print(f"Prompt guardrail baseline complete: {result['total']} scenarios.")


if __name__ == "__main__":
    main()
