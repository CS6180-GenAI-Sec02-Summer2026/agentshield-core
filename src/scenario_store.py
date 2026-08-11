"""Scenario loading helpers for AgentShield dataset and API flows."""

import json
from pathlib import Path
from typing import Any

from src.app_settings import AppSettings

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA_DIR = REPO_ROOT / "data"

DATASET_FILES = {
    "demo": "demo_scenarios.json",
    "sample": "sample_examples.json",
    "dataset_v0": "dataset_v0.json",
    "red_team": "red_team_examples.json",
    "benign_edge": "benign_edge_cases.json",
}


def available_datasets(data_dir: Path | str | None = None) -> list[dict[str, Any]]:
    """Return scenario datasets that are present in the current checkout."""
    root = _resolve_data_dir(data_dir)
    found = []
    for name, filename in DATASET_FILES.items():
        path = root / filename
        if not path.exists():
            continue
        rows = _load_json_list(path)
        found.append(
            {
                "name": name,
                "file": path.name,
                "count": len(rows),
            }
        )
    return found


def load_dataset(name: str, data_dir: Path | str | None = None) -> list[dict[str, Any]]:
    """Load one named scenario dataset and attach stable IDs/source metadata."""
    if name not in DATASET_FILES:
        supported = ", ".join(sorted(DATASET_FILES))
        raise ValueError(f"Unknown dataset '{name}'. Supported datasets: {supported}.")

    path = _resolve_data_dir(data_dir) / DATASET_FILES[name]
    rows = _load_json_list(path)
    return [_with_metadata(row, name, index) for index, row in enumerate(rows, start=1)]


def load_scenarios(
    names: list[str] | None = None,
    data_dir: Path | str | None = None,
) -> list[dict[str, Any]]:
    """Load all requested datasets, or every present dataset when names is omitted."""
    if names is None:
        names = [item["name"] for item in available_datasets(data_dir)]

    scenarios: list[dict[str, Any]] = []
    for name in names:
        scenarios.extend(load_dataset(name, data_dir))
    return scenarios


def get_scenario(scenario_id: str, data_dir: Path | str | None = None) -> dict[str, Any]:
    """Find one scenario by generated or explicit ID."""
    for scenario in load_scenarios(data_dir=data_dir):
        if scenario["id"] == scenario_id:
            return scenario
    raise KeyError(f"Scenario '{scenario_id}' was not found.")


def _load_json_list(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Scenario dataset not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"Scenario dataset must be a JSON array: {path}")
    return data


def _with_metadata(row: dict[str, Any], dataset_name: str, index: int) -> dict[str, Any]:
    scenario = dict(row)
    scenario.setdefault("id", f"{dataset_name}-{index:03d}")
    scenario["_source_dataset"] = dataset_name
    scenario["_source_index"] = index
    return scenario


def _resolve_data_dir(data_dir: Path | str | None) -> Path:
    configured = data_dir or AppSettings().data_dir or DEFAULT_DATA_DIR
    path = Path(configured)
    if path.is_absolute():
        return path
    cwd_path = Path.cwd() / path
    if cwd_path.exists():
        return cwd_path
    return REPO_ROOT / path
