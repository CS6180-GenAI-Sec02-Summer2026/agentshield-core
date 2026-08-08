"""Generate data/red_team_examples.json from the red-team seeds.

This makes the adversarial dataset reproducible: re-running regenerates the same
schema-valid examples from the deterministic seeds. Kept separate from
data/dataset_v0.json so the verified baseline dataset stays stable.

Usage:
    python agents/generate_red_team.py
"""

from __future__ import annotations

import json
from pathlib import Path

try:  # works under pytest / when run from repo root
    from agents.red_team_agent import RedTeamAgent
    from agents.red_team_seeds import all_seeds
except ModuleNotFoundError:  # works when run from the agents/ directory
    from red_team_agent import RedTeamAgent
    from red_team_seeds import all_seeds

OUTPUT_PATH = Path(__file__).resolve().parent.parent / "data" / "red_team_examples.json"


def build_examples() -> list[dict]:
    """Generate the full list of adversarial examples from the seeds.

    Each example gets a stable ``id`` (``rt-001`` ...) so it can be looked up by
    the backend scenario store.
    """
    examples = RedTeamAgent().generate_examples(all_seeds())
    return [{"id": f"rt-{i:03d}", **e} for i, e in enumerate(examples, 1)]


def main() -> None:
    examples = build_examples()
    OUTPUT_PATH.write_text(json.dumps(examples, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(examples)} examples to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
