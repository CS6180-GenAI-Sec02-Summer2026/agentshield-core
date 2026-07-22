"""Validate AgentShield dataset examples against dataset_schema.json.

Usage:
    python data/validate_dataset.py                      # validates data/sample_examples.json
    python data/validate_dataset.py path/to/examples.json

Exit code is 0 when every example is valid, 1 otherwise.
"""

import json
import sys
from pathlib import Path

try:
    from jsonschema import Draft202012Validator
except ImportError:
    sys.exit(
        "Missing dependency 'jsonschema'. Install it with:\n"
        "    pip install jsonschema"
    )

HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "dataset_schema.json"
DEFAULT_EXAMPLES_PATH = HERE / "sample_examples.json"


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def main():
    examples_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_EXAMPLES_PATH

    schema = load_json(SCHEMA_PATH)
    examples = load_json(examples_path)

    if not isinstance(examples, list):
        sys.exit(f"Expected a JSON array of examples in {examples_path}, got {type(examples).__name__}.")

    validator = Draft202012Validator(schema)

    failures = 0
    for i, example in enumerate(examples):
        errors = sorted(validator.iter_errors(example), key=lambda e: list(e.path))
        if errors:
            failures += 1
            print(f"[FAIL] example {i}:")
            for err in errors:
                location = "/".join(str(p) for p in err.path) or "(root)"
                print(f"    - at {location}: {err.message}")
        else:
            print(f"[ok]   example {i}")

    total = len(examples)
    print(f"\n{total - failures}/{total} examples valid.")

    if failures:
        sys.exit(1)


if __name__ == "__main__":
    main()
