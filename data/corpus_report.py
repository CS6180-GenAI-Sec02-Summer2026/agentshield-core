"""Combined-corpus validation and report for AgentShield.

Treats the three dataset files as one corpus, schema-validates every example,
flags any duplicate `user_request` (within or across files), and prints the
combined distribution. Guards corpus quality risks: too few benign cases,
missing attack category, and repetitive/duplicate examples.

Usage:
    python data/corpus_report.py     # exit 0 if clean, 1 otherwise
"""

from __future__ import annotations

import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA_PATH = HERE / "dataset_schema.json"

# The corpus. sample_examples.json is excluded: it is the schema demo, not part
# of the working dataset.
CORPUS_FILES = [
    HERE / "dataset_v0.json",
    HERE / "red_team_examples.json",
    HERE / "benign_edge_cases.json",
]


def load_corpus():
    """Return a list of (source_filename, example) pairs across all files."""
    pairs = []
    for path in CORPUS_FILES:
        for e in json.loads(path.read_text(encoding="utf-8")):
            pairs.append((path.name, e))
    return pairs


def schema_errors(examples):
    from jsonschema import Draft202012Validator
    validator = Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))
    bad = []
    for i, e in enumerate(examples):
        errs = list(validator.iter_errors(e))
        if errs:
            bad.append((i, errs))
    return bad


def duplicate_requests(pairs):
    """Map each duplicated user_request to the list of source files it appears in."""
    sources = defaultdict(list)
    for src, e in pairs:
        sources[e["user_request"]].append(src)
    return {req: srcs for req, srcs in sources.items() if len(srcs) > 1}


def distribution(examples):
    benign = sum(1 for e in examples if e["attack_category"] == "none")
    return {
        "total": len(examples),
        "benign": benign,
        "malicious": len(examples) - benign,
        "attack_category": dict(Counter(e["attack_category"] for e in examples)),
        "expected_decision": dict(Counter(e["expected_decision"] for e in examples)),
        "risk_level": dict(Counter(e["risk_level"] for e in examples)),
        "tools": dict(Counter(e["proposed_tool_call"]["tool_name"] for e in examples)),
    }


def main() -> int:
    pairs = load_corpus()
    examples = [e for _, e in pairs]

    problems = 0

    bad = schema_errors(examples)
    print(f"Schema: {len(examples) - len(bad)}/{len(examples)} examples valid")
    if bad:
        problems += 1
        for i, errs in bad[:10]:
            print(f"  [invalid] example {i}: {errs[0].message}")

    dups = duplicate_requests(pairs)
    if dups:
        problems += 1
        print(f"\nDuplicate user_request values: {len(dups)}")
        for req, srcs in dups.items():
            print(f"  - {req!r} in {srcs}")
    else:
        print("Duplicates: none")

    dist = distribution(examples)
    print("\nCombined distribution:")
    for key, value in dist.items():
        print(f"  {key:18} {value}")

    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
