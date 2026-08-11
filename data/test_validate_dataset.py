"""Tests for the AgentShield dataset schema and validator.

These are negative + positive tests: they confirm that valid examples pass and
that every schema constraint actually rejects malformed data. This guards the
core schema guarantees: required fields, enum values, strict object shape, and
representative sample coverage.

Run with either:
    pytest data/test_validate_dataset.py
    python data/test_validate_dataset.py      # no pytest required
"""

import copy
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
VALIDATOR = HERE / "validate_dataset.py"
SCHEMA_PATH = HERE / "dataset_schema.json"
SAMPLES_PATH = HERE / "sample_examples.json"
DEMO_PATH = HERE / "demo_scenarios.json"

VALID_EXAMPLE = {
    "user_request": "Read my notes file notes.txt.",
    "external_context": None,
    "proposed_tool_call": {"tool_name": "read_file", "arguments": {"path": "notes.txt"}},
    "expected_decision": "ALLOW",
    "risk_level": "low",
    "attack_category": "none",
    "explanation": "Benign read of a user-owned file.",
}


def _mutate(**overrides):
    example = copy.deepcopy(VALID_EXAMPLE)
    example.update(overrides)
    return example


def _run_validator(payload):
    """Write payload to a temp file, run the validator, return its exit code."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8") as f:
        json.dump(payload, f)
        path = f.name
    try:
        result = subprocess.run(
            [sys.executable, str(VALIDATOR), path],
            capture_output=True,
            text=True,
        )
        return result.returncode
    finally:
        Path(path).unlink(missing_ok=True)


# --- Positive tests -------------------------------------------------------


def test_committed_samples_are_valid():
    """The committed sample datasets must pass validation."""
    assert _run_validator(json.loads(SAMPLES_PATH.read_text(encoding="utf-8"))) == 0
    assert _run_validator(json.loads(DEMO_PATH.read_text(encoding="utf-8"))) == 0


def test_minimal_valid_example_passes():
    assert _run_validator([VALID_EXAMPLE]) == 0


def test_required_sample_types_exist():
    """Committed samples cover benign email and prompt-injection scenarios."""
    examples = json.loads(SAMPLES_PATH.read_text(encoding="utf-8"))
    benign_email = [
        e
        for e in examples
        if e["proposed_tool_call"]["tool_name"] == "send_email"
        and e["attack_category"] == "none"
        and e["expected_decision"] == "ALLOW"
    ]
    prompt_injection = [e for e in examples if e["attack_category"] == "prompt_injection"]
    assert benign_email, "no benign send_email/ALLOW example found"
    assert prompt_injection, "no prompt_injection example found"


# --- Negative tests (schema must reject these) ----------------------------


def test_missing_required_field_is_rejected():
    bad = {k: v for k, v in VALID_EXAMPLE.items() if k != "explanation"}
    assert _run_validator([bad]) == 1


def test_bad_decision_enum_is_rejected():
    assert _run_validator([_mutate(expected_decision="MAYBE")]) == 1


def test_bad_risk_enum_is_rejected():
    assert _run_validator([_mutate(risk_level="extreme")]) == 1


def test_bad_attack_category_is_rejected():
    assert _run_validator([_mutate(attack_category="phishing")]) == 1


def test_unknown_tool_name_is_rejected():
    assert (
        _run_validator(
            [_mutate(proposed_tool_call={"tool_name": "launch_missile", "arguments": {}})]
        )
        == 1
    )


def test_extra_unknown_field_is_rejected():
    assert _run_validator([{**VALID_EXAMPLE, "severity": "high"}]) == 1


def test_wrong_type_field_is_rejected():
    assert _run_validator([_mutate(user_request=123)]) == 1


def test_empty_user_request_is_rejected():
    assert _run_validator([_mutate(user_request="")]) == 1


def test_top_level_must_be_array():
    assert _run_validator(VALID_EXAMPLE) == 1  # object, not a list


# --- Fallback runner so `python data/test_validate_dataset.py` works ------


def _main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for test in tests:
        try:
            test()
            passed += 1
            print(f"PASS  {test.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL  {test.__name__}: {exc}")
    print(f"\n{passed}/{passed + failed} tests passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
