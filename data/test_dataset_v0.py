"""Balance and consistency tests for data/dataset_v0.json (M2-S2).

These guard the M2-S2 "bug items to track": invalid labels, unbalanced dataset
categories, and low-quality/duplicate examples. They also confirm the whole
file still conforms to the schema via the shared validator.

Run with either:
    pytest data/test_dataset_v0.py
    python data/test_dataset_v0.py      # no pytest required
"""

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
DATASET_PATH = HERE / "dataset_v0.json"
VALIDATOR = HERE / "validate_dataset.py"

ALL_TOOLS = {
    "send_email", "read_file", "write_file", "delete_file",
    "create_calendar_event", "create_task", "create_github_issue",
    "send_http_request",
}
ATTACK_CATEGORIES = {"prompt_injection", "data_exfiltration", "unauthorized_action"}


def _load():
    return json.loads(DATASET_PATH.read_text(encoding="utf-8"))


DATASET = _load()


# --- Schema conformance ---------------------------------------------------

def test_dataset_passes_schema_validator():
    """The whole file must pass the shared schema validator (exit code 0)."""
    result = subprocess.run(
        [sys.executable, str(VALIDATOR), str(DATASET_PATH)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout


# --- Size and benign/malicious split -------------------------------------

def test_total_size():
    assert len(DATASET) == 50


def test_benign_malicious_split():
    benign = [e for e in DATASET if e["attack_category"] == "none"]
    malicious = [e for e in DATASET if e["attack_category"] != "none"]
    assert len(benign) == 25, f"expected 25 benign, got {len(benign)}"
    assert len(malicious) == 25, f"expected 25 malicious, got {len(malicious)}"


# --- Coverage (nothing missing) ------------------------------------------

def test_all_tools_present():
    used = {e["proposed_tool_call"]["tool_name"] for e in DATASET}
    assert used == ALL_TOOLS, f"missing tools: {ALL_TOOLS - used}"


def test_all_decisions_present():
    decisions = {e["expected_decision"] for e in DATASET}
    assert decisions == {"ALLOW", "BLOCK", "ASK_APPROVAL"}


def test_all_risk_levels_present():
    risks = {e["risk_level"] for e in DATASET}
    assert risks == {"low", "medium", "high", "critical"}


def test_all_attack_categories_present():
    cats = {e["attack_category"] for e in DATASET if e["attack_category"] != "none"}
    assert cats == ATTACK_CATEGORIES, f"missing categories: {ATTACK_CATEGORIES - cats}"


def test_attack_categories_roughly_balanced():
    """No single attack category should dominate the malicious half."""
    counts = Counter(
        e["attack_category"] for e in DATASET if e["attack_category"] != "none"
    )
    for cat in ATTACK_CATEGORIES:
        assert counts[cat] >= 5, f"attack category {cat} underrepresented: {counts[cat]}"


# --- Balance (no tool dominates) -----------------------------------------

def test_no_tool_dominates():
    counts = Counter(e["proposed_tool_call"]["tool_name"] for e in DATASET)
    top_share = max(counts.values()) / len(DATASET)
    assert top_share <= 0.40, f"a tool dominates the dataset: {counts.most_common(1)}"


# --- Label consistency (guards 'invalid labels') --------------------------

def test_benign_label_consistency():
    for i, e in enumerate(DATASET):
        if e["attack_category"] == "none":
            assert e["expected_decision"] in {"ALLOW", "ASK_APPROVAL"}, \
                f"benign example {i} has decision {e['expected_decision']}"


def test_malicious_label_consistency():
    for i, e in enumerate(DATASET):
        if e["attack_category"] != "none":
            assert e["expected_decision"] in {"BLOCK", "ASK_APPROVAL"}, \
                f"malicious example {i} has decision {e['expected_decision']}"
            assert e["risk_level"] in {"high", "critical"}, \
                f"malicious example {i} has risk {e['risk_level']}"


def test_prompt_injection_has_external_context():
    for i, e in enumerate(DATASET):
        if e["attack_category"] == "prompt_injection":
            assert e["external_context"], \
                f"prompt_injection example {i} is missing external_context"


# --- Quality (guards duplicates) -----------------------------------------

def test_no_duplicate_user_requests():
    dups = [u for u, c in Counter(e["user_request"] for e in DATASET).items() if c > 1]
    assert not dups, f"duplicate user_request values: {dups}"


def test_all_explanations_nonempty():
    for i, e in enumerate(DATASET):
        assert e["explanation"].strip(), f"example {i} has an empty explanation"


# --- Fallback runner ------------------------------------------------------

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
