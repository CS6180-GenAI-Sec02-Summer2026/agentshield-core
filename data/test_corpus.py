"""Tests for the combined dataset corpus and the benign edge cases.

Guards corpus quality risks: dataset has too few benign cases, an attack category
is missing, and examples are too repetitive (duplicates).
"""

import json
import re
import sys
from pathlib import Path

from corpus_report import (
    CORPUS_FILES,
    distribution,
    duplicate_requests,
    load_corpus,
    schema_errors,
)

HERE = Path(__file__).resolve().parent
PAIRS = load_corpus()
EXAMPLES = [e for _, e in PAIRS]
BENIGN_EDGE = json.loads((HERE / "benign_edge_cases.json").read_text(encoding="utf-8"))

ATTACK_CATEGORIES = {"prompt_injection", "data_exfiltration", "unauthorized_action"}


# --- Combined corpus ------------------------------------------------------


def test_corpus_all_schema_valid():
    assert schema_errors(EXAMPLES) == []


def test_corpus_no_duplicate_requests():
    assert duplicate_requests(PAIRS) == {}, "repetitive/duplicate user_requests found"


def test_corpus_has_enough_benign():
    d = distribution(EXAMPLES)
    assert d["benign"] >= 25, f"too few benign cases: {d['benign']}"
    assert d["benign"] / d["total"] >= 0.30, f"benign fraction too low: {d}"


def test_corpus_all_attack_categories_present():
    cats = {e["attack_category"] for e in EXAMPLES if e["attack_category"] != "none"}
    assert cats == ATTACK_CATEGORIES, f"missing categories: {ATTACK_CATEGORIES - cats}"


def test_corpus_all_tools_present():
    tools = {e["proposed_tool_call"]["tool_name"] for e in EXAMPLES}
    assert len(tools) == 8, f"not all 8 tools present: {tools}"


def test_corpus_all_decisions_present():
    assert {e["expected_decision"] for e in EXAMPLES} == {"ALLOW", "BLOCK", "ASK_APPROVAL"}


def test_corpus_files_exist():
    for path in CORPUS_FILES:
        assert path.exists(), f"missing corpus file: {path}"


def test_corpus_ids_present_and_unique():
    """Every corpus example needs a unique id for backend scenario lookup."""
    ids = [e.get("id") for e in EXAMPLES]
    assert all(ids), "some corpus examples are missing an id"
    assert len(set(ids)) == len(ids), "duplicate ids in the corpus"


# --- Benign edge cases ----------------------------------------------------


def test_benign_edge_has_enough():
    assert len(BENIGN_EDGE) >= 10


def test_benign_edge_all_benign():
    assert all(e["attack_category"] == "none" for e in BENIGN_EDGE)


def test_benign_edge_decisions_are_allow_or_ask():
    for i, e in enumerate(BENIGN_EDGE):
        assert e["expected_decision"] in {"ALLOW", "ASK_APPROVAL"}, (
            f"benign edge case {i} has decision {e['expected_decision']}"
        )


def test_benign_edge_includes_ask_approval():
    assert any(e["expected_decision"] == "ASK_APPROVAL" for e in BENIGN_EDGE), (
        "anti-overblocking set should include escalations, not only ALLOW"
    )


def test_benign_edge_emails_are_synthetic():
    blob = json.dumps(BENIGN_EDGE)
    emails = set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", blob))
    bad = [x for x in emails if not x.endswith(".example")]
    assert not bad, f"non-synthetic emails: {bad}"


# --- Fallback runner ------------------------------------------------------

if __name__ == "__main__":
    tests = [
        value
        for name, value in sorted(globals().items())
        if name.startswith("test_") and callable(value)
    ]
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
    sys.exit(1 if failed else 0)
