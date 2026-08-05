"""Tests for the Red-Team Agent and its generated adversarial examples (M3-S2).

Guards the M3-S2 bug items:
  * attack examples too obvious   -> diversity heuristics
  * attack labels inconsistent    -> label-consistency checks
  * generated text contains real PII / real secrets -> synthetic-only scan
"""

import json
import re
import sys
from collections import Counter
from pathlib import Path

import pytest

try:  # pytest (run from repo root)
    from agents.red_team_agent import RedTeamAgent, ScenarioSeed
    from agents.red_team_seeds import all_seeds, email_seeds, file_seeds, http_seeds
    from agents.generate_red_team import build_examples, OUTPUT_PATH
except ModuleNotFoundError:  # standalone: python agents/test_red_team_agent.py
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from red_team_agent import RedTeamAgent, ScenarioSeed
    from red_team_seeds import all_seeds, email_seeds, file_seeds, http_seeds
    from generate_red_team import build_examples, OUTPUT_PATH

REPO = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO / "data" / "dataset_schema.json"

EXAMPLES = build_examples()
SEEDS = all_seeds()


def _validator():
    from jsonschema import Draft202012Validator
    return Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))


# --- Generation basics ----------------------------------------------------

def test_generates_enough_examples():
    assert len(EXAMPLES) >= 15


def test_all_examples_schema_valid():
    v = _validator()
    for i, e in enumerate(EXAMPLES):
        errs = list(v.iter_errors(e))
        assert not errs, f"example {i} invalid: {errs}"


def test_all_examples_are_malicious():
    assert all(e["attack_category"] != "none" for e in EXAMPLES)


# --- Label consistency (bug item) -----------------------------------------

def test_label_consistency():
    for i, e in enumerate(EXAMPLES):
        assert e["expected_decision"] in {"BLOCK", "ASK_APPROVAL"}, \
            f"example {i}: malicious but decision {e['expected_decision']}"
        assert e["risk_level"] in {"high", "critical"}, \
            f"example {i}: malicious but risk {e['risk_level']}"


def test_injection_examples_have_external_context():
    for i, e in enumerate(EXAMPLES):
        if e["attack_category"] == "prompt_injection":
            assert e["external_context"], f"example {i}: injection without external_context"


# --- Synthetic-only scan (bug item: real PII / secrets) -------------------

def test_all_emails_are_synthetic():
    blob = json.dumps(EXAMPLES)
    emails = set(re.findall(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", blob))
    bad = [e for e in emails if not e.endswith(".example")]
    assert not bad, f"non-synthetic emails: {bad}"


def test_no_realistic_secrets():
    """Any secret-looking value must be a clearly-marked placeholder."""
    blob = json.dumps(EXAMPLES)
    # long unbroken alphanumeric runs that are not English words and not placeholders
    for token in re.findall(r"[A-Za-z0-9+/]{20,}", blob):
        if token.isalpha():
            continue  # a long word, not a secret
        assert "placeholder" in token or "synthetic" in token, \
            f"possible real secret in generated data: {token!r}"


def test_no_real_domains():
    blob = json.dumps(EXAMPLES).lower()
    for dom in ("gmail.com", "yahoo.com", "outlook.com", "hotmail.com", ".edu", ".gov"):
        assert dom not in blob, f"real-looking domain present: {dom}"


# --- Diversity / "not too obvious" (bug item) -----------------------------

def test_uses_multiple_injection_patterns():
    patterns = {s.pattern_id for s in SEEDS if s.pattern_id}
    assert len(patterns) >= 3, f"too few distinct injection patterns: {patterns}"


def test_covers_email_file_and_http_tools():
    tools = {e["proposed_tool_call"]["tool_name"] for e in EXAMPLES}
    assert "send_email" in tools
    assert tools & {"read_file", "write_file", "delete_file"}
    assert "send_http_request" in tools


def test_multiple_attack_categories_present():
    cats = {e["attack_category"] for e in EXAMPLES}
    assert len(cats) >= 3, f"attacks not diverse across categories: {cats}"


def test_injection_contexts_are_not_all_identical():
    contexts = [e["external_context"] for e in EXAMPLES
                if e["attack_category"] == "prompt_injection"]
    assert len(set(contexts)) == len(contexts), "duplicate injection external_context values"


def test_no_duplicate_user_requests():
    dups = [u for u, c in Counter(e["user_request"] for e in EXAMPLES).items() if c > 1]
    assert not dups, f"duplicate user_request values: {dups}"


# --- On-disk file stays in sync with the seeds ----------------------------

def test_written_file_matches_generation():
    on_disk = json.loads(OUTPUT_PATH.read_text(encoding="utf-8"))
    assert on_disk == EXAMPLES, "data/red_team_examples.json is out of date; re-run generate_red_team.py"


# --- Agent error paths ----------------------------------------------------

def test_unknown_mode_raises():
    with pytest.raises(ValueError):
        RedTeamAgent(mode="bogus")


def test_pattern_without_directive_raises():
    bad = ScenarioSeed("read_file", {}, "prompt_injection", "high", "BLOCK", "u", "x",
                       pattern_id="direct_override")
    with pytest.raises(ValueError):
        RedTeamAgent().generate_example(bad)


def test_online_mode_not_implemented():
    with pytest.raises(NotImplementedError):
        RedTeamAgent(mode="online").generate_example(email_seeds()[0])


# --- Fallback runner (no pytest) ------------------------------------------

def _main():
    import types
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and isinstance(v, types.FunctionType)]
    passed = failed = 0
    for t in tests:
        try:
            t(); passed += 1; print(f"PASS  {t.__name__}")
        except Exception as exc:  # noqa: BLE001 - simple runner
            failed += 1; print(f"FAIL  {t.__name__}: {exc}")
    print(f"\n{passed}/{passed + failed} tests passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
