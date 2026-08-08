"""Dataset quality and ambiguity report for AgentShield.

Summarizes the label distribution and balance of the corpus, and flags examples
whose `expected_decision` is debatable so they can be manually reviewed. This
supports the quality tasks "validate dataset quality and labels", "check label
distribution", and "flag ambiguous examples", and guards the bug item
"ambiguous expected decision".

Usage:
    python data/quality_report.py
"""

from __future__ import annotations

import sys
from collections import Counter

from corpus_report import CORPUS_FILES, distribution, load_corpus

HIGH_RISK = {"high", "critical"}


def ambiguity_reasons(example) -> list[str]:
    """Return the reasons this example's decision is debatable (empty if clear)."""
    reasons = []
    cat = example["attack_category"]
    decision = example["expected_decision"]
    risk = example["risk_level"]

    if decision == "ASK_APPROVAL":
        # escalation cases are borderline by design: a human must adjudicate
        reasons.append("escalation (ASK_APPROVAL)")
    if cat != "none" and decision != "BLOCK":
        # a malicious example that is not blocked outright
        reasons.append("malicious-not-blocked")
    if cat == "none" and risk in HIGH_RISK:
        # a benign example carrying high/critical risk
        reasons.append("benign-high-risk")
    return reasons


def flag_ambiguous(pairs):
    """Return (source, index_in_file, example, reasons) for each flagged example."""
    flagged = []
    counters = Counter()
    for src, e in pairs:
        counters[src] += 1
        reasons = ambiguity_reasons(e)
        if reasons:
            flagged.append((src, counters[src] - 1, e, reasons))
    return flagged


def main() -> int:
    pairs = load_corpus()
    examples = [e for _, e in pairs]

    print("=== Per-file distribution ===")
    for path in CORPUS_FILES:
        import json
        ex = json.loads(path.read_text(encoding="utf-8"))
        d = distribution(ex)
        print(f"\n{path.name}  (n={d['total']}, benign={d['benign']}, malicious={d['malicious']})")
        print(f"  decision: {d['expected_decision']}")
        print(f"  category: {d['attack_category']}")

    d = distribution(examples)
    print("\n=== Combined balance ===")
    print(f"  total={d['total']}  benign={d['benign']} ({d['benign']/d['total']:.0%})  "
          f"malicious={d['malicious']} ({d['malicious']/d['total']:.0%})")
    print(f"  decisions: {d['expected_decision']}")

    flagged = flag_ambiguous(pairs)
    print(f"\n=== Ambiguous / review-needed examples: {len(flagged)} ===")
    for src, idx, e, reasons in flagged:
        print(f"  [{src}#{idx}] {e['proposed_tool_call']['tool_name']:20} "
              f"{e['attack_category']:18} {e['risk_level']:8} {e['expected_decision']:12} "
              f"-> {', '.join(reasons)}")
        print(f"       user_request: {e['user_request']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
