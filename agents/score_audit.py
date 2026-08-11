"""Score every audit explanation in the corpus against the rubric.

Runs the offline audit judge over the corpus explanations and writes
`data/audit_scores.json`. Because no firewall "early runs" exist yet, the
explanations being scored are the dataset's own `explanation` fields; the same
report can later be pointed at real firewall audit logs.

Usage:
    python agents/score_audit.py
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

try:  # pytest / repo root
    from agents.audit_judge import score_explanation
except ModuleNotFoundError:  # run from agents/
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from audit_judge import score_explanation

REPO = Path(__file__).resolve().parent.parent
CORPUS = ["dataset_v0.json", "red_team_examples.json", "benign_edge_cases.json"]
OUTPUT_PATH = REPO / "data" / "audit_scores.json"


def build_scores() -> list[dict]:
    rows = []
    for name in CORPUS:
        for e in json.loads((REPO / "data" / name).read_text(encoding="utf-8")):
            r = score_explanation(e)
            rows.append(
                {
                    "source": name,
                    "user_request": e["user_request"],
                    "total": r["total"],
                    "rating": r["rating"],
                    "scores": r["scores"],
                }
            )
    return rows


def main() -> None:
    rows = build_scores()
    OUTPUT_PATH.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")

    ratings = Counter(r["rating"] for r in rows)
    totals = [r["total"] for r in rows]
    print(f"Scored {len(rows)} explanations -> {OUTPUT_PATH.name}")
    print(f"ratings: {dict(ratings)}")
    print(f"avg={sum(totals) / len(totals):.1f}  min={min(totals)}  max={max(totals)}")

    print("\nLowest-scoring explanations (review candidates):")
    for r in sorted(rows, key=lambda x: x["total"])[:8]:
        print(f"  {r['total']:2}/10 {r['rating']:8} [{r['source']}] {r['user_request'][:58]}")


if __name__ == "__main__":
    main()
