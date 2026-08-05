# AgentShield Agents

GenAI agents used across AgentShield. This package currently contains the
**Red-Team Agent** (M3-S2), which generates synthetic adversarial tool-call
examples for testing the firewall.

> **Owner:** Aditya Shenoy — Red-Team Agent & Dataset Lead
> **Milestone 3 story:** M3-S2 — Red-Team Agent v0

---

## Files

| File | Purpose |
| --- | --- |
| [`injection_patterns.py`](injection_patterns.py) | Library of prompt-injection patterns (`id`, `name`, `description`, `template`) with a `render()` helper. |
| [`red_team_agent.py`](red_team_agent.py) | The Red-Team Agent: `ScenarioSeed` + `RedTeamAgent` that build schema-valid adversarial examples. |
| [`red_team_seeds.py`](red_team_seeds.py) | The attack seed catalog, grouped by tool (`email_seeds`, `file_seeds`, `http_seeds`, `mixed_seeds`). |
| [`generate_red_team.py`](generate_red_team.py) | Writes all seeds to `../data/red_team_examples.json`. |
| [`audit_judge.py`](audit_judge.py) | Scores audit-explanation quality against the rubric (offline; online deferred). |
| [`score_audit.py`](score_audit.py) | Scores every corpus explanation → `../data/audit_scores.json`. |
| [`judge_vs_manual.py`](judge_vs_manual.py) | Compares the judge against manual ratings on a sample. |
| `test_*.py` | Tests for the patterns, the agent, and the judge. |

---

## Red-Team Agent

The agent turns a `ScenarioSeed` (deterministic inputs describing one attack)
into a dictionary that conforms to
[`../data/dataset_schema.json`](../data/dataset_schema.json). When a seed names an
injection `pattern_id` and a `directive`, the hidden malicious instruction is
embedded into the surrounding `benign_context` to form `external_context`.

### Two modes

| Mode | What it does | API key |
| --- | --- | --- |
| `offline` (default) | Deterministic template-fill from seeds + patterns. Used by all tests. | No |
| `online` (deferred) | Would call the Claude API to generate richer attacks. Currently raises `NotImplementedError`. | Yes |

The agent is intentionally reproducible and testable **without** an API key.

### Injection patterns

Five distinct patterns keep generated attacks from being too obvious (all
"ignore previous instructions"):

`direct_override`, `hidden_html_comment`, `fake_system_note`,
`authority_urgency`, `fake_tool_response`.

---

## Generating the adversarial dataset

```bash
# From the repo root
python agents/generate_red_team.py
# -> writes data/red_team_examples.json (20 examples)
```

Generation is deterministic: re-running reproduces the same file. Validate it
with the shared validator:

```bash
python data/validate_dataset.py data/red_team_examples.json
```

## Running the tests

```bash
pytest agents/                              # patterns + agent tests
python agents/test_injection_patterns.py    # or run standalone
python agents/test_red_team_agent.py
```

---

## Audit Judge (M5-S2)

The audit judge scores the **quality of an audit explanation** against the rubric
in [`../data/audit_rubric.md`](../data/audit_rubric.md) (five criteria, 0-2 each,
max 10). It judges *how well an explanation justifies a decision* — not whether
the ALLOW/BLOCK/ASK_APPROVAL decision itself is correct.

| Mode | What it does | API key |
| --- | --- | --- |
| `offline` (default) | Deterministic rule-based scoring; penalizes weak/generic/empty/contradictory explanations. | No |
| `online` (deferred) | Would call the Claude API to score. Raises `NotImplementedError`. | Yes |

```bash
# Score every corpus explanation -> data/audit_scores.json
python agents/score_audit.py

# Compare the judge against manual ratings on a sample
python agents/judge_vs_manual.py
```

On the corpus the judge averages 9.4/10 (82 strong, 3 adequate) and agrees with
manual ratings 9/10 (100% within one band). See
[`../data/judge_vs_manual.md`](../data/judge_vs_manual.md).

---

## Synthetic data policy

All generated content is synthetic. Emails use `*.example` domains and any
secret is a clearly-marked `<synthetic-...-placeholder>` token. The test suite
enforces this (no real emails, secrets, or domains).
