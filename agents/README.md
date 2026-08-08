# AgentShield Agent Utilities

This directory contains deterministic utilities used to build and evaluate the
synthetic security corpus. The utilities are part of the local test harness:
they do not call external services, require credentials, or perform side
effects.

## Files

| File | Purpose |
| --- | --- |
| `injection_patterns.py` | Prompt-injection pattern library with stable ids, descriptions, templates, and a `render()` helper. |
| `red_team_agent.py` | Deterministic red-team example generator built around `ScenarioSeed` and `RedTeamAgent`. |
| `red_team_seeds.py` | Attack seed catalog grouped by tool and attack style. |
| `generate_red_team.py` | Regenerates `data/red_team_examples.json` from the seed catalog. |
| `audit_judge.py` | Offline audit-explanation quality scorer. |
| `score_audit.py` | Scores every corpus explanation and writes `data/audit_scores.json`. |
| `judge_vs_manual.py` | Compares offline judge ratings against a hand-scored sample. |
| `test_*.py` | Regression tests for patterns, generation, and audit scoring. |

## Red-Team Generator

The red-team generator turns deterministic `ScenarioSeed` inputs into
schema-valid adversarial examples. Each seed defines the target tool, tool
arguments, expected decision, risk level, attack category, user request,
explanation, and optional hidden directive. When `pattern_id` is set, the
directive is embedded into benign-looking external context.

Generation is intentionally deterministic:

| Mode | Behavior | External dependency |
| --- | --- | --- |
| `offline` | Template-fill from checked-in seeds and injection patterns. This is the default and the mode used by tests. | No |
| `online` | Reserved extension point; currently raises `NotImplementedError`. | No |

### Injection Patterns

The corpus uses five prompt-injection styles so attacks do not rely on a single
phrase:

- `direct_override`
- `hidden_html_comment`
- `fake_system_note`
- `authority_urgency`
- `fake_tool_response`

## Regenerate Adversarial Data

```bash
PYTHONPATH=. python3 agents/generate_red_team.py
PYTHONPATH=. python3 data/validate_dataset.py data/red_team_examples.json
```

Regeneration should be byte-stable unless the seed catalog or pattern library
changes.

## Audit Judge

The audit judge scores explanation quality against
[`../data/audit_rubric.md`](../data/audit_rubric.md). It evaluates whether an
explanation identifies the decision reason, references scenario specifics,
matches the expected label, stays concise, and avoids unsupported claims.

It scores explanation quality only; it does not decide whether the firewall
decision itself is correct.

```bash
PYTHONPATH=. python3 agents/score_audit.py
PYTHONPATH=. python3 agents/judge_vs_manual.py
```

The current corpus average is 9.4/10, with 82 strong explanations and 3
adequate explanations.

## Tests

```bash
PYTHONPATH=. python3 agents/test_injection_patterns.py
PYTHONPATH=. python3 agents/test_red_team_agent.py
PYTHONPATH=. python3 agents/test_audit_judge.py
```

The tests enforce deterministic generation, schema validity, prompt-pattern
coverage, synthetic-only content, and audit-scoring behavior.

## Synthetic Data Boundary

All generated content is synthetic. Email addresses use `*.example` domains, and
secret-like values use clearly marked `<synthetic-...-placeholder>` tokens.
