# Evaluation Summary

## Method

Evaluation runs every fixed stored tool call through the offline policy checker,
risk detectors, intent helpers, and firewall path. Results are compared against
each scenario's `expected_decision` label. Online agent outputs are not mixed
into the committed benchmark.

The committed evaluation artifacts under `data/evaluation/` are generated from
all discoverable datasets:

- `data/demo_scenarios.json`
- `data/sample_examples.json`
- `data/dataset_v0.json`
- `data/red_team_examples.json`
- `data/benign_edge_cases.json`

## Current Results

The 94-scenario stored evaluation reports:

| Metric | Result |
| --- | --- |
| Attack Success Rate | 0.0% |
| Defense Success Rate | 100.0% |
| Benign Task Success Rate | 100.0% |
| False Positive Rate | 0.0% |
| False Negative Rate | 0.0% |
| Policy Compliance Accuracy | 100.0% |
| BLOCK Precision / Recall / F1 | 100.0% / 100.0% / 100.0% |

The 85-example evaluation corpus has 85/85 firewall-label agreement, with no false
negatives, no false positives, and all approval-labeled scenarios escalated.

## Baseline Comparison

Evaluation includes three configurations:

| Configuration | Behavior |
| --- | --- |
| Unprotected baseline | Allows every proposed call. |
| Prompt-only guardrail baseline | Uses keyword heuristics over external context and flattened arguments without structured policies. |
| AgentShield firewall | Applies structured policy rules, risk scoring, and user-intent checks. |

The baseline exports demonstrate why structured tool-call enforcement is needed:
the prompt-only guardrail catches obvious attacks but misses subtler policy
violations that require inspecting tool arguments, recipients, URLs, HTTP
methods, file paths, repository visibility, and user intent.

## Fixed Issue Classes

The expanded corpus previously surfaced the following issue classes, all now
covered by reusable policies and regression tests:

| Issue class | Current behavior |
| --- | --- |
| Unrequested protected file writes | BLOCK or ASK_APPROVAL depending on user authorization. |
| Credentials in public issue bodies | BLOCK. |
| Unrequested calendar or task creation from read-only requests | BLOCK. |
| Sensitive file reads not requested by the user | BLOCK. |
| Broadcast email beyond requested recipient scope | BLOCK. |
| Internal `*.example` destinations treated as external | Correctly treated as internal when configured. |
| Benign read-only public HTTP GET overblocked | ALLOW. |
| Authorized external sends, posts, or attendees | ASK_APPROVAL when confirmation is required. |
| Read-only intent matched by substrings inside unrelated words | Fixed with standalone keyword and phrase matching. |

## Reproduction

```bash
PYTHONPATH=. python3 src/experiment_runner.py
PYTHONPATH=. python3 src/baseline_unprotected.py
PYTHONPATH=. python3 src/baseline_prompt_guardrail.py
PYTHONPATH=. python3 src/test_metrics.py
PYTHONPATH=. python3 src/label_validator.py --rules data/policy_rules.json --test
```

Generated artifacts are written to `data/evaluation/`.

## Residual Scope

- The dataset is synthetic and scenario-based. It proves coverage for the
  committed project scenarios, not every possible production input.
- `ASK_APPROVAL` is a policy boundary for legitimate but risky actions.
- The committed metrics evaluate fixed tool calls and do not measure live model
  generation quality, latency, quota behavior, or cost.
- Future corpus growth should add new tools, argument fields, prompt-injection
  phrasings, and benign lookalikes as the system expands.
