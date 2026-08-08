# AgentShield Submission Guide

This directory is the project-level submission package for AgentShield. It
summarizes the complete system, dataset, red-team method, evaluation evidence,
and demo path as one integrated project.

## Submission Contents

| File | Purpose |
| --- | --- |
| `dataset.md` | Dataset composition, schema, label rules, tool coverage, and quality checks. |
| `red_team_method.md` | Deterministic adversarial generation method and coverage. |
| `evaluation.md` | Firewall-vs-label results, metric summary, fixed issue classes, and residual scope. |
| `demo.md` | Three runnable demo scenarios covering `ALLOW`, `BLOCK`, and `ASK_APPROVAL`. |

## Project Deliverables

AgentShield includes:

- A deterministic backend workflow for scenario ingestion, tool-call proposal,
  policy checking, risk scoring, audit logging, and safe mock execution.
- A synthetic 94-scenario stored evaluation set: 3 demo scenarios, 6 sample
  scenarios, and an 85-example corpus for deeper evaluation.
- A structured safety-policy rule set covering prompt injection, data
  exfiltration, unauthorized actions, destructive operations, sensitive file
  reads, protected writes, external sharing, public issue leaks, and unsafe HTTP
  behavior.
- Baseline comparison for unprotected execution, prompt-only guardrails, and
  AgentShield policy enforcement.
- A frontend console for running simulations, reviewing decisions, inspecting
  audit logs, and comparing metrics.

## Documentation Map

Use this path for a complete project review:

1. Root setup and commands: [`../../README.md`](../../README.md)
2. Backend architecture: [`../architecture.md`](../architecture.md)
3. API contract: [`../api_contract.md`](../api_contract.md)
4. Safety policy catalog: [`../safety_policies.md`](../safety_policies.md)
5. Rule format: [`../policy_rule_format.md`](../policy_rule_format.md)
6. Metrics definitions: [`../evaluation_metrics.md`](../evaluation_metrics.md)
7. Dataset details: [`dataset.md`](dataset.md)
8. Evaluation summary: [`evaluation.md`](evaluation.md)
9. Demo path: [`demo.md`](demo.md)

## Validation Snapshot

The current submission state is validated by:

```bash
PYTHONPATH=. python3 -m py_compile src/*.py data/*.py agents/*.py
PYTHONPATH=. python3 -m pytest -q
PYTHONPATH=. python3 src/test_orchestrator.py
PYTHONPATH=. python3 src/label_validator.py --rules data/policy_rules.json --test
```

The committed evaluation artifacts under `data/evaluation/` report 100% policy
compliance for the 94 stored scenarios.

## Scope Boundary

All tool execution is simulated. Mock tools validate arguments and return
synthetic outputs, but they do not send email, read or write real files, create
calendar events, create issues, or perform HTTP requests.
