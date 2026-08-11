# AgentShield Project Report

This directory contains the project report for AgentShield. It summarizes the
complete system, dataset, red-team method, evaluation evidence, and demo path
as one integrated project.

## Report Contents

| File | Purpose |
| --- | --- |
| `dataset.md` | Dataset composition, schema, label rules, tool coverage, and quality checks. |
| `red_team_method.md` | Online/offline adversarial generation method and coverage. |
| `evaluation.md` | Firewall-vs-label results, metric summary, fixed issue classes, and residual scope. |
| `demo.md` | Three runnable demo scenarios covering `ALLOW`, `BLOCK`, and `ASK_APPROVAL`. |
| `agentshield_report.md` | Canonical report source. |
| `agentshield_report.tex` / `.pdf` | Generated submission artifacts. |
| `report_header.tex` | Shared LaTeX layout controls for report generation. |

## Project Overview

AgentShield includes:

- A provider-neutral model runtime for target generation, red-team generation,
  policy compilation, semantic risk, audit explanations, and explanation
  judging, configured through one provider, model, and API-key contract.
- An authoritative deterministic policy boundary plus explicit offline modes
  for reproducible scenario evaluation.
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
7. Model runtime and key setup: [`../model_integration.md`](../model_integration.md)
8. Dataset details: [`dataset.md`](dataset.md)
9. Evaluation summary: [`evaluation.md`](evaluation.md)
10. Demo path: [`demo.md`](demo.md)

## Validation Snapshot

The current project state is validated by:

```bash
PYTHONPATH=. python3 -m py_compile src/*.py data/*.py agents/*.py
PYTHONPATH=. python3 -m pytest -q
PYTHONPATH=. python3 src/test_orchestrator.py
PYTHONPATH=. python3 src/label_validator.py --rules data/policy_rules.json --test
```

Regenerate the synchronized TeX and PDF artifacts with:

```bash
./scripts/build_report.sh
```

The committed offline evaluation artifacts under `data/evaluation/` report
100% policy compliance for the 94 fixed stored scenarios. Online generation
quality is a separate runtime concern and is not inferred from that result.

## Scope Boundary

All tool execution is simulated. Mock tools validate arguments and return
synthetic outputs, but they do not send email, read or write real files, create
calendar events, create issues, or perform HTTP requests.
