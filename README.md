# agentshield-core

Core backend for AgentShield: policy rules, synthetic security scenarios,
tool-call firewalling, deterministic target-agent simulation, safe mock tools,
audit logs, API endpoints, baseline comparison, and evaluation metrics.

AgentShield evaluates proposed tool calls before execution. It classifies each
call as `ALLOW`, `BLOCK`, or `ASK_APPROVAL` using compiled policy rules, risk
signals, and user-intent checks. Mock tools are intentionally side-effect free:
they validate arguments and return synthetic outputs, but never send email,
touch real files, create calendar events, open issues, or make HTTP requests.

## What Is Included

- Dataset schema, attack taxonomy, sample scenarios, and dataset validators.
- Markdown safety policies compiled into structured JSON rules.
- Firewall, policy checker, risk classifier, and label validator.
- Shared helper modules for intent matching, security patterns, text matching,
  and external-target classification.
- Deterministic target-agent proposal flow for repeatable local testing.
- Safe mock tool registry covering email, files, calendar, tasks, issues, and HTTP.
- End-to-end orchestrator with workflow state, audit entries, metrics, and exports.
- FastAPI backend for frontend or demo integration.
- Baselines for unprotected and prompt-guardrail behavior.

## Repository Map

| Path | Purpose |
| --- | --- |
| `src/api.py` | FastAPI app and backend endpoints. |
| `src/orchestrator.py` | End-to-end scenario workflow and audit capture. |
| `src/firewall_agent.py` | Firewall decision layer. |
| `src/policy_checker.py` | Structured policy-rule evaluation. |
| `src/risk_classifier.py` | Risk-level and attack-category classification. |
| `src/intent_utils.py` | Shared user-intent matching helpers. |
| `src/security_patterns.py` | Shared security pattern constants. |
| `src/security_text.py` | Shared text matching and external-target helpers. |
| `src/tools.py` | Supported tool schemas and safe mock execution. |
| `src/target_agent.py` | Deterministic target-agent tool-call proposals. |
| `src/metrics.py` | Security, usability, and accuracy metrics. |
| `src/policy_compiler_agent.py` | Markdown policy compiler for structured rule exports. |
| `src/label_validator.py` | Dataset label consistency checker. |
| `data/` | Synthetic scenarios, schema, policy rules, audit logs, and exports. |
| `docs/` | Architecture, API contract, policies, rule format, and metrics docs. |

## Setup

Use Python 3.10+.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
```

## Run The API

```bash
uvicorn src.api:app --reload
```

Useful endpoints:

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Backend health, loaded policies, datasets, and supported tools. |
| `GET` | `/tools` | Supported tool schemas. |
| `GET` | `/datasets` | Discoverable scenario datasets. |
| `GET` | `/scenarios` | Stored demo/sample scenarios from `data/`. |
| `POST` | `/run-scenario` | Run one ad-hoc or stored scenario through the full workflow. |
| `POST` | `/run-batch` | Run multiple scenarios or named datasets. |
| `GET` | `/metrics` | Compute metrics for available labeled scenarios. |
| `POST` | `/metrics` | Compute metrics for selected datasets. |
| `GET` | `/audit-log` | In-memory audit entries for the current API process. |
| `POST` | `/baseline-comparison` | Compare unprotected, prompt guardrail, and AgentShield decisions. |

See `docs/api_contract.md` for request and response shapes.

## Run Local Workflows

Focused orchestration checks:

```bash
PYTHONPATH=. python3 src/test_orchestrator.py
```

Repeatable experiment and baseline exports:

```bash
PYTHONPATH=. python3 src/experiment_runner.py
PYTHONPATH=. python3 src/baseline_unprotected.py
PYTHONPATH=. python3 src/baseline_prompt_guardrail.py
```

Generated evaluation artifacts are written under `data/evaluation/`.

## Full Validation

Run the complete local backend check set before merging:

```bash
PYTHONPATH=. python3 -m py_compile src/*.py data/*.py
PYTHONPATH=. python3 -m pytest -q
PYTHONPATH=. python3 data/test_validate_dataset.py
PYTHONPATH=. python3 src/test_orchestrator.py
PYTHONPATH=. python3 src/test_firewall.py
PYTHONPATH=. python3 src/test_integration.py
PYTHONPATH=. python3 src/test_metrics.py
PYTHONPATH=. python3 data/validate_dataset.py data/sample_examples.json
PYTHONPATH=. python3 data/validate_dataset.py data/demo_scenarios.json
PYTHONPATH=. python3 src/label_validator.py --rules data/policy_rules.json --test
PYTHONPATH=. python3 src/label_validator.py --rules data/policy_rules.json --dataset data/sample_examples.json
PYTHONPATH=. python3 src/label_validator.py --rules data/policy_rules.json --dataset data/demo_scenarios.json
git diff --check
```

## Documentation

- `docs/architecture.md` - backend scope, module map, lifecycle, and safety boundary.
- `docs/api_contract.md` - API payload and response contract.
- `docs/safety_policies.md` - human-readable safety policies.
- `docs/policy_rule_format.md` - compiled rule format.
- `docs/evaluation_metrics.md` - metrics definitions and formulas.
- `data/README.md` - dataset schema, labels, validation, and safety notes.
