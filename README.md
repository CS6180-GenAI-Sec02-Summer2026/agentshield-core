# agentshield-core

Core backend for AgentShield: model-backed agent workflows, policy rules,
synthetic security scenarios, tool-call firewalling, safe mock tools, audit
logs, API endpoints, baseline comparison, and evaluation metrics.

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
- Model-backed target, red-team, policy, risk, audit, and judge agents with
  strict structured outputs and explicit offline modes.
- Credential redaction, bounded retries and timeouts, stateless Gemini requests,
  optional OpenAI retention, safe metadata, and labeled fallback behavior.
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
| `src/target_agent.py` | Model-backed and offline target-agent tool-call proposals. |
| `src/llm_client.py` | Provider-neutral structured client with Gemini and OpenAI adapters. |
| `src/llm_settings.py` | Typed `.env` and environment configuration. |
| `src/llm_models.py` | Strict structured-output schemas for every online agent. |
| `src/llm_safety.py` | Provider-input redaction and size enforcement. |
| `src/metrics.py` | Security, usability, and accuracy metrics. |
| `src/policy_compiler_agent.py` | Markdown policy compiler for structured rule exports. |
| `src/label_validator.py` | Dataset label consistency checker. |
| `agents/` | Online/offline red-team generation and audit-quality judging. |
| `data/` | Synthetic scenarios, schema, policy rules, audit logs, and exports. |
| `docs/` | Architecture, API contract, policies, rule format, metrics, and project report. |

## Setup

Use Python 3.10+.

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install -r requirements.txt
cp .env.example .env
```

For online mode, set the generic `AGENTSHIELD_LLM_API_KEY` field in `.env`,
choose `gemini` or `openai` with `AGENTSHIELD_LLM_PROVIDER`, set a compatible
model identifier, and change `AGENTSHIELD_LLM_MODE` to `online`. No credential
belongs in frontend variables or committed files. See
[`docs/model_integration.md`](docs/model_integration.md) for the complete setup.

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
| `POST` | `/agents/red-team/generate` | Generate one synthetic adversarial scenario. |
| `POST` | `/agents/policy/compile` | Compile an inactive policy candidate for review. |

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
`src/experiment_runner.py` covers every discoverable stored scenario. In the
committed dataset set, that is 94 scenarios total: demo, sample, dataset v0,
red-team, and benign-edge datasets. Metrics tests use temporary export
directories so the committed full-scenario artifacts stay stable after test
runs.

## Full Validation

Run the complete local backend check set before merging:

```bash
PYTHONPATH=. python3 -m py_compile src/*.py data/*.py agents/*.py
PYTHONPATH=. python3 -m pytest -q
PYTHONPATH=. python3 data/test_validate_dataset.py
PYTHONPATH=. python3 data/test_dataset_v0.py
PYTHONPATH=. python3 data/test_corpus.py
PYTHONPATH=. python3 src/test_orchestrator.py
PYTHONPATH=. python3 src/test_firewall.py
PYTHONPATH=. python3 src/test_integration.py
PYTHONPATH=. python3 src/test_metrics.py
PYTHONPATH=. python3 agents/test_red_team_agent.py
PYTHONPATH=. python3 agents/test_injection_patterns.py
PYTHONPATH=. python3 agents/test_audit_judge.py
PYTHONPATH=. python3 data/validate_dataset.py data/sample_examples.json
PYTHONPATH=. python3 data/validate_dataset.py data/demo_scenarios.json
PYTHONPATH=. python3 data/validate_dataset.py data/dataset_v0.json
PYTHONPATH=. python3 data/validate_dataset.py data/red_team_examples.json
PYTHONPATH=. python3 data/validate_dataset.py data/benign_edge_cases.json
PYTHONPATH=. python3 src/label_validator.py --rules data/policy_rules.json --test
PYTHONPATH=. python3 src/label_validator.py --rules data/policy_rules.json --dataset data/sample_examples.json
PYTHONPATH=. python3 src/label_validator.py --rules data/policy_rules.json --dataset data/demo_scenarios.json
PYTHONPATH=. python3 src/label_validator.py --rules data/policy_rules.json --dataset data/dataset_v0.json
PYTHONPATH=. python3 src/label_validator.py --rules data/policy_rules.json --dataset data/red_team_examples.json
PYTHONPATH=. python3 src/label_validator.py --rules data/policy_rules.json --dataset data/benign_edge_cases.json
git diff --check
```

The automated suite validates every online agent through a schema-faithful fake
provider. After configuring a real key, run the separate live-provider check:

```bash
PYTHONPATH=. python3 scripts/llm_smoke.py
```

## Documentation

- `docs/architecture.md` - backend scope, module map, lifecycle, and safety boundary.
- `docs/api_contract.md` - API payload and response contract.
- `docs/safety_policies.md` - human-readable safety policies.
- `docs/policy_rule_format.md` - compiled rule format.
- `docs/evaluation_metrics.md` - metrics definitions and formulas.
- `docs/model_integration.md` - provider setup, agent roles, safeguards, and live validation.
- `docs/report/README.md` - project report and supporting evidence index.
- `data/README.md` - dataset schema, labels, validation, and safety notes.
- `agents/README.md` - red-team generation and audit-quality utility guide.
