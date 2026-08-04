# agentshield-core

Core backend for AgentShield, including multi-agent orchestration, red-team attack generation, simulated tools, tool-call firewalling, policy validation, audit logs, and evaluation metrics.

## Backend Orchestration API

Architecture and lifecycle details live in `docs/architecture.md`; the frontend
contract lives in `docs/api_contract.md`.

Install runtime dependencies:

```bash
python3 -m pip install -r requirements.txt
```

Run the API:

```bash
uvicorn src.api:app --reload
```

Main endpoints:

- `GET /health` - backend health, loaded policies, datasets, and supported tools.
- `GET /scenarios` - stored demo scenarios available in `data/`.
- `POST /run-scenario` - run one ad-hoc or stored scenario through Target Agent -> Firewall -> mock tool result.
- `POST /run-batch` - run multiple scenarios or named datasets.
- `GET /metrics` - compute metrics for available labeled scenarios.
- `GET /audit-log` - in-memory audit entries for this API process.
- `POST /baseline-comparison` - compare unprotected, prompt guardrail, and AgentShield decisions.

The mock tools never send email, touch real files, call GitHub, create calendar events, or make HTTP requests. They only validate arguments and return synthetic results after the firewall allows a call.

Run the focused orchestration checks:

```bash
PYTHONPATH=. python3 src/test_orchestrator.py
```

Run and export a repeatable experiment:

```bash
PYTHONPATH=. python3 src/experiment_runner.py
PYTHONPATH=. python3 src/baseline_unprotected.py
PYTHONPATH=. python3 src/baseline_prompt_guardrail.py
```

Run the complete local backend checks:

```bash
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
