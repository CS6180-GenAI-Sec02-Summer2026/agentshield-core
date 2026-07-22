# agentshield-core

Core backend for AgentShield, including multi-agent orchestration, red-team attack generation, simulated tools, tool-call firewalling, policy validation, audit logs, and evaluation metrics.

## Backend Orchestration API

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
```
