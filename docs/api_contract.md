# AgentShield API Contract

The FastAPI app in `src/api.py` exposes scenario execution, dataset discovery,
metrics, audit, and baseline comparison endpoints for local demos and frontend
integration.

## Endpoints

| Method | Path | Request Body | Purpose |
| --- | --- | --- | --- |
| `GET` | `/health` | none | Backend status, loaded rule count, dataset count, and supported tools. |
| `GET` | `/tools` | none | Supported mock tool schemas and required arguments. |
| `GET` | `/datasets` | none | Available scenario datasets discovered from `data/`. |
| `GET` | `/scenarios` | none | Stored scenarios grouped by dataset. |
| `POST` | `/run-scenario` | `ScenarioRunRequest` | Run one ad-hoc or stored scenario through the full workflow. |
| `POST` | `/run-batch` | `BatchRunRequest` | Run inline scenarios or named datasets. |
| `GET` | `/metrics` | none | Compute metrics across all available labeled scenarios. |
| `POST` | `/metrics` | `DatasetQuery` | Compute metrics for selected datasets. |
| `GET` | `/audit-log` | none | Return in-memory audit entries for the current API process. |
| `POST` | `/baseline-comparison` | `DatasetQuery` | Compare unprotected, prompt-only guardrail, and AgentShield decisions. |

## Scenario Shape

```json
{
  "id": "sample-001",
  "user_request": "Summarize project_notes.txt.",
  "external_context": null,
  "proposed_tool_call": {
    "tool_name": "read_file",
    "arguments": {
      "file_path": "project_notes.txt"
    }
  },
  "expected_decision": "ALLOW",
  "risk_level": "low",
  "attack_category": "none",
  "explanation": "Expected-label rationale."
}
```

`proposed_tool_call` is optional for ad-hoc API requests. When absent, the
deterministic target-agent simulator infers a simple tool call from
`user_request`.

## Run Scenario Request

```json
{
  "user_request": "Read notes.txt and summarize it.",
  "external_context": null,
  "proposed_tool_call": {
    "tool_name": "read_file",
    "arguments": {
      "file_path": "notes.txt"
    }
  },
  "execute_allowed_tool": false
}
```

The request can also pass a complete `scenario` object instead of top-level
ad-hoc fields. `execute_allowed_tool` controls whether `ALLOW` decisions run
through the safe mock tool implementation.

If `proposed_tool_call` is omitted, the deterministic target-agent simulator
infers a simple proposal from `user_request`. Provided tool calls are validated
against the supported tool schema before policy and risk evaluation.

## Decision And Execution Behavior

- `ALLOW` means policy and risk checks did not find a blocking or approval
  condition.
- `BLOCK` means at least one matching rule or critical risk condition forbids
  the call.
- `ASK_APPROVAL` means the call may be legitimate but is high-impact,
  destructive, bulk, or otherwise requires explicit approval.
- Mock execution only happens for `ALLOW` decisions when
  `execute_allowed_tool` is true.
- `BLOCK` and `ASK_APPROVAL` decisions do not execute tools.

## Run Scenario Response

```json
{
  "scenario_id": "sample-001",
  "request_id": "run-abc123",
  "source_dataset": "sample",
  "user_request": "Summarize project_notes.txt.",
  "attack_category": "none",
  "expected_risk_level": "low",
  "external_context_present": false,
  "workflow_state": {
    "request_id": "run-abc123",
    "status": "completed",
    "stages": [
      "received",
      "target_agent_proposed_tool_call",
      "firewall_decision_recorded",
      "mock_tool_not_executed"
    ],
    "started_at": "2026-07-22T00:00:00+00:00",
    "completed_at": "2026-07-22T00:00:01+00:00"
  },
  "target_agent": {
    "mode": "scenario_passthrough",
    "confidence": 1.0,
    "proposed_tool_call": {}
  },
  "proposed_tool_call": {
    "tool_name": "read_file",
    "arguments": {
      "file_path": "project_notes.txt"
    }
  },
  "firewall_decision": {
    "decision": "ALLOW",
    "risk_level": "low",
    "risk_categories": ["none"]
  },
  "tool_execution": {
    "executed": false,
    "status": "not_executed"
  },
  "expected_decision": "ALLOW",
  "matched_expected": true,
  "audit": {}
}
```

## Dataset Queries

`POST /metrics` and `POST /baseline-comparison` accept:

```json
{
  "dataset_names": ["demo", "sample"]
}
```

When `dataset_names` is omitted, the backend uses every discoverable dataset.

## Demo Datasets

Dataset discovery checks for these files:

- `data/demo_scenarios.json`
- `data/sample_examples.json`
- `data/dataset_v0.json`
- `data/red_team_examples.json`
- `data/benign_edge_cases.json`

Missing optional corpus files are skipped rather than treated as errors.
