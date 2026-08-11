# AgentShield API Contract

The FastAPI app in `src/api.py` exposes scenario execution, dataset discovery,
metrics, audit, baseline comparison, red-team generation, and policy compilation
endpoints for the security console and integrations.

## Endpoints

| Method | Path | Request Body | Purpose |
| --- | --- | --- | --- |
| `GET` | `/health` | none | Backend, policy, dataset, tool, and non-secret model status. |
| `GET` | `/tools` | none | Supported mock tool schemas, argument groups, and types. |
| `GET` | `/datasets` | none | Available scenario datasets discovered from `data/`. |
| `GET` | `/scenarios` | none | Stored scenarios grouped by dataset. |
| `POST` | `/run-scenario` | `ScenarioRunRequest` | Run one ad-hoc or stored scenario through the full workflow. |
| `POST` | `/run-batch` | `BatchRunRequest` | Run inline scenarios or named datasets. |
| `GET` | `/metrics` | none | Compute metrics across all available labeled scenarios. |
| `POST` | `/metrics` | `DatasetQuery` | Compute metrics for selected datasets. |
| `GET` | `/audit-log` | none | Return in-memory audit entries for the current API process. |
| `POST` | `/baseline-comparison` | `DatasetQuery` | Compare unprotected, prompt-only guardrail, and AgentShield decisions. |
| `POST` | `/agents/red-team/generate` | `RedTeamGenerationRequest` | Generate and validate one synthetic adversarial scenario. |
| `POST` | `/agents/policy/compile` | `PolicyCompileRequest` | Compile one disabled policy candidate for review. |

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
Target Agent generates a call with the configured model in online mode or uses
explicit offline inference in offline mode.

## Run Scenario Request

```json
{
  "user_request": "Read notes.txt and summarize it.",
  "external_context": null,
  "execute_allowed_tool": false,
  "use_llm": true
}
```

The request can also pass a complete `scenario` object instead of top-level
ad-hoc fields. `execute_allowed_tool` controls whether `ALLOW` decisions run
through the safe mock tool implementation.

`use_llm` can explicitly request or disable model-backed processing for one
run. When omitted, the backend configuration controls the mode. Fixed stored
tool calls remain unchanged unless
`AGENTSHIELD_LLM_REGENERATE_STORED_TOOL_CALLS=true` is configured.
An explicit `true` requires the participating pipeline agents to be enabled;
incomplete online configuration fails visibly rather than silently falling
back.

Provided and generated calls are validated against the supported tool registry
before policy and risk evaluation. In a batch request, `use_llm` defaults to
`false` so the committed benchmark remains reproducible.

## Decision And Execution Behavior

- `ALLOW` means no applicable policy rule requires blocking or approval.
- `BLOCK` means at least one matching policy rule forbids the call.
- `ASK_APPROVAL` means the call may be legitimate but is high-impact,
  destructive, bulk, or otherwise requires explicit approval.
- Mock execution only happens for `ALLOW` decisions when
  `execute_allowed_tool` is true.
- `BLOCK` and `ASK_APPROVAL` decisions do not execute tools.

## Run Scenario Response

```json
{
  "scenario_id": "ad-hoc",
  "request_id": "run-abc123",
  "source_dataset": null,
  "user_request": "Read notes.txt and summarize it.",
  "attack_category": null,
  "expected_risk_level": null,
  "external_context_present": false,
  "workflow_state": {
    "request_id": "run-abc123",
    "status": "completed",
    "stages": [
      "received",
      "target_agent_proposed_tool_call",
      "firewall_decision_recorded",
      "audit_explanation_judged",
      "mock_tool_not_executed"
    ],
    "started_at": "2026-07-22T00:00:00+00:00",
    "completed_at": "2026-07-22T00:00:01+00:00"
  },
  "target_agent": {
    "mode": "llm_generation",
    "confidence": 0.98,
    "llm": {
      "provider": "gemini",
      "model": "gemini-3.6-flash",
      "purpose": "target_tool_call"
    },
    "proposed_tool_call": {
      "tool_name": "read_file",
      "arguments": {"file_path": "notes.txt"}
    }
  },
  "proposed_tool_call": {
    "tool_name": "read_file",
    "arguments": {
      "file_path": "notes.txt"
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
  "expected_decision": null,
  "matched_expected": null,
  "audit": {
    "explanation_mode": "llm_explanation",
    "quality_judge": {
      "total": 10,
      "rating": "strong",
      "mode": "llm_judge"
    }
  }
}
```

Model metadata is safe to expose and never contains the API key. Model
configuration or provider failures return HTTP 503. Input and tool validation
failures return HTTP 400 or FastAPI validation status 422.

## Agent Requests

Red-team generation accepts a bounded seed containing the supported tool,
synthetic arguments, attack category, risk level, expected decision, user
request, explanation, and optional injection-pattern inputs. The response
contains a schema-valid synthetic scenario and model metadata.

Policy compilation accepts `policy_id`, `name`, `policy_text`, and optional
`priority`. The response contains an inactive candidate rule,
`activation_required: true`, compilation mode, and model metadata. The endpoint
never edits or activates the live policy file.

## Dataset Queries

`POST /metrics` and `POST /baseline-comparison` accept:

```json
{
  "dataset_names": ["demo", "sample"]
}
```

When `dataset_names` is omitted, the backend uses every discoverable dataset.
With all committed datasets present, that means 94 stored scenarios across the
demo, sample, dataset v0, red-team, and benign-edge sets.

## Demo Datasets

Dataset discovery checks for these files:

- `data/demo_scenarios.json`
- `data/sample_examples.json`
- `data/dataset_v0.json`
- `data/red_team_examples.json`
- `data/benign_edge_cases.json`

Missing optional corpus files are skipped rather than treated as errors.
