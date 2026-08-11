"""Shared API and workflow schemas for AgentShield."""

import json
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, field_validator

Decision = Literal["ALLOW", "BLOCK", "ASK_APPROVAL"]
RiskLevel = Literal["low", "medium", "high", "critical"]
AttackCategory = Literal["none", "prompt_injection", "data_exfiltration", "unauthorized_action"]
ToolName = Literal[
    "send_email",
    "read_file",
    "write_file",
    "delete_file",
    "create_calendar_event",
    "create_task",
    "create_github_issue",
    "send_http_request",
]
DatasetName = Annotated[str, Field(min_length=1, max_length=200)]
MAX_TOOL_ARGUMENT_KEYS = 50
MAX_TOOL_ARGUMENT_CHARS = 30_000


def _validate_tool_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    if len(arguments) > MAX_TOOL_ARGUMENT_KEYS:
        raise ValueError(f"tool arguments must contain at most {MAX_TOOL_ARGUMENT_KEYS} keys")
    try:
        payload = json.dumps(arguments, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as exc:
        raise ValueError("tool arguments must be JSON serializable") from exc
    if len(payload) > MAX_TOOL_ARGUMENT_CHARS:
        raise ValueError(
            f"serialized tool arguments must not exceed {MAX_TOOL_ARGUMENT_CHARS} characters"
        )
    return arguments


class ToolCallModel(BaseModel):
    """Structured tool call proposed by the Target Agent."""

    tool_name: ToolName
    arguments: dict[str, Any] = Field(default_factory=dict)

    _bounded_arguments = field_validator("arguments")(_validate_tool_arguments)


class ScenarioModel(BaseModel):
    """Labeled or ad-hoc AgentShield scenario."""

    id: str | None = Field(default=None, max_length=200)
    user_request: str = Field(min_length=1, max_length=10_000)
    external_context: str | None = Field(default=None, max_length=30_000)
    proposed_tool_call: ToolCallModel | None = None
    expected_decision: Decision | None = None
    risk_level: RiskLevel | None = None
    attack_category: AttackCategory | None = None
    explanation: str | None = Field(default=None, max_length=10_000)


class ScenarioRunRequest(BaseModel):
    """API request for running one scenario."""

    user_request: str | None = Field(default=None, max_length=10_000)
    external_context: str | None = Field(default=None, max_length=30_000)
    proposed_tool_call: ToolCallModel | None = None
    scenario: ScenarioModel | None = None
    execute_allowed_tool: bool = False
    use_llm: bool | None = None


class BatchRunRequest(BaseModel):
    """API request for running many scenarios."""

    scenarios: list[ScenarioModel] | None = Field(default=None, max_length=500)
    dataset_names: list[DatasetName] | None = Field(default=None, max_length=20)
    execute_allowed_tools: bool = False
    use_llm: bool = False


class RedTeamSeedModel(BaseModel):
    """Seed constraints for one synthetic adversarial scenario."""

    tool_name: ToolName
    arguments: dict[str, Any] = Field(default_factory=dict)
    attack_category: Literal["prompt_injection", "data_exfiltration", "unauthorized_action"]
    risk_level: Literal["high", "critical"]
    expected_decision: Literal["BLOCK", "ASK_APPROVAL"]
    user_request: str = Field(min_length=1, max_length=2_000)
    explanation: str = Field(min_length=1, max_length=2_000)
    directive: str | None = Field(default=None, max_length=2_000)
    benign_context: str = Field(default="", max_length=5_000)
    pattern_id: str | None = Field(default=None, max_length=100)

    _bounded_arguments = field_validator("arguments")(_validate_tool_arguments)


class RedTeamGenerationRequest(BaseModel):
    """Request for model-backed adversarial scenario generation."""

    seed: RedTeamSeedModel


class PolicyCompileRequest(BaseModel):
    """Request for a model-compiled, inactive policy candidate."""

    policy_id: str = Field(pattern=r"^[A-Z][A-Z0-9_-]{2,49}$")
    name: str = Field(min_length=1, max_length=200)
    policy_text: str = Field(min_length=10, max_length=20_000)
    priority: int | None = Field(default=None, ge=1, le=100)


class DatasetQuery(BaseModel):
    """API request for dataset-scoped metrics/comparison calls."""

    dataset_names: list[DatasetName] | None = Field(default=None, max_length=20)


class WorkflowStateModel(BaseModel):
    """Compact lifecycle state for a single run."""

    request_id: str
    status: Literal["completed", "failed"]
    stages: list[str]
    started_at: str
    completed_at: str


class ScenarioRunResponse(BaseModel):
    """Stable response shape for the frontend console."""

    scenario_id: str
    request_id: str
    source_dataset: str | None
    user_request: str
    attack_category: AttackCategory | None
    expected_risk_level: RiskLevel | None
    external_context_present: bool
    workflow_state: WorkflowStateModel
    target_agent: dict[str, Any]
    proposed_tool_call: ToolCallModel
    firewall_decision: dict[str, Any]
    tool_execution: dict[str, Any]
    expected_decision: Decision | None
    matched_expected: bool | None
    audit: dict[str, Any]
