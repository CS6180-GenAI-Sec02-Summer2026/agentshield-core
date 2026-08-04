"""Shared API and workflow schemas for AgentShield."""

from typing import Any, Literal

from pydantic import BaseModel, Field


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


class ToolCallModel(BaseModel):
    """Structured tool call proposed by the Target Agent."""

    tool_name: ToolName
    arguments: dict[str, Any] = Field(default_factory=dict)


class ScenarioModel(BaseModel):
    """Labeled or ad-hoc AgentShield scenario."""

    id: str | None = None
    user_request: str = Field(min_length=1)
    external_context: str | None = None
    proposed_tool_call: ToolCallModel | None = None
    expected_decision: Decision | None = None
    risk_level: RiskLevel | None = None
    attack_category: AttackCategory | None = None
    explanation: str | None = None


class ScenarioRunRequest(BaseModel):
    """API request for running one scenario."""

    user_request: str | None = None
    external_context: str | None = None
    proposed_tool_call: ToolCallModel | None = None
    scenario: ScenarioModel | None = None
    execute_allowed_tool: bool = False


class BatchRunRequest(BaseModel):
    """API request for running many scenarios."""

    scenarios: list[ScenarioModel] | None = None
    dataset_names: list[str] | None = None
    execute_allowed_tools: bool = False


class DatasetQuery(BaseModel):
    """API request for dataset-scoped metrics/comparison calls."""

    dataset_names: list[str] | None = None


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
