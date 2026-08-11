"""Strict structured-output models shared by model-backed agents."""

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.schemas import Decision, RiskLevel, ToolName


class StrictLLMModel(BaseModel):
    """Base for model outputs that must reject unrecognized fields."""

    model_config = ConfigDict(extra="forbid")


class LLMKeyValue(StrictLLMModel):
    """Strict key-value representation for map-like tool arguments."""

    key: str = Field(min_length=1, max_length=200)
    value: str = Field(max_length=2_000)

    @field_validator("key")
    @classmethod
    def normalize_key(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("key must not be blank")
        return value


class ToolArgumentsModel(StrictLLMModel):
    """Strict superset of supported tool arguments; unused fields are omitted."""

    to: str | list[str] | None = None
    recipients: list[str] | None = None
    cc: list[str] | None = None
    bcc: list[str] | None = None
    subject: str | None = None
    body: str | None = None
    content: str | None = None
    attachments: list[str] | None = None
    targets: list[str] | None = None
    file_path: str | None = None
    path: str | None = None
    recursive: bool | None = None
    mode: str | None = None
    title: str | None = None
    summary: str | None = None
    description: str | None = None
    time: str | None = None
    start_time: str | None = None
    start: str | None = None
    end_time: str | None = None
    end: str | None = None
    participants: list[str] | None = None
    attendees: list[str] | None = None
    visibility: str | None = None
    location: str | None = None
    assignee: str | None = None
    due_date: str | None = None
    due: str | None = None
    repo: str | None = None
    repository: str | None = None
    repo_visibility: str | None = None
    labels: list[str] | None = None
    url: str | None = None
    method: str | None = None
    headers: list[LLMKeyValue] | None = Field(default=None, max_length=50)
    params: list[LLMKeyValue] | None = Field(default=None, max_length=50)

    @model_validator(mode="after")
    def reject_duplicate_map_keys(self) -> "ToolArgumentsModel":
        for name, entries, case_insensitive in (
            ("headers", self.headers, True),
            ("params", self.params, False),
        ):
            if entries is None:
                continue
            keys = [entry.key.lower() if case_insensitive else entry.key for entry in entries]
            if len(keys) != len(set(keys)):
                raise ValueError(f"{name} must not contain duplicate keys")
        return self

    def compact(self) -> dict[str, Any]:
        arguments = self.model_dump(exclude_none=True)
        for name in ("headers", "params"):
            entries = arguments.get(name)
            if entries is not None:
                arguments[name] = {entry["key"]: entry["value"] for entry in entries}
        return arguments


class LLMToolCall(StrictLLMModel):
    tool_name: ToolName
    arguments: ToolArgumentsModel
    confidence: float = Field(ge=0.0, le=1.0)
    rationale: str = Field(min_length=1, max_length=500)

    def as_tool_call(self) -> dict[str, Any]:
        return {"tool_name": self.tool_name, "arguments": self.arguments.compact()}


RiskCategory = Literal[
    "none",
    "prompt_injection",
    "data_exfiltration",
    "unauthorized_action",
    "credential_exposure",
]


class LLMRiskAssessment(StrictLLMModel):
    risk_level: RiskLevel
    risk_categories: list[RiskCategory] = Field(min_length=1)
    risk_score: float = Field(ge=0.0, le=1.0)
    risk_factors: list[str] = Field(min_length=1, max_length=12)
    requires_approval: bool


class LLMAuditExplanation(StrictLLMModel):
    decision: Decision
    explanation: str = Field(min_length=20, max_length=2_500)
    referenced_rule_ids: list[str] = Field(default_factory=list, max_length=30)


class LLMJudgeScores(StrictLLMModel):
    states_decision_reason: int = Field(ge=0, le=2)
    references_specifics: int = Field(ge=0, le=2)
    consistent_with_label: int = Field(ge=0, le=2)
    concise: int = Field(ge=0, le=2)
    no_hallucination: int = Field(ge=0, le=2)


class LLMJudgeOutput(StrictLLMModel):
    scores: LLMJudgeScores
    notes: list[str] = Field(default_factory=list, max_length=10)


PolicyCheckType = Literal[
    "equals",
    "contains_file_content",
    "is_external_recipient",
    "contains_secret_pattern",
    "contains_credential_value",
    "is_external_target",
    "contradicts_user_intent",
    "contains_instruction_pattern",
    "not_in_user_request",
    "is_external_url",
    "is_state_changing_http_method",
    "user_request_is_read_only",
    "contains_sensitive_content",
    "has_external_participant_or_public",
    "contains_internal_reference",
    "is_public_repository",
    "contains_sensitive_sharing_content",
    "contains_sensitive_file_path",
    "contains_protected_file_change",
    "is_broadcast_recipient",
    "count_greater_than",
    "greater_than",
]


class LLMPolicyCheck(StrictLLMModel):
    field: str = Field(min_length=1, max_length=200)
    check: PolicyCheckType
    description: str = Field(min_length=1, max_length=500)
    patterns: list[str] | None = Field(default=None, max_length=50)
    value: str | int | float | bool | None = None


class LLMPolicyConditions(StrictLLMModel):
    operator: Literal["AND", "OR", "ALWAYS"]
    checks: list[LLMPolicyCheck] = Field(default_factory=list, max_length=20)


class LLMPolicyCompilation(StrictLLMModel):
    description: str = Field(min_length=1, max_length=500)
    priority: int = Field(ge=1, le=100)
    tools: list[ToolName] = Field(min_length=1)
    conditions: LLMPolicyConditions
    decision: Decision
    risk_level: RiskLevel
    attack_categories: list[
        Literal["prompt_injection", "data_exfiltration", "unauthorized_action"]
    ] = Field(min_length=1)
    explanation_template: str = Field(min_length=1, max_length=1_500)


class LLMRedTeamScenario(StrictLLMModel):
    user_request: str = Field(min_length=1, max_length=2_000)
    external_context: str | None = Field(default=None, max_length=5_000)
    proposed_tool_call: LLMToolCall
    expected_decision: Literal["BLOCK", "ASK_APPROVAL"]
    risk_level: Literal["high", "critical"]
    attack_category: Literal["prompt_injection", "data_exfiltration", "unauthorized_action"]
    explanation: str = Field(min_length=20, max_length=2_000)

    def as_dataset_example(self) -> dict[str, Any]:
        return {
            "user_request": self.user_request,
            "external_context": self.external_context,
            "proposed_tool_call": self.proposed_tool_call.as_tool_call(),
            "expected_decision": self.expected_decision,
            "risk_level": self.risk_level,
            "attack_category": self.attack_category,
            "explanation": self.explanation,
        }
