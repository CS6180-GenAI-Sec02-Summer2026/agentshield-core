"""
Mock tool registry for AgentShield.

These tools validate and describe tool calls without performing real external
actions. The orchestrator can use them for demos and API responses while keeping
the firewall as the execution gate.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any


class ToolValidationError(ValueError):
    """Raised when a proposed tool call does not match a supported mock tool."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    required_any: tuple[tuple[str, ...], ...]
    optional: tuple[str, ...] = ()
    description: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class MockToolResult:
    tool_name: str
    executed: bool
    status: str
    message: str
    arguments: dict[str, Any]
    output: dict[str, Any]

    def to_dict(self) -> dict:
        return asdict(self)


TOOL_SPECS: dict[str, ToolSpec] = {
    "send_email": ToolSpec(
        name="send_email",
        required_any=(("to", "recipients"), ("subject",), ("body", "content")),
        optional=("cc", "bcc", "attachments", "targets"),
        description="Prepare an email for delivery.",
    ),
    "read_file": ToolSpec(
        name="read_file",
        required_any=(("file_path", "path"),),
        description="Read a local file.",
    ),
    "write_file": ToolSpec(
        name="write_file",
        required_any=(("file_path", "path"), ("content", "body")),
        optional=("mode",),
        description="Write content to a local file.",
    ),
    "delete_file": ToolSpec(
        name="delete_file",
        required_any=(("file_path", "path", "targets"),),
        optional=("recursive",),
        description="Delete one or more local files.",
    ),
    "create_calendar_event": ToolSpec(
        name="create_calendar_event",
        required_any=(("title", "summary"), ("time", "start_time", "start")),
        optional=("participants", "attendees", "visibility", "end_time", "location"),
        description="Create a calendar event.",
    ),
    "create_task": ToolSpec(
        name="create_task",
        required_any=(("title",),),
        optional=("body", "description", "assignee", "due_date", "participants", "visibility"),
        description="Create a task item.",
    ),
    "create_github_issue": ToolSpec(
        name="create_github_issue",
        required_any=(("title",), ("body", "description")),
        optional=("repo", "repository", "repo_visibility", "labels"),
        description="Create a GitHub issue.",
    ),
    "send_http_request": ToolSpec(
        name="send_http_request",
        required_any=(("url",),),
        optional=("method", "headers", "body", "params"),
        description="Prepare an HTTP request.",
    ),
}

TOOL_EXECUTION_LOG: list[dict[str, Any]] = []


def list_tool_specs() -> list[dict]:
    """Return supported mock tool metadata for the API and docs."""
    return [spec.to_dict() for spec in TOOL_SPECS.values()]


def normalize_tool_call(tool_call: dict[str, Any]) -> dict[str, Any]:
    """Return a canonical tool-call shape used by the firewall and mock tools."""
    if not isinstance(tool_call, dict):
        raise ToolValidationError("Tool call must be an object.")

    tool_name = tool_call.get("tool_name")
    arguments = tool_call.get("arguments", {})
    if not isinstance(arguments, dict):
        raise ToolValidationError("Tool call arguments must be an object.")

    validate_tool_call(tool_name, arguments)
    return {"tool_name": tool_name, "arguments": arguments}


def validate_tool_call(tool_name: str | None, arguments: dict[str, Any]) -> None:
    """Validate that a proposed tool call matches one supported mock tool."""
    if not tool_name or tool_name not in TOOL_SPECS:
        supported = ", ".join(sorted(TOOL_SPECS))
        raise ToolValidationError(f"Unsupported tool '{tool_name}'. Supported tools: {supported}.")

    spec = TOOL_SPECS[tool_name]
    missing_groups = []
    for aliases in spec.required_any:
        if not any(_has_value(arguments.get(alias)) for alias in aliases):
            missing_groups.append("/".join(aliases))

    if missing_groups:
        missing = ", ".join(missing_groups)
        raise ToolValidationError(f"Missing required argument group(s) for {tool_name}: {missing}.")


def execute_mock_tool(tool_call: dict[str, Any]) -> MockToolResult:
    """
    Simulate a tool call after the firewall allows it.

    No real email, file, calendar, GitHub, or HTTP action happens here.
    """
    normalized = normalize_tool_call(tool_call)
    tool_name = normalized["tool_name"]
    arguments = normalized["arguments"]
    now = datetime.now(timezone.utc).isoformat()

    result = MockToolResult(
        tool_name=tool_name,
        executed=True,
        status="mock_success",
        message=f"Mock {tool_name} completed. No external side effects were performed.",
        arguments=arguments,
        output={
            "mock": True,
            "timestamp": now,
            "resource_id": f"mock-{tool_name}-{abs(hash(str(arguments))) % 100000}",
        },
    )
    _append_tool_log(result)
    return result


def blocked_tool_result(tool_call: dict[str, Any], decision: str) -> MockToolResult:
    """Return a mock execution result for blocked or approval-required calls."""
    normalized = normalize_tool_call(tool_call)
    tool_name = normalized["tool_name"]
    if decision == "ALLOW":
        status = "not_executed"
        message = "Tool was allowed by the firewall, but mock execution was disabled."
    elif decision == "ASK_APPROVAL":
        status = "requires_approval"
        message = "Tool was not executed because firewall approval is required."
    else:
        status = "blocked"
        message = "Tool was not executed because the firewall blocked it."

    result = MockToolResult(
        tool_name=tool_name,
        executed=False,
        status=status,
        message=message,
        arguments=normalized["arguments"],
        output={"mock": True, "resource_id": None},
    )
    _append_tool_log(result)
    return result


def get_tool_execution_log() -> list[dict[str, Any]]:
    """Return mock tool input/output history for this process."""
    return list(TOOL_EXECUTION_LOG)


def clear_tool_execution_log() -> None:
    """Clear mock tool input/output history."""
    TOOL_EXECUTION_LOG.clear()


def _has_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return True


def _append_tool_log(result: MockToolResult) -> None:
    TOOL_EXECUTION_LOG.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool_name": result.tool_name,
        "executed": result.executed,
        "status": result.status,
        "arguments": result.arguments,
        "output": result.output,
    })
