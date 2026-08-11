"""
Mock tool registry for AgentShield.

These tools validate and describe tool calls without performing real external
actions. The orchestrator can use them for demos and API responses while keeping
the firewall as the execution gate.
"""

import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from src.llm_safety import redact_for_model


class ToolValidationError(ValueError):
    """Raised when a proposed tool call does not match a supported mock tool."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    required_any: tuple[tuple[str, ...], ...]
    argument_types: dict[str, tuple[type, ...]]
    description: str = ""

    def to_dict(self) -> dict:
        required_arguments = {argument for aliases in self.required_any for argument in aliases}
        return {
            "name": self.name,
            "required_any": self.required_any,
            "optional": tuple(
                argument for argument in self.argument_types if argument not in required_arguments
            ),
            "argument_types": {
                argument: tuple(value_type.__name__ for value_type in value_types)
                for argument, value_types in self.argument_types.items()
            },
            "description": self.description,
        }


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
        argument_types={
            "to": (str, list),
            "recipients": (list,),
            "subject": (str,),
            "body": (str,),
            "content": (str,),
            "cc": (list,),
            "bcc": (list,),
            "attachments": (list,),
            "targets": (list,),
        },
        description="Prepare an email for delivery.",
    ),
    "read_file": ToolSpec(
        name="read_file",
        required_any=(("file_path", "path"),),
        argument_types={"file_path": (str,), "path": (str,)},
        description="Read a local file.",
    ),
    "write_file": ToolSpec(
        name="write_file",
        required_any=(("file_path", "path"), ("content", "body")),
        argument_types={
            "file_path": (str,),
            "path": (str,),
            "content": (str,),
            "body": (str,),
            "mode": (str,),
        },
        description="Write content to a local file.",
    ),
    "delete_file": ToolSpec(
        name="delete_file",
        required_any=(("file_path", "path", "targets"),),
        argument_types={
            "file_path": (str,),
            "path": (str,),
            "targets": (list,),
            "recursive": (bool,),
        },
        description="Delete one or more local files.",
    ),
    "create_calendar_event": ToolSpec(
        name="create_calendar_event",
        required_any=(("title", "summary"), ("time", "start_time", "start")),
        argument_types={
            "title": (str,),
            "summary": (str,),
            "time": (str,),
            "start_time": (str,),
            "start": (str,),
            "participants": (list,),
            "attendees": (list,),
            "visibility": (str,),
            "end_time": (str,),
            "end": (str,),
            "location": (str,),
            "description": (str,),
        },
        description="Create a calendar event.",
    ),
    "create_task": ToolSpec(
        name="create_task",
        required_any=(("title",),),
        argument_types={
            "title": (str,),
            "body": (str,),
            "description": (str,),
            "assignee": (str,),
            "due_date": (str,),
            "due": (str,),
            "participants": (list,),
            "visibility": (str,),
        },
        description="Create a task item.",
    ),
    "create_github_issue": ToolSpec(
        name="create_github_issue",
        required_any=(("title",), ("body", "description")),
        argument_types={
            "title": (str,),
            "body": (str,),
            "description": (str,),
            "repo": (str,),
            "repository": (str,),
            "repo_visibility": (str,),
            "labels": (list,),
        },
        description="Create a GitHub issue.",
    ),
    "send_http_request": ToolSpec(
        name="send_http_request",
        required_any=(("url",),),
        argument_types={
            "url": (str,),
            "method": (str,),
            "headers": (dict,),
            "body": (str, dict, list),
            "params": (dict,),
        },
        description="Prepare an HTTP request.",
    ),
}

STRING_LIST_ARGUMENTS = {
    "to",
    "recipients",
    "cc",
    "bcc",
    "attachments",
    "targets",
    "participants",
    "attendees",
    "labels",
}
STRING_MAP_ARGUMENTS = {"headers", "params"}

TOOL_EXECUTION_LOG: list[dict[str, Any]] = []
MAX_TOOL_EXECUTION_LOG_ENTRIES = 1000


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
    unexpected = sorted(set(arguments) - set(spec.argument_types))
    if unexpected:
        raise ToolValidationError(
            f"Unexpected argument(s) for {tool_name}: {', '.join(unexpected)}."
        )

    expected_types = spec.argument_types
    for argument_name, value in arguments.items():
        if value is None:
            continue
        if not isinstance(value, expected_types[argument_name]):
            expected = "/".join(value_type.__name__ for value_type in expected_types[argument_name])
            raise ToolValidationError(
                f"Argument '{argument_name}' for {tool_name} must be {expected}."
            )
        if (
            argument_name in STRING_LIST_ARGUMENTS
            and isinstance(value, list)
            and (not value or any(not isinstance(item, str) or not item.strip() for item in value))
        ):
            raise ToolValidationError(
                f"Argument '{argument_name}' for {tool_name} must contain non-empty strings."
            )
        if (
            argument_name in STRING_MAP_ARGUMENTS
            and isinstance(value, dict)
            and any(
                not isinstance(key, str) or not isinstance(item, str) for key, item in value.items()
            )
        ):
            raise ToolValidationError(
                f"Argument '{argument_name}' for {tool_name} must map strings to strings."
            )

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
            "resource_id": _stable_resource_id(tool_name, arguments),
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
    TOOL_EXECUTION_LOG.append(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool_name": result.tool_name,
            "executed": result.executed,
            "status": result.status,
            "arguments": redact_for_model(result.arguments),
            "output": result.output,
        }
    )
    if len(TOOL_EXECUTION_LOG) > MAX_TOOL_EXECUTION_LOG_ENTRIES:
        del TOOL_EXECUTION_LOG[:-MAX_TOOL_EXECUTION_LOG_ENTRIES]


def _stable_resource_id(tool_name: str, arguments: dict[str, Any]) -> str:
    payload = json.dumps(arguments, sort_keys=True, default=str)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:12]
    return f"mock-{tool_name}-{digest}"
