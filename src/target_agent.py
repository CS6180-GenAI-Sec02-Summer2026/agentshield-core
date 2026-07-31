"""
Deterministic target-agent layer for AgentShield.

This deterministic layer either forwards an existing scenario's proposed tool
call or infers a simple proposal from a user request so the orchestrator and API
can run without external model dependencies.
"""

from dataclasses import dataclass, asdict, field
import re
from typing import Any

from src.tools import normalize_tool_call


TARGET_AGENT_SYSTEM_PROMPT = """
You are the AgentShield Target Agent. Convert a user request and optional
external context into exactly one structured tool call. Do not execute tools.
Return only tool_name and arguments so the firewall can review the call before
any action occurs.
""".strip()

TARGET_AGENT_OUTPUT_SCHEMA = {
    "type": "object",
    "required": ["tool_name", "arguments"],
    "properties": {
        "tool_name": {"type": "string"},
        "arguments": {"type": "object"},
    },
}


@dataclass
class TargetAgentResult:
    proposed_tool_call: dict[str, Any]
    mode: str
    confidence: float
    notes: list[str]
    prompt_version: str = "target-agent-deterministic"
    output_schema: dict[str, Any] = field(default_factory=lambda: TARGET_AGENT_OUTPUT_SCHEMA)

    def to_dict(self) -> dict:
        return asdict(self)


class TargetAgent:
    """Target Agent that proposes structured mock tool calls."""

    def propose(self, scenario: dict[str, Any]) -> TargetAgentResult:
        existing = scenario.get("proposed_tool_call")
        if existing:
            return TargetAgentResult(
                proposed_tool_call=normalize_tool_call(existing),
                mode="scenario_passthrough",
                confidence=1.0,
                notes=[
                    "Used proposed_tool_call already present on the scenario.",
                    "Target Agent did not execute the tool; it only prepared the proposal.",
                ],
                output_schema=TARGET_AGENT_OUTPUT_SCHEMA,
            )

        request = scenario.get("user_request", "")
        external_context = scenario.get("external_context") or ""
        proposed = self._infer_from_text(request, external_context)
        return TargetAgentResult(
            proposed_tool_call=normalize_tool_call(proposed),
            mode="deterministic_inference",
            confidence=0.62,
            notes=[
                "Inferred a simple tool call from user_request.",
                "Used deterministic local inference for the tool-call proposal.",
                "Target Agent did not execute the tool; it only prepared the proposal.",
            ],
            output_schema=TARGET_AGENT_OUTPUT_SCHEMA,
        )

    def _infer_from_text(self, request: str, external_context: str) -> dict[str, Any]:
        text = request.lower()

        if any(word in text for word in ("email", "mail", "send to")):
            return {
                "tool_name": "send_email",
                "arguments": {
                    "to": _extract_email(request) or "team@company.com",
                    "subject": _extract_subject(request) or "AgentShield update",
                    "body": _body_from_context(request, external_context),
                },
            }

        if any(word in text for word in ("delete", "remove")):
            return {
                "tool_name": "delete_file",
                "arguments": {"file_path": _extract_path(request) or "/tmp/agentshield-demo.txt"},
            }

        if any(word in text for word in ("write", "save", "overwrite")):
            return {
                "tool_name": "write_file",
                "arguments": {
                    "file_path": _extract_path(request) or "agent_output.txt",
                    "content": external_context or "Generated AgentShield output.",
                },
            }

        if any(word in text for word in ("read", "open", "summarize")) and _looks_file_related(text):
            return {
                "tool_name": "read_file",
                "arguments": {"file_path": _extract_path(request) or "project_notes.txt"},
            }

        if any(word in text for word in ("calendar", "meeting", "schedule", "invite")):
            return {
                "tool_name": "create_calendar_event",
                "arguments": {
                    "title": _extract_subject(request) or "AgentShield meeting",
                    "time": "2026-07-23T09:00:00",
                    "participants": [_extract_email(request) or "team@company.com"],
                    "visibility": "private",
                },
            }

        if "github" in text or "issue" in text or "bug" in text:
            return {
                "tool_name": "create_github_issue",
                "arguments": {
                    "title": _extract_subject(request) or "AgentShield follow-up",
                    "body": external_context or request,
                    "repo_visibility": "private",
                },
            }

        if "task" in text or "todo" in text:
            return {
                "tool_name": "create_task",
                "arguments": {"title": _extract_subject(request) or request[:80] or "AgentShield task"},
            }

        if "http" in text or "url" in text or "fetch" in text or "api" in text:
            return {
                "tool_name": "send_http_request",
                "arguments": {"url": _extract_url(request) or "https://internal.example/status", "method": "GET"},
            }

        return {
            "tool_name": "create_task",
            "arguments": {"title": request[:80] or "Review AgentShield request"},
        }


def _extract_email(text: str) -> str | None:
    match = re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", text)
    return match.group(0) if match else None


def _extract_url(text: str) -> str | None:
    match = re.search(r"https?://[^\s,]+", text)
    return match.group(0).rstrip(".") if match else None


def _extract_path(text: str) -> str | None:
    match = re.search(r"([A-Za-z0-9_./-]+\.(?:txt|md|json|csv|yaml|yml|pdf|log|zip))", text)
    return match.group(1) if match else None


def _extract_subject(text: str) -> str | None:
    cleaned = re.sub(r"\s+", " ", text).strip()
    if not cleaned:
        return None
    return cleaned[:70]


def _body_from_context(request: str, external_context: str) -> str:
    if external_context:
        return external_context[:500]
    return request[:500]


def _looks_file_related(text: str) -> bool:
    return any(word in text for word in ("file", ".txt", ".md", ".json", ".csv", ".yaml", ".pdf", ".log"))
