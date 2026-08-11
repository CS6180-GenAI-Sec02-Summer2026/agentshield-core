"""Shared runtime controls for model-backed AgentShield components."""

from dataclasses import dataclass
from typing import TypeVar

from pydantic import BaseModel

from src.llm_client import LLMCallResult, LLMConfigurationError, StructuredLLMClient
from src.llm_settings import LLMSettings

ResponseT = TypeVar("ResponseT", bound=BaseModel)


@dataclass(frozen=True)
class AgentLLMRuntime:
    """Bind validated settings and one reusable provider client to every agent."""

    settings: LLMSettings
    client: StructuredLLMClient | None = None

    def enabled(self, agent_name: str) -> bool:
        return self.settings.agent_enabled(agent_name)

    def generate(
        self,
        *,
        agent_name: str,
        purpose: str,
        prompt_version: str,
        system_instruction: str,
        prompt: str,
        response_model: type[ResponseT],
    ) -> LLMCallResult[ResponseT]:
        if not self.enabled(agent_name):
            raise LLMConfigurationError(f"Model-backed agent '{agent_name}' is not enabled.")
        if self.client is None:
            raise LLMConfigurationError(
                f"Model-backed agent '{agent_name}' has no configured provider client."
            )
        return self.client.generate_structured(
            purpose=purpose,
            prompt_version=prompt_version,
            system_instruction=system_instruction,
            prompt=prompt,
            response_model=response_model,
        )

    @property
    def fallback_to_offline(self) -> bool:
        return self.settings.fallback_to_offline


def offline_runtime() -> AgentLLMRuntime:
    """Create a runtime that never performs provider calls."""
    return AgentLLMRuntime(settings=LLMSettings(mode="offline"))
