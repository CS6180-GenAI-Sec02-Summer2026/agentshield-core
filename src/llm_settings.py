"""Typed runtime configuration for model-backed AgentShield components."""

from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parent.parent
SUPPORTED_AGENTS = frozenset({"target", "red_team", "policy", "risk", "audit", "judge"})
SUPPORTED_PROVIDERS = frozenset({"gemini", "openai"})


class LLMSettings(BaseSettings):
    """Load backend-only model configuration from environment variables or .env."""

    model_config = SettingsConfigDict(
        env_file=REPO_ROOT / ".env",
        env_file_encoding="utf-8",
        env_prefix="AGENTSHIELD_LLM_",
        case_sensitive=False,
        extra="ignore",
    )

    provider: str = "gemini"
    model: str = "gemini-3.6-flash"
    mode: Literal["offline", "online"] = "offline"
    api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("api_key", "AGENTSHIELD_LLM_API_KEY"),
    )
    base_url: str | None = None
    enabled_agents: str = "target,red_team,policy,risk,audit,judge"
    timeout_seconds: float = Field(default=30.0, ge=1.0, le=300.0)
    retry_attempts: int = Field(default=4, ge=1, le=10)
    max_input_chars: int = Field(default=30_000, ge=1_000, le=200_000)
    max_output_tokens: int = Field(default=2_048, ge=128, le=8_192)
    max_online_batch_size: int = Field(default=20, ge=1, le=100)
    store_interactions: bool = False
    fallback_to_offline: bool = False
    regenerate_stored_tool_calls: bool = False

    @field_validator("provider", "model")
    @classmethod
    def validate_nonempty_identifier(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be empty")
        return value

    @field_validator("provider")
    @classmethod
    def validate_provider(cls, value: str) -> str:
        value = value.lower()
        if value not in SUPPORTED_PROVIDERS:
            supported = ", ".join(sorted(SUPPORTED_PROVIDERS))
            raise ValueError(f"unsupported provider '{value}'; expected one of: {supported}")
        return value

    @field_validator("base_url")
    @classmethod
    def normalize_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip().rstrip("/")
        return value or None

    @field_validator("enabled_agents")
    @classmethod
    def validate_enabled_agents(cls, value: str) -> str:
        agents = {item.strip().lower() for item in value.split(",") if item.strip()}
        unknown = agents - SUPPORTED_AGENTS
        if unknown:
            raise ValueError(f"unknown agents: {', '.join(sorted(unknown))}")
        return ",".join(sorted(agents))

    @model_validator(mode="after")
    def require_online_api_key(self) -> "LLMSettings":
        if self.mode == "online" and not self.api_key:
            raise ValueError("AGENTSHIELD_LLM_API_KEY is required when AGENTSHIELD_LLM_MODE=online")
        if self.provider == "gemini" and self.base_url:
            raise ValueError("AGENTSHIELD_LLM_BASE_URL is supported only by the openai provider")
        if self.provider == "gemini" and self.store_interactions:
            raise ValueError(
                "AGENTSHIELD_LLM_STORE_INTERACTIONS is supported only by the openai provider"
            )
        return self

    @property
    def enabled_agent_names(self) -> frozenset[str]:
        return frozenset(item for item in self.enabled_agents.split(",") if item)

    def agent_enabled(self, agent_name: str) -> bool:
        return self.mode == "online" and agent_name in self.enabled_agent_names

    def public_status(self) -> dict:
        """Return configuration metadata that is safe to expose from the API."""
        return {
            "mode": self.mode,
            "provider": self.provider,
            "model": self.model,
            "configured": bool(self.api_key),
            "enabled_agents": sorted(self.enabled_agent_names),
            "store_interactions": self.store_interactions,
            "fallback_to_offline": self.fallback_to_offline,
            "regenerate_stored_tool_calls": self.regenerate_stored_tool_calls,
            "max_online_batch_size": self.max_online_batch_size,
        }
