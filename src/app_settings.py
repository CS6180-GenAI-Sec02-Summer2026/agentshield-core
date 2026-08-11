"""Typed non-secret application settings loaded from the backend environment."""

from pathlib import Path

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parent.parent


class AppSettings(BaseSettings):
    """Load service paths and browser access settings from the backend .env file."""

    model_config = SettingsConfigDict(
        env_file=REPO_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    rules_path: str = Field(
        default="data/policy_rules.json",
        validation_alias=AliasChoices("AGENTSHIELD_RULES_PATH", "rules_path"),
    )
    data_dir: str = Field(
        default="data",
        validation_alias=AliasChoices("AGENTSHIELD_DATA_DIR", "data_dir"),
    )
    cors_origins: str = Field(
        default="http://localhost:5173,http://127.0.0.1:5173",
        validation_alias=AliasChoices("AGENTSHIELD_CORS_ORIGINS", "cors_origins"),
    )

    @field_validator("rules_path", "data_dir", "cors_origins")
    @classmethod
    def validate_nonempty_setting(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("must not be empty")
        return value

    @property
    def cors_origin_list(self) -> list[str]:
        """Return normalized, unique CORS origins in configured order."""
        return list(
            dict.fromkeys(
                origin.strip() for origin in self.cors_origins.split(",") if origin.strip()
            )
        )
