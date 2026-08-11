"""Provider-neutral structured-output clients for supported model APIs."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from time import monotonic
from typing import Generic, Protocol, TypeVar

from pydantic import BaseModel, ValidationError

from src.llm_settings import LLMSettings

LOGGER = logging.getLogger(__name__)
ResponseT = TypeVar("ResponseT", bound=BaseModel)


class LLMError(RuntimeError):
    """Base class for safe, user-facing model integration failures."""


class LLMConfigurationError(LLMError):
    """Raised when online model configuration is incomplete or unsupported."""


class LLMRequestError(LLMError):
    """Raised when the provider request fails."""


class LLMResponseValidationError(LLMError):
    """Raised when provider output does not satisfy the required schema."""


@dataclass(frozen=True)
class LLMCallMetadata:
    provider: str
    model: str
    purpose: str
    prompt_version: str
    request_id: str | None
    latency_ms: int
    input_tokens: int | None
    output_tokens: int | None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class LLMCallResult(Generic[ResponseT]):
    output: ResponseT
    metadata: LLMCallMetadata


class StructuredLLMClient(Protocol):
    settings: LLMSettings

    def generate_structured(
        self,
        *,
        purpose: str,
        prompt_version: str,
        system_instruction: str,
        prompt: str,
        response_model: type[ResponseT],
    ) -> LLMCallResult[ResponseT]:
        """Generate and validate one schema-constrained model response."""


class GeminiLLMClient:
    """Gemini generate-content adapter used by all online AgentShield agents."""

    def __init__(self, settings: LLMSettings, sdk_client=None):
        if settings.provider.lower() != "gemini":
            raise LLMConfigurationError(
                f"Unsupported LLM provider '{settings.provider}'. Supported provider: gemini."
            )
        if settings.mode != "online" or not settings.api_key:
            raise LLMConfigurationError(
                "Online Gemini client requires AGENTSHIELD_LLM_MODE=online and "
                "AGENTSHIELD_LLM_API_KEY."
            )

        self.settings = settings
        if sdk_client is not None:
            self._client = sdk_client
            return

        try:
            from google import genai
            from google.genai import types
        except ImportError as exc:  # pragma: no cover - depends on installation
            raise LLMConfigurationError(
                "google-genai is not installed; install requirements.txt."
            ) from exc

        retry_options = types.HttpRetryOptions(
            attempts=settings.retry_attempts,
            initial_delay=1.0,
            max_delay=8.0,
            exp_base=2.0,
            jitter=0.2,
            http_status_codes=[408, 429, 500, 502, 503, 504],
        )
        self._client = genai.Client(
            api_key=settings.api_key.get_secret_value(),
            http_options=types.HttpOptions(
                timeout=int(settings.timeout_seconds * 1_000),
                retry_options=retry_options,
            ),
        )

    def generate_structured(
        self,
        *,
        purpose: str,
        prompt_version: str,
        system_instruction: str,
        prompt: str,
        response_model: type[ResponseT],
    ) -> LLMCallResult[ResponseT]:
        started = monotonic()
        try:
            response = self._client.models.generate_content(
                model=self.settings.model,
                contents=prompt,
                config={
                    "system_instruction": system_instruction,
                    "response_mime_type": "application/json",
                    "response_json_schema": response_model.model_json_schema(),
                    "max_output_tokens": self.settings.max_output_tokens,
                },
            )
        except Exception as exc:  # SDK errors vary by transport and API revision.
            LOGGER.warning(
                "Model request failed for purpose=%s error=%s", purpose, type(exc).__name__
            )
            raise LLMRequestError(
                f"Model request failed for {purpose} ({type(exc).__name__})."
            ) from exc

        output_text = getattr(response, "text", None)
        if not output_text:
            raise LLMResponseValidationError(f"Model returned no structured output for {purpose}.")

        try:
            output = response_model.model_validate_json(output_text)
        except ValidationError as exc:
            raise LLMResponseValidationError(
                f"Model output failed schema validation for {purpose}."
            ) from exc

        usage = getattr(response, "usage_metadata", None)
        metadata = LLMCallMetadata(
            provider=self.settings.provider,
            model=self.settings.model,
            purpose=purpose,
            prompt_version=prompt_version,
            request_id=getattr(response, "response_id", None),
            latency_ms=round((monotonic() - started) * 1_000),
            input_tokens=_int_attr(usage, "prompt_token_count"),
            output_tokens=_int_attr(usage, "candidates_token_count"),
        )
        return LLMCallResult(output=output, metadata=metadata)

    def close(self) -> None:
        close = getattr(self._client, "close", None)
        if callable(close):
            close()


class OpenAILLMClient:
    """OpenAI Structured Outputs adapter, including compatible custom base URLs."""

    def __init__(self, settings: LLMSettings, sdk_client=None):
        if settings.provider != "openai":
            raise LLMConfigurationError(
                f"OpenAI client cannot serve provider '{settings.provider}'."
            )
        if settings.mode != "online" or not settings.api_key:
            raise LLMConfigurationError(
                "Online OpenAI client requires online mode and a provider API key."
            )

        self.settings = settings
        if sdk_client is not None:
            self._client = sdk_client
            return

        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover - depends on installation
            raise LLMConfigurationError(
                "openai is not installed; install requirements.txt."
            ) from exc

        client_options = {
            "api_key": settings.api_key.get_secret_value(),
            "timeout": settings.timeout_seconds,
            "max_retries": settings.retry_attempts - 1,
        }
        if settings.base_url:
            client_options["base_url"] = settings.base_url
        self._client = OpenAI(**client_options)

    def generate_structured(
        self,
        *,
        purpose: str,
        prompt_version: str,
        system_instruction: str,
        prompt: str,
        response_model: type[ResponseT],
    ) -> LLMCallResult[ResponseT]:
        started = monotonic()
        request = {
            "model": self.settings.model,
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt},
            ],
            "response_format": response_model,
            "max_completion_tokens": self.settings.max_output_tokens,
        }
        if self.settings.store_interactions:
            request["store"] = True
        try:
            completion = self._client.chat.completions.parse(**request)
        except Exception as exc:  # SDK errors vary by transport and compatible endpoint.
            LOGGER.warning(
                "Model request failed for purpose=%s error=%s", purpose, type(exc).__name__
            )
            raise LLMRequestError(
                f"Model request failed for {purpose} ({type(exc).__name__})."
            ) from exc

        choices = getattr(completion, "choices", None) or []
        message = getattr(choices[0], "message", None) if choices else None
        refusal = getattr(message, "refusal", None)
        if refusal:
            raise LLMResponseValidationError(f"Model refused structured output for {purpose}.")
        parsed = getattr(message, "parsed", None)
        if parsed is None:
            raise LLMResponseValidationError(f"Model returned no structured output for {purpose}.")
        try:
            output = (
                parsed
                if isinstance(parsed, response_model)
                else response_model.model_validate(parsed)
            )
        except ValidationError as exc:
            raise LLMResponseValidationError(
                f"Model output failed schema validation for {purpose}."
            ) from exc

        usage = getattr(completion, "usage", None)
        metadata = LLMCallMetadata(
            provider=self.settings.provider,
            model=self.settings.model,
            purpose=purpose,
            prompt_version=prompt_version,
            request_id=getattr(completion, "id", None),
            latency_ms=round((monotonic() - started) * 1_000),
            input_tokens=_int_attr(usage, "prompt_tokens"),
            output_tokens=_int_attr(usage, "completion_tokens"),
        )
        return LLMCallResult(output=output, metadata=metadata)

    def close(self) -> None:
        close = getattr(self._client, "close", None)
        if callable(close):
            close()


def create_llm_client(settings: LLMSettings) -> StructuredLLMClient | None:
    if settings.mode == "offline":
        return None
    client_types = {
        "gemini": GeminiLLMClient,
        "openai": OpenAILLMClient,
    }
    try:
        client_type = client_types[settings.provider]
    except KeyError as exc:
        raise LLMConfigurationError(f"Unsupported LLM provider '{settings.provider}'.") from exc
    return client_type(settings)


def _int_attr(value, name: str) -> int | None:
    raw = getattr(value, name, None) if value is not None else None
    return int(raw) if raw is not None else None
