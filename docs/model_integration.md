# Model Integration

AgentShield has a provider-backed online mode and an explicit offline mode. One
shared backend runtime serves six schema-constrained agent responsibilities:

| Agent | Online responsibility | Safety constraint |
| --- | --- | --- |
| Target Agent | Generate one structured tool-call proposal from user intent. | Cannot execute tools; registry validation rejects unsupported calls. |
| Red-Team Agent | Generate synthetic adversarial scenarios from bounded seeds. | Reserved `.example` domains and synthetic-data validation are mandatory. |
| Policy Compiler Agent | Translate natural-language policy into a structured candidate. | Candidate is disabled until human review and activation. |
| Risk Analysis Agent | Detect semantic risk missed by local patterns. | Model evidence is merged conservatively with local detectors. |
| Audit Explanation Agent | Explain the authoritative firewall decision. | Cannot change the decision or cite unmatched rules. |
| Audit Judge | Score explanation quality against the five-part rubric. | Does not decide policy correctness; totals are computed locally. |

The deterministic policy checker remains the final execution boundary. Model
output cannot convert a policy `BLOCK` or `ASK_APPROVAL` decision into `ALLOW`.

## Environment Files

The committed `.env.example` documents every setting. The local `.env` file is
ignored by Git and holds the selected provider credential:

```bash
cp .env.example .env
```

Do not commit `.env`. Do not put provider keys in `VITE_` variables, request
payloads, logs, documentation, or browser storage.

## Select A Provider

The same three fields select either supported provider:

```dotenv
AGENTSHIELD_LLM_PROVIDER=gemini
AGENTSHIELD_LLM_MODEL=gemini-3.6-flash
AGENTSHIELD_LLM_API_KEY=your-provider-key
AGENTSHIELD_LLM_MODE=online
```

For Gemini, create a key in
[Google AI Studio](https://aistudio.google.com/app/apikey). The adapter uses the
stable, stateless `models.generate_content` API with a strict JSON schema.

For an OpenAI model, change only the provider, model, and generic key values:

```dotenv
AGENTSHIELD_LLM_PROVIDER=openai
AGENTSHIELD_LLM_MODEL=gpt-5.6-luna
AGENTSHIELD_LLM_API_KEY=your-provider-key
AGENTSHIELD_LLM_MODE=online
```

The OpenAI adapter uses typed Chat Completions structured outputs. A custom
`AGENTSHIELD_LLM_BASE_URL` can target an OpenAI-compatible endpoint, provided
that endpoint implements Chat Completions JSON-schema structured outputs. An
arbitrary text-completion endpoint is not sufficient.

## Configuration Reference

| Variable | Template default | Purpose |
| --- | --- | --- |
| `AGENTSHIELD_LLM_API_KEY` | empty | One backend-only credential for the selected provider. |
| `AGENTSHIELD_LLM_PROVIDER` | `gemini` | Adapter name: `gemini` or `openai`. |
| `AGENTSHIELD_LLM_MODEL` | `gemini-3.6-flash` | Provider model identifier. |
| `AGENTSHIELD_LLM_MODE` | `offline` | `online` or reproducible `offline`. |
| `AGENTSHIELD_LLM_BASE_URL` | empty | Optional OpenAI-compatible API base URL; rejected for Gemini. |
| `AGENTSHIELD_LLM_ENABLED_AGENTS` | all six agents | Comma-separated online agent set. |
| `AGENTSHIELD_LLM_TIMEOUT_SECONDS` | `30` | Provider request timeout. |
| `AGENTSHIELD_LLM_RETRY_ATTEMPTS` | `4` | Total attempts for transient failures. |
| `AGENTSHIELD_LLM_MAX_INPUT_CHARS` | `30000` | Prompt-size limit after redaction. |
| `AGENTSHIELD_LLM_MAX_OUTPUT_TOKENS` | `2048` | Structured-response token limit. |
| `AGENTSHIELD_LLM_MAX_ONLINE_BATCH_SIZE` | `20` | Maximum scenarios in one online batch. |
| `AGENTSHIELD_LLM_STORE_INTERACTIONS` | `false` | Optional OpenAI storage flag; rejected for Gemini. |
| `AGENTSHIELD_LLM_FALLBACK_TO_OFFLINE` | `false` | Permit an explicitly labeled offline fallback. |
| `AGENTSHIELD_LLM_REGENERATE_STORED_TOOL_CALLS` | `false` | Regenerate fixed benchmark tool calls in a separate experiment. |

The `/health` response exposes only non-secret status. Online mode fails during
configuration loading when the generic key is empty, the provider is unknown,
or a provider-specific option is incompatible.

## Structured Tool Calls

The model generates a strict tool-call object rather than executing a provider
function directly. AgentShield validates the object against its local tool
registry, passes it through risk and policy enforcement, and permits only
optional mock execution after an `ALLOW` decision. This separation makes the
firewall the single authoritative execution gate.

Map-like HTTP headers and query parameters use strict key/value arrays in model
output and are converted to dictionaries only after validation. Unknown fields,
duplicate keys, unsupported tools, wrong argument types, oversized payloads,
and untyped schema fragments are rejected.

## Data And Failure Handling

- Credential-like values are recursively redacted before prompt serialization.
- Gemini requests are stateless; OpenAI storage defaults to `false`.
- Inputs, online batch sizes, and outputs have hard limits.
- Every model response is validated by a closed Pydantic schema.
- Transient requests use bounded retries and timeouts.
- Provider errors are sanitized and returned by the API as HTTP 503.
- Offline fallback is disabled by default. When enabled, output is labeled
  `offline_fallback`; it is never represented as a model result.
- The frontend calls the backend only and never receives the API key.

Review the selected provider's data-use terms before sending production data.
The bundled scenarios are synthetic, but a deployment must add its own access,
privacy, retention, monitoring, rate-limit, and cost controls.

## Reproducible Evaluation

The committed benchmark uses fixed `proposed_tool_call` values and offline
scoring by default. This preserves comparability across the unprotected,
prompt-only, and AgentShield configurations. Online runs exercise generation,
semantic risk, explanations, and judging, but their outputs are not silently
mixed into the committed deterministic accuracy metrics.

## Validation

Automated tests use schema-faithful fake Gemini and OpenAI clients. They cover
all six online agent paths, strict output validation, redaction, fallback
labeling, provider metadata, request configuration, and failure handling:

```bash
PYTHONPATH=. .venv/bin/python -m pytest -q
```

After adding a real key and changing the mode to `online`, run:

```bash
PYTHONPATH=. .venv/bin/python scripts/llm_smoke.py
```

The smoke test calls target generation, risk analysis, audit explanation,
judging, red-team generation, and policy compilation. It invokes only
side-effect-free mock workflows. No live-provider result is claimed until this
command succeeds with the selected provider and model.
