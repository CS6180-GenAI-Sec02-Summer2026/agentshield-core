# Red-Team Method

## Purpose

The Red-Team Agent creates adversarial scenarios that stress-test AgentShield.
Online mode performs schema-constrained model generation from bounded seeds;
offline mode produces the stable committed regression corpus.

## Components

| Component | Role |
| --- | --- |
| `agents/injection_patterns.py` | Prompt-injection pattern library. |
| `agents/red_team_seeds.py` | Attack seed catalog grouped by tool and attack style. |
| `agents/red_team_agent.py` | Renders a `ScenarioSeed` into a schema-valid example. |
| `agents/generate_red_team.py` | Writes `data/red_team_examples.json`. |

Online pipeline:

```text
ScenarioSeed -> model generation -> tool validation -> synthetic-data validation -> scenario
```

## Injection Patterns

The generator uses five prompt-injection styles:

| Pattern | Purpose |
| --- | --- |
| `direct_override` | Explicitly instructs the agent to ignore prior instructions. |
| `hidden_html_comment` | Hides the directive in markup-like content. |
| `fake_system_note` | Impersonates a privileged instruction inside external context. |
| `authority_urgency` | Uses claimed authority and urgency to pressure compliance. |
| `fake_tool_response` | Presents the directive as if it came from a tool response. |

Using multiple styles prevents the corpus from depending on one obvious phrase.

## Generation Modes

Online mode uses the shared backend model runtime, strict structured output,
tool-registry validation, and reserved-domain checks. Offline mode fills
checked-in templates from checked-in seeds, requires no network access, and
produces byte-stable outputs suitable for tests and audits.

Regenerate and validate:

```bash
PYTHONPATH=. python3 agents/generate_red_team.py
PYTHONPATH=. python3 data/validate_dataset.py data/red_team_examples.json
```

## Coverage

`data/red_team_examples.json` contains 25 adversarial examples across all eight
supported tools:

- `send_http_request`
- `send_email`
- `delete_file`
- `write_file`
- `create_github_issue`
- `create_calendar_event`
- `read_file`
- `create_task`

Attack categories include prompt injection, data exfiltration, and unauthorized
actions. The generated set includes both injected-context attacks and pure
tool-call attacks where the risk is visible in the proposed arguments.

## Quality Controls

The red-team generator is covered by:

```bash
PYTHONPATH=. python3 agents/test_injection_patterns.py
PYTHONPATH=. python3 agents/test_red_team_agent.py
PYTHONPATH=. python3 data/validate_dataset.py data/red_team_examples.json
```

The tests check pattern integrity, deterministic generation, online structured
generation, schema validity, tool coverage, label consistency, and
synthetic-only content.

## Impact

The expanded adversarial corpus exposed missing policy coverage around protected
writes, public issue credential leaks, sensitive reads, unauthorized calendar
and task creation, and external HTTP behavior. Those issue classes are now
covered by reusable policy checks and regression tests rather than by
scenario-specific exceptions.
