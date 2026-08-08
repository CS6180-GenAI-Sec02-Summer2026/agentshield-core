# Dataset

## Purpose

The dataset is a synthetic benchmark of agent tool-call scenarios with
ground-truth firewall decisions. Each example pairs a user request, optional
external context, and proposed tool call with the decision the firewall should
make. These labels drive policy validation, risk classification, metrics,
baselines, and regression tests.

## Composition

The full stored evaluation set contains 94 scenarios:

| Source | Count | Role |
| --- | --- | --- |
| `data/demo_scenarios.json` | 3 | Compact demo set covering all three decisions. |
| `data/sample_examples.json` | 6 | Small representative set for schema and label checks. |
| `data/dataset_v0.json` | 50 | Balanced baseline of benign and malicious scenarios. |
| `data/red_team_examples.json` | 25 | Adversarial scenarios spanning all supported tools. |
| `data/benign_edge_cases.json` | 10 | Safe actions that resemble attacks and guard against overblocking. |

The deeper evaluation corpus is the 85-example set formed by
`dataset_v0.json`, `red_team_examples.json`, and `benign_edge_cases.json`:

| Split | Count |
| --- | --- |
| Benign | 35 |
| Malicious | 50 |
| `ALLOW` labels | 27 |
| `ASK_APPROVAL` labels | 12 |
| `BLOCK` labels | 46 |

## Schema

Every scenario follows `data/dataset_schema.json` and includes:

| Field | Purpose |
| --- | --- |
| `user_request` | Natural-language request from the user. |
| `external_context` | External content the agent read; may contain injected instructions. |
| `proposed_tool_call` | Proposed tool name and arguments before firewall evaluation. |
| `expected_decision` | Ground-truth decision: `ALLOW`, `BLOCK`, or `ASK_APPROVAL`. |
| `risk_level` | Impact if the call executed unchecked: `low`, `medium`, `high`, or `critical`. |
| `attack_category` | `none`, `prompt_injection`, `data_exfiltration`, or `unauthorized_action`. |
| `explanation` | Human-readable rationale for the expected decision. |

Stable ids such as `v0-*`, `rt-*`, `be-*`, and `demo-*` support scenario lookup.

## Tool Coverage

All eight supported mock tools are represented:

`send_email`, `read_file`, `write_file`, `delete_file`,
`create_calendar_event`, `create_task`, `create_github_issue`,
`send_http_request`.

The corpus deliberately covers high-risk tools such as external HTTP requests,
email, file deletion, protected writes, public issue creation, calendar events,
and task creation.

## Label Rules

The controlled vocabularies are documented in
[`../../data/attack_taxonomy.md`](../../data/attack_taxonomy.md).

General labeling rules:

- Benign scenarios use `attack_category: none` and are allowed when the tool call
  matches the request and is low impact.
- Destructive but user-requested actions use `ASK_APPROVAL` when execution
  should be confirmed.
- Prompt-injection, data-exfiltration, and unauthorized-action scenarios use
  `BLOCK` when the proposed call violates user intent or exposes sensitive data.
- External sends, external state-changing HTTP calls, and external attendees may
  use `ASK_APPROVAL` when the user authorized the action but the impact warrants
  confirmation.

## Quality Checks

Dataset quality is enforced by:

```bash
PYTHONPATH=. python3 data/validate_dataset.py data/sample_examples.json
PYTHONPATH=. python3 data/validate_dataset.py data/demo_scenarios.json
PYTHONPATH=. python3 data/validate_dataset.py data/dataset_v0.json
PYTHONPATH=. python3 data/validate_dataset.py data/red_team_examples.json
PYTHONPATH=. python3 data/validate_dataset.py data/benign_edge_cases.json
PYTHONPATH=. python3 data/corpus_report.py
PYTHONPATH=. python3 data/quality_report.py
PYTHONPATH=. python3 src/label_validator.py --rules data/policy_rules.json --dataset data/dataset_v0.json
PYTHONPATH=. python3 src/label_validator.py --rules data/policy_rules.json --dataset data/red_team_examples.json
PYTHONPATH=. python3 src/label_validator.py --rules data/policy_rules.json --dataset data/benign_edge_cases.json
```

The label validator uses the same shared intent, security-pattern, and text
helpers as the runtime policy path, so dataset labels stay aligned with firewall
behavior.

## Synthetic Data Boundary

All examples are synthetic. Email addresses use `*.example` domains, and
secret-like values use clearly marked `<synthetic-...-placeholder>` tokens.
Tests and scans reject real-looking contact data or credentials.
