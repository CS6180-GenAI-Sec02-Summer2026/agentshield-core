# AgentShield Policy Rule Format

This document describes the structured JSON rules consumed by the policy
checker and firewall. Rules define when proposed tool calls are blocked, require
approval, or pass through to the default decision.

## File Location

Policy rules are stored in `data/policy_rules.json`.

## Schema Overview

```json
{
  "schema_version": "0.1",
  "default_decision": "ALLOW",
  "rules": []
}
```

If no enabled rule matches a proposed tool call, `default_decision` applies.

## Rule Structure

| Field | Type | Description |
| --- | --- | --- |
| `rule_id` | string | Unique identifier, for example `POLICY-001`. |
| `name` | string | Human-readable rule name. |
| `description` | string | Short rule summary. |
| `priority` | integer | Evaluation order hint. Lower numbers represent higher-priority rules. |
| `enabled` | boolean | Whether the rule is active. Set to `false` to disable without deleting. |
| `tools` | string[] | Tools this rule applies to. |
| `conditions` | object | Condition block that determines whether the rule fires. |
| `decision` | string | `BLOCK`, `ASK_APPROVAL`, or `ALLOW`. |
| `risk_level` | string | `low`, `medium`, `high`, or `critical`. |
| `attack_categories` | string[] | Attack types associated with the rule. |
| `explanation_template` | string | Audit explanation template. Supports `{arguments.field}` replacements. |

## Supported Tools

Rules can target these simulated tools:

`send_email`, `read_file`, `write_file`, `delete_file`,
`create_calendar_event`, `create_task`, `create_github_issue`,
`send_http_request`.

## Conditions Block

```json
{
  "operator": "AND",
  "checks": []
}
```

| Operator | Behavior |
| --- | --- |
| `AND` | All checks must pass for the rule to fire. |
| `OR` | At least one check must pass. |
| `ALWAYS` | Rule fires whenever the tool matches, regardless of checks. |

Each check has a `field`, a `check` type, and optional `value` or `patterns`.

| Check Type | Purpose | Used By |
| --- | --- | --- |
| `equals` | Exact field-value match. | `POLICY-002`, `POLICY-007` |
| `contains_file_content` | Detects file-content references in arguments. | Legacy-compatible checker support |
| `contains_sensitive_sharing_content` | Detects sensitive business data, private exports, or credential-like sharing content. | `POLICY-001` |
| `is_external_recipient` | Checks whether an email recipient is outside trusted domains. | `POLICY-001`, `POLICY-011` |
| `contains_secret_pattern` | Matches credential patterns such as API keys, passwords, and tokens. | `POLICY-003` |
| `is_external_target` | Checks whether a URL or email target is external. | `POLICY-003` |
| `contains_credential_value` | Detects credential-like key/value material. | `POLICY-013` |
| `contradicts_user_intent` | Detects tool calls that do not match the user's original request. | `POLICY-004`, `POLICY-005`, `POLICY-009`, `POLICY-010` |
| `contains_instruction_pattern` | Matches prompt-injection phrases in external context. | `POLICY-004` |
| `not_in_user_request` | Checks whether a value was absent from the user's request. | `POLICY-014`, `POLICY-015` |
| `is_external_url` | Checks whether a URL points to an external domain. | `POLICY-005`, `POLICY-017` |
| `is_state_changing_http_method` | Checks whether an HTTP method can mutate server state. | `POLICY-016`, `POLICY-017` |
| `user_request_is_read_only` | Detects read-only user intent. | `POLICY-016` |
| `contains_sensitive_content` | Detects financial, credential, or proprietary content. | `POLICY-006` |
| `has_external_participant_or_public` | Checks for external participants, attendees, or public visibility. | `POLICY-006`, `POLICY-018` |
| `contains_internal_reference` | Detects internal IPs, private URLs, or system references. | `POLICY-007` |
| `is_public_repository` | Detects public GitHub repositories from visibility or repo naming. | `POLICY-013` |
| `contains_sensitive_file_path` | Detects sensitive file paths such as SSH keys and environment files. | `POLICY-014` |
| `contains_protected_file_change` | Detects writes to config, allowlists, environment files, or security settings. | `POLICY-012` |
| `is_broadcast_recipient` | Detects broad group recipients. | `POLICY-015` |
| `count_greater_than` | Checks whether a list field exceeds a threshold. | `POLICY-008` |
| `greater_than` | Numeric comparison on a field value. | `POLICY-008` |

## Shared Matching Behavior

`src/policy_checker.py`, `src/risk_classifier.py`, and
`src/label_validator.py` share pattern constants and text helpers from
`src/security_patterns.py` and `src/security_text.py`. A pattern change in those
shared modules affects runtime decisions, risk scoring, and label validation
consistently.

`contradicts_user_intent` delegates to `src/intent_utils.py`. Intent keywords
are matched as standalone terms with flexible whitespace for multi-word phrases.
This avoids accidental matches inside unrelated words, such as matching `get`
inside another word. `delete_file` has additional handling so read-only requests
only permit deletion when the request also explicitly asks to delete or remove.

External-recipient and external-target checks use the default internal email
domains `@agentshield.example`, `@company.example`, and `@internal.example`, plus any
internal domains supplied by a programmatic scenario payload.

## Field Paths

Fields use dot notation to access nested values:

- `arguments.to` - the recipient field inside `proposed_tool_call.arguments`
- `arguments.body` - the email body, task body, issue body, or request body
- `arguments.url` - the target URL

Pipe-separated alternatives are supported. For example,
`arguments.body|arguments.title` checks the body first, then falls back to the
title.

## Evaluation Logic

1. Rules are sorted by `priority`.
2. Disabled rules are skipped.
3. Only rules whose `tools` list contains the proposed `tool_name` are evaluated.
4. Every matching rule is collected as a policy violation.
5. The final decision is the most restrictive matching decision:
   `BLOCK` takes precedence over `ASK_APPROVAL`, which takes precedence over
   `ALLOW`.
6. If no rules match, the default decision is `ALLOW`.

This mirrors `src/policy_checker.py`, which returns the full violation list for
audit and explanation generation rather than stopping at the first match.

## Adding A New Rule

1. Choose a unique `rule_id`, such as `POLICY-010`.
2. Specify the tool or tools the rule applies to.
3. Define conditions using existing check types, or add a new check type to
   `src/policy_checker.py`.
4. Add shared patterns or text helpers when the behavior must stay aligned
   across policy checks, risk classification, and label validation.
5. Set `decision`, `risk_level`, `attack_categories`, and
   `explanation_template`.
6. Add the rule to `data/policy_rules.json`.
7. Add focused coverage in `src/test_firewall.py`, `src/test_integration.py`, or
   `src/test_orchestrator.py`.
8. Run validation.

```bash
PYTHONPATH=. python3 src/label_validator.py --rules data/policy_rules.json --test
PYTHONPATH=. python3 src/test_firewall.py
PYTHONPATH=. python3 src/test_integration.py
```
