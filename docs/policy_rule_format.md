# AgentShield Policy Rule Format

This document explains the structured JSON format used by AgentShield's policy rules. These rules define the conditions under which tool calls are blocked, require approval, or are allowed.

## File Location

Policy rules are stored in `data/policy_rules.json`.

## Schema Overview

The top-level structure:

```json
{
  "schema_version": "0.1",
  "default_decision": "ALLOW",
  "rules": [ ... ]
}
```

If no rule matches a given tool call, the `default_decision` applies (currently ALLOW).

## Rule Structure

Each rule in the `rules` array has the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | string | Unique identifier, e.g. `POLICY-001` |
| `name` | string | Human-readable rule name |
| `description` | string | What the rule does |
| `priority` | integer | Evaluation order. Lower number = checked first. Priority 1 rules are critical security blocks, priority 2 are approval-required cases |
| `enabled` | boolean | Whether the rule is active. Set to `false` to disable without deleting |
| `tools` | string[] | Which tools this rule applies to. Must be one or more of the 8 supported tools |
| `conditions` | object | The condition block that determines if the rule fires (see below) |
| `decision` | string | `BLOCK`, `ASK_APPROVAL`, or `ALLOW` |
| `risk_level` | string | `low`, `medium`, `high`, or `critical` |
| `attack_categories` | string[] | Which attack types this rule catches, e.g. `prompt_injection`, `data_exfiltration`, `unauthorized_action` |
| `explanation_template` | string | Template for the audit explanation. Can reference argument values with `{arguments.field}` syntax |

## Supported Tools

Rules can target any of these 8 simulated tools:

`send_email`, `read_file`, `write_file`, `delete_file`, `create_calendar_event`, `create_task`, `create_github_issue`, `send_http_request`

## Conditions Block

The conditions block defines when a rule fires:

```json
{
  "operator": "AND",
  "checks": [ ... ]
}
```

**Operators:**

| Operator | Behavior |
|----------|----------|
| `AND` | All checks must pass for the rule to fire |
| `OR` | At least one check must pass |
| `ALWAYS` | Rule fires whenever the tool matches, regardless of checks |

## Check Types

Each check in the `checks` array has a `field`, a `check` type, and optionally a `value` or `patterns` list.

| Check Type | What It Does | Used By |
|------------|-------------|---------|
| `equals` | Exact match on a field value | POLICY-002, POLICY-007 |
| `contains_file_content` | Detects file data references in arguments | POLICY-001 |
| `is_external_recipient` | Checks if email recipient is outside the organization | POLICY-001 |
| `contains_secret_pattern` | Matches credential patterns (API keys, passwords, tokens) against a patterns list | POLICY-003 |
| `is_external_target` | Checks if target URL or email is external | POLICY-003 |
| `contradicts_user_intent` | Detects if the proposed tool call doesn't match the user's original request | POLICY-004, POLICY-009 |
| `contains_instruction_pattern` | Matches prompt injection phrases in external context against a patterns list | POLICY-004 |
| `not_in_user_request` | Checks if a URL was not mentioned by the user | POLICY-005 |
| `is_external_url` | Checks if a URL points to an external domain | POLICY-005 |
| `contains_sensitive_content` | Detects financial, credential, or proprietary content | POLICY-006 |
| `has_external_participant_or_public` | Checks for external participants or public visibility | POLICY-006 |
| `contains_internal_reference` | Detects internal IPs, private URLs, or system references | POLICY-007 |
| `count_greater_than` | Checks if a list field has more items than a threshold | POLICY-008 |
| `greater_than` | Numeric comparison on a field value | POLICY-008 |

## Field Paths

Fields use dot notation to access nested values in the dataset example:

- `arguments.to` — the `to` field inside `proposed_tool_call.arguments`
- `arguments.body` — the email body or request body
- `arguments.url` — the target URL

Pipe-separated alternatives are supported: `arguments.body|arguments.title` checks the body first, falls back to title.

## Evaluation Logic

1. Rules are sorted by `priority` (lowest first).
2. For each rule, check if the example's `tool_name` is in the rule's `tools` list.
3. If yes, evaluate the `conditions` block.
4. The first rule whose conditions match determines the decision.
5. If no rule matches, the `default_decision` (ALLOW) applies.

## Adding a New Rule

To add a new rule:

1. Choose a unique `rule_id` (e.g. `POLICY-009`).
2. Specify which `tools` it applies to.
3. Define the `conditions` using existing check types or request a new one.
4. Set the `decision` and `risk_level`.
5. Add it to the `rules` array in `data/policy_rules.json`.
6. Add a corresponding test case in `src/label_validator.py` under `TEST_CASES`.
7. Run `python3 src/label_validator.py --rules data/policy_rules.json --test` to verify.

## Validation

Use the label validator to check dataset labels against these rules:

```bash
# Run built-in tests
python3 src/label_validator.py --rules data/policy_rules.json --test

# Validate a dataset file
python3 src/label_validator.py --rules data/policy_rules.json --dataset data/dataset.json
```
