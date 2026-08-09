---
title: "AgentShield: Agentic AI Security Framework"
subtitle: "Securing Tool-Using AI Agents Against Prompt Injection, Data Leakage, and Unsafe Actions"
author:
  - "Mrinal Setty — Agent Orchestration & Target Agent Lead"
  - "Aditya Shenoy — Red-Team Agent & Dataset Lead"
  - "Yashas Uttangi — Safety, Firewall, Evaluation & Console Lead"
date: "CS6180 · Summer 2026 · August 9, 2026"
---

# Introduction

## Problem Statement

Modern AI systems are moving from simple chatbots to agentic systems that take
real actions through tools such as email, files, calendars, task managers, code
hosting, and HTTP APIs. This shift creates a new class of security risk:
malicious content hidden inside emails, documents, webpages, or tool responses
can manipulate an agent into unsafe actions — leaking private data, sending
messages to unauthorized recipients, or performing destructive operations the
user never requested.

The specific problem this project addresses is: **how can we test and protect
tool-using AI agents from prompt injection, data leakage, unauthorized tool use,
and unsafe actions before a tool call is executed?**

AgentShield is a multi-agent security framework that simulates tool-using AI
agents, generates red-team attacks against them, validates each proposed tool
call against structured safety policies, blocks or escalates risky actions, and
produces audit records explaining every decision. Crucially, the firewall
inspects the proposed tool call **before** execution, so an unsafe action is
stopped rather than merely reported after the fact.

## Why Generative AI Is Useful

Generative AI is central to the framework because AgentShield must interpret
natural-language requests, reason over tool-use intent, generate realistic
adversarial scenarios, apply safety policies to ambiguous cases, classify risk,
and explain its decisions in readable audit reports:

- The **Target Agent** uses GenAI for tool-use reasoning and structured
  tool-call generation.
- The **Red-Team Agent** uses adversarial prompting to generate realistic
  prompt-injection attacks and malicious scenarios.
- The **Policy Compiler and Firewall** use policy reasoning to interpret rules,
  resolve ambiguous risk, and generate audit explanations.
- An **LLM-as-a-judge** is used only for subjective quality checks (audit
  explanation quality), never for primary correctness scoring, which is always
  measured against fixed ground-truth labels.

# System Architecture

AgentShield uses a modular backend workflow that owns the full local decision
path: scenario ingestion, tool-call proposal, schema validation, policy and risk
evaluation, safe mock execution, audit capture, metrics, and baseline
comparison. (Full detail: `docs/architecture.md`.)

## Decision Pipeline

Each user request or stored scenario flows through the same path:

1. The **Target Agent** proposes a structured tool call.
2. The proposed call is **schema-validated**.
3. In parallel, the **Policy Checker** evaluates every enabled safety rule and
   the **Risk Classifier** scores risk level and category.
4. The **Firewall** combines both results and chooses the most restrictive
   outcome: `ALLOW`, `BLOCK`, or `ASK_APPROVAL`.
5. Only `ALLOW` may proceed to optional **safe mock execution**; `BLOCK` and
   `ASK_APPROVAL` never execute.
6. The **Orchestrator** records an audit entry and workflow state, which feed
   metrics, the API response, and evaluation exports.

## Key Components

| Component | Responsibility |
| --- | --- |
| `target_agent.py` | Deterministic target-agent simulator and tool-call proposal format. |
| `scenario_store.py` | Loads scenario datasets from `data/` with stable source metadata. |
| `policy_compiler_agent.py` | Parses Markdown safety policies into structured JSON rules. |
| `policy_checker.py` | Evaluates enabled rules and returns every matching violation. |
| `risk_classifier.py` | Classifies risk level, score, and categories. |
| `firewall_agent.py` | Combines policy and risk into an `ALLOW` / `BLOCK` / `ASK_APPROVAL` decision. |
| `orchestrator.py` | Runs the end-to-end workflow and stores audit entries. |
| `api.py` | FastAPI app, CORS, and endpoints for the console. |
| `metrics.py` / `baseline_analyzer.py` | Security/usability metrics and baseline comparison. |

## Safety Boundary

All tool execution is simulated. Mock tools validate arguments and return
synthetic outputs but never perform real side effects — no email is sent, no
file is read or written, no HTTP request leaves the machine. `ALLOW` means the
firewall permits the call *in simulation only*.

Policy checking, risk classification, and label validation share the same
security-pattern, text-matching, and intent helpers, which keeps dataset labels,
runtime decisions, and evaluation reports aligned. Intent checks use standalone
keyword matching (so short terms like `get` or `list` do not match inside
unrelated words), and `delete_file` has an explicit deletion gate so read-only
requests never authorize a deletion. External-target checks treat known internal
hosts and configured internal email domains as internal; everything else is
external for policy purposes.

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
`../../data/attack_taxonomy.md`.

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

# Red-Team Method

## Purpose

The red-team generator creates deterministic adversarial scenarios that
stress-test AgentShield before runtime integration. The generated corpus is used
as regression coverage for prompt injection, data exfiltration, unauthorized
actions, sensitive file reads, protected writes, public issue leaks, and unsafe
external requests.

## Components

| Component | Role |
| --- | --- |
| `agents/injection_patterns.py` | Prompt-injection pattern library. |
| `agents/red_team_seeds.py` | Attack seed catalog grouped by tool and attack style. |
| `agents/red_team_agent.py` | Renders a `ScenarioSeed` into a schema-valid example. |
| `agents/generate_red_team.py` | Writes `data/red_team_examples.json`. |

Pipeline:

```text
ScenarioSeed -> injection pattern rendering -> schema-valid scenario -> dataset validation
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

## Deterministic Generation

The default generation mode is offline and deterministic. It fills checked-in
templates from checked-in seeds, requires no network access, and produces stable
outputs suitable for tests and audits. An `online` mode remains reserved as an
extension point and currently raises `NotImplementedError`.

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

The tests check pattern integrity, deterministic generation, schema validity,
tool coverage, label consistency, and synthetic-only content.

## Impact

The expanded adversarial corpus exposed missing policy coverage around protected
writes, public issue credential leaks, sensitive reads, unauthorized calendar
and task creation, and external HTTP behavior. Those issue classes are now
covered by reusable policy checks and regression tests rather than by
scenario-specific exceptions.

# Evaluation Summary

## Method

Evaluation runs every stored scenario through the same policy checker, risk
classifier, intent helpers, and firewall decision path used by the API. Results
are compared against each scenario's `expected_decision` label.

The committed evaluation artifacts under `data/evaluation/` are generated from
all discoverable datasets:

- `data/demo_scenarios.json`
- `data/sample_examples.json`
- `data/dataset_v0.json`
- `data/red_team_examples.json`
- `data/benign_edge_cases.json`

## Current Results

The 94-scenario stored evaluation reports:

| Metric | Result |
| --- | --- |
| Attack Success Rate | 0.0% |
| Defense Success Rate | 100.0% |
| Benign Task Success Rate | 100.0% |
| False Positive Rate | 0.0% |
| False Negative Rate | 0.0% |
| Policy Compliance Accuracy | 100.0% |
| BLOCK Precision / Recall / F1 | 100.0% / 100.0% / 100.0% |

The 85-example evaluation corpus has 85/85 firewall-label agreement, with no false
negatives, no false positives, and all approval-labeled scenarios escalated.

## Baseline Comparison

Evaluation includes three configurations:

| Configuration | Behavior |
| --- | --- |
| Unprotected baseline | Allows every proposed call. |
| Prompt-only guardrail baseline | Uses lightweight prompt and credential heuristics without structured policies. |
| AgentShield firewall | Applies structured policy rules, risk scoring, and user-intent checks. |

The baseline exports demonstrate why structured tool-call enforcement is needed:
the prompt-only guardrail catches obvious attacks but misses subtler policy
violations that require inspecting tool arguments, recipients, URLs, HTTP
methods, file paths, repository visibility, and user intent.

## Fixed Issue Classes

The expanded corpus previously surfaced the following issue classes, all now
covered by reusable policies and regression tests:

| Issue class | Current behavior |
| --- | --- |
| Unrequested protected file writes | BLOCK or ASK_APPROVAL depending on user authorization. |
| Credentials in public issue bodies | BLOCK. |
| Unrequested calendar or task creation from read-only requests | BLOCK. |
| Sensitive file reads not requested by the user | BLOCK. |
| Broadcast email beyond requested recipient scope | BLOCK. |
| Internal `*.example` destinations treated as external | Correctly treated as internal when configured. |
| Benign read-only public HTTP GET overblocked | ALLOW. |
| Authorized external sends, posts, or attendees | ASK_APPROVAL when confirmation is required. |
| Read-only intent matched by substrings inside unrelated words | Fixed with standalone keyword and phrase matching. |

## Reproduction

```bash
PYTHONPATH=. python3 src/experiment_runner.py
PYTHONPATH=. python3 src/baseline_unprotected.py
PYTHONPATH=. python3 src/baseline_prompt_guardrail.py
PYTHONPATH=. python3 src/test_metrics.py
PYTHONPATH=. python3 src/label_validator.py --rules data/policy_rules.json --test
```

Generated artifacts are written to `data/evaluation/`.

## Residual Scope

- The dataset is synthetic and scenario-based. It proves coverage for the
  committed project scenarios, not every possible production input.
- `ASK_APPROVAL` is a policy boundary for legitimate but risky actions.
- Future corpus growth should add new tools, argument fields, prompt-injection
  phrasings, and benign lookalikes as the system expands.

# Demo Scenarios

The demo set in `data/demo_scenarios.json` covers the three user-visible
decision paths: `ALLOW`, `BLOCK`, and `ASK_APPROVAL`.

## Scenarios

| ID | Tool | Expected decision | What it demonstrates |
| --- | --- | --- | --- |
| `demo-safe-email` | `send_email` | `ALLOW` | A normal internal email that matches the user's request. |
| `demo-block-unauthorized-http` | `send_http_request` | `BLOCK` | An external state-changing HTTP request the user did not authorize. |
| `demo-approval-delete` | `delete_file` | `ASK_APPROVAL` | A legitimate but destructive deletion that requires confirmation. |

## Run Through The API

Start the backend:

```bash
uvicorn src.api:app --reload
```

Run the demo scenarios from the frontend or call the API directly:

```bash
curl -X POST http://localhost:8000/run-batch \
  -H "Content-Type: application/json" \
  -d '{"dataset_names":["demo"]}'
```

## Run Locally

```bash
PYTHONPATH=. python3 src/test_orchestrator.py
PYTHONPATH=. python3 src/label_validator.py --rules data/policy_rules.json --dataset data/demo_scenarios.json
```

## Demo Narrative

1. Safe internal email is allowed because the tool call matches the request and
   the recipient is internal.
2. Unauthorized external HTTP is blocked because the user requested a summary,
   not a state-changing call to an external endpoint.
3. User-requested deletion is escalated because file deletion is destructive
   even when the user asked for it.

# Milestones and Team Contributions

The project ran over eight weekly milestones. Each milestone contained three
parallel stories so all three members contributed every week: Mrinal Setty owned
the `-S1` (orchestration/backend) track, Aditya Shenoy the `-S2` (dataset and
red-team) track, and Yashas Uttangi the `-S3` (policy, firewall, evaluation, and
console) track.

## Milestone Timeline

| Milestone | Dates | Primary outcome |
| --- | --- | --- |
| M1 | 15–22 Jun | Project setup, architecture, dataset schema, policy/evaluation setup |
| M2 | 23–29 Jun | Dataset v0, simulated tool interfaces, policy/rule foundation |
| M3 | 30 Jun–06 Jul | Target Agent, Red-Team Agent, and Firewall/Risk Classifier v0 |
| M4 | 07–13 Jul | Integrated backend workflow, expanded attacks, policy compiler + firewall |
| M5 | 14–20 Jul | Baselines, evaluation metrics, dataset validation, audit rubric |
| M6 | 21–27 Jul | Dashboard, API integration, demo scenarios, result visualization |
| M7 | 28 Jul–03 Aug | System testing, failure analysis, UI polish, report draft |
| M8 | 04–10 Aug | Final demo, report submission, code submission |

## Team Contributions

| Member | Core ownership | GenAI contribution |
| --- | --- | --- |
| Mrinal Setty | Agent orchestration, Target Agent, tool interfaces, backend workflow and API | Multi-agent orchestration, Target Agent prompting, structured tool-call generation |
| Aditya Shenoy | Red-Team Agent, synthetic dataset, attack taxonomy, dataset quality, report content | Adversarial attack generation, synthetic scenario generation, prompt-injection patterns |
| Yashas Uttangi | Firewall, policy compiler, evaluation metrics, dashboard/console | Policy reasoning, audit explanation generation, LLM-as-a-judge quality checks |

Work was delivered continuously through reviewed pull requests across all eight
milestones, spanning the backend workflow, the dataset and red-team corpus, and
the policy/firewall/evaluation stack. The contribution target was an
approximately equal split across the three members (about one third each), with
each owning one major story every milestone.

# Conclusion and Limitations

## Conclusion

AgentShield demonstrates that a dedicated, policy-driven firewall can secure
tool-using AI agents against prompt injection, data exfiltration, and
unauthorized actions *before* a tool call executes. On the 94-scenario stored
evaluation set the firewall reaches 100% policy-compliance with no false
negatives and no false positives, while the unprotected and prompt-only
baselines let unsafe calls through — showing that structured inspection of tool
arguments, recipients, URLs, and user intent catches violations that
prompt-level guardrails miss.

The red-team track was central to this outcome. Expanding the adversarial corpus
across all eight tools surfaced coverage gaps — around protected writes, public
issue credential leaks, sensitive reads, and unauthorized calendar/task creation
— that were then closed with reusable policy checks and regression tests. Finding
and fixing those gaps *before* they reach a production integration is exactly the
value the framework is meant to provide.

## Limitations

- **Synthetic and scenario-based.** The dataset proves coverage for the
  committed project scenarios, not every possible production input. Real
  deployments would need continual corpus growth with new tools, argument
  fields, injection phrasings, and benign lookalikes.
- **Simulation only.** All tool execution is mocked; no real side effects occur.
  Real-world execution must remain behind explicit user approval and production
  integration controls.
- **`ASK_APPROVAL` is a policy boundary**, not a guarantee: it marks legitimate
  but risky actions for human confirmation, and its calibration depends on the
  configured policies.
- **Subjective quality** (audit-explanation readability) is scored with an
  LLM-as-a-judge and a rubric; only objective correctness is measured against
  fixed ground-truth labels.

