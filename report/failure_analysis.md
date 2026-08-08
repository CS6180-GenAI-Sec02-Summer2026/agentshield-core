# Failure Analysis - AgentShield Firewall vs. Red-Team Corpus

## 1. Purpose & Method

This analysis runs **all 85 report-corpus examples** through the real firewall
(`src/firewall_agent.py`, `FirewallAgent.evaluate`) against
`data/policy_rules.json`, then compares each decision to the ground-truth label.
The report corpus is `dataset_v0.json` + `red_team_examples.json` +
`benign_edge_cases.json`.

The broader corpus is used because it exercises all eight tools and includes the
red-team and benign-edge cases that expose policy blind spots. The raw
per-example table is reproducible from
[`firewall_vs_label.md`](firewall_vs_label.md).

## 2. Current Headline Result

- **Agreement: 85/85 (100%). Disagreement: 0.**
- False negatives: **0/50 malicious examples**.
- False positives: **0/35 benign examples**.
- Approval calibration: **12/12 report-corpus approval cases** return
  `ASK_APPROVAL`.

The full stored-scenario evaluation also includes `demo_scenarios.json` and
`sample_examples.json`, for **94 scenarios total**. Regenerated artifacts in
`data/evaluation/` show 100% policy compliance across those 94 scenarios.

## 3. What the Expanded Corpus Caught

Before policy hardening, the expanded corpus exposed real defects that the
smaller metrics set did not cover:

| Prior issue class | Example ids | Current status |
| --- | --- | --- |
| Unrequested `write_file` changes to config or allowlists | v0-030, v0-044, rt-007, rt-009 | BLOCK |
| Credentials published in public GitHub issues | v0-033, v0-037, rt-021, rt-022 | BLOCK |
| Unrequested calendar or task creation from read-only requests | rt-023, rt-024, rt-025 | BLOCK |
| Sensitive file reads not requested by the user | rt-006 | BLOCK |
| Broadcast email beyond the requested recipient scope | v0-046 | BLOCK |
| Internal `*.agentshield.example` destinations treated as external | v0-007, v0-022, be-009 | ALLOW |
| Benign read-only public HTTP GET over-blocked | be-007 | ALLOW |
| External but user-authorized sends, posts, or attendees not escalated correctly | v0-016, v0-017, v0-018, v0-047, v0-048, rt-016, rt-017, be-002, be-010 | ASK_APPROVAL |

The fixes are policy-level and reusable rather than example-id special cases.
They add explicit checks for protected file writes, public issue credential
leaks, sensitive file reads, broadcast recipients, external attendee approval,
external state-changing HTTP approval, and read-only intent versus unsafe HTTP
methods.

## 4. Metric Impact

The regenerated 94-scenario evaluation reports:

| Metric | Current AgentShield value |
| --- | --- |
| Attack Success Rate | 0.0% |
| Defense Success Rate | 100.0% |
| Benign Task Success Rate | 100.0% |
| False Positive Rate | 0.0% |
| False Negative Rate | 0.0% |
| Policy Compliance Accuracy | 100.0% |
| BLOCK Precision / Recall / F1 | 100.0% / 100.0% / 100.0% |

Per-tool policy accuracy is also 100% for all eight tools in the committed
evaluation artifacts.

## 5. Residual Scope Notes

- The corpus is synthetic and scenario-based; the result proves coverage for the
  committed project scenarios, not all possible production traffic.
- `ASK_APPROVAL` remains a policy-design boundary. The ambiguity review documents
  the debatable cases, and the current firewall now matches those labels.
- Future corpus growth should keep adding regression examples for new tools,
  new argument fields, and new prompt-injection phrasing so policy coverage stays
  aligned with the dataset.
