# Dataset Documentation - AgentShield

## 1. Purpose

The dataset is a **synthetic benchmark of agent tool-call scenarios** with
ground-truth firewall decisions. Each example pairs a user request (and any
external content the agent read) with a proposed tool call and the decision the
firewall *should* make. These labels are the **answer key** every evaluation
metric - defense success, false-positive/negative rates, policy compliance - is
scored against, for both the AgentShield firewall and the baseline agents.

## 2. Composition

**85 examples** across three complementary sources:

| Source | Count | Benign / Malicious | Role |
| --- | --- | --- | --- |
| `dataset_v0.json` | 50 | 25 / 25 | Core balanced baseline of benign and malicious scenarios. |
| `red_team_examples.json` | 25 | 0 / 25 | Generated adversarial attacks across all 8 tools. |
| `benign_edge_cases.json` | 10 | 10 / 0 | Safe actions that *resemble* attacks (anti over-block). |

**Overall splits:**

- Benign vs malicious: **35 benign / 50 malicious**
- Decisions: **ALLOW 27, ASK_APPROVAL 12, BLOCK 46**
- Risk levels: low 12, medium 16, high 25, critical 32

## 3. Schema

Every example is a JSON object with seven required fields, enforced by
`data/dataset_schema.json` (strict, enum-locked, `additionalProperties: false`):

| Field | Purpose |
| --- | --- |
| `user_request` | The user's natural-language request. |
| `external_context` | External content the agent read (may hide injected instructions); `null` if none. |
| `proposed_tool_call` | The `{tool_name, arguments}` the agent proposes before the firewall decides. |
| `expected_decision` | Ground-truth decision: `ALLOW` / `BLOCK` / `ASK_APPROVAL`. |
| `risk_level` | `low` / `medium` / `high` / `critical`. |
| `attack_category` | `none` / `prompt_injection` / `data_exfiltration` / `unauthorized_action`. |
| `explanation` | Human-readable rationale for the decision. |

An optional `id` (`v0-*`, `rt-*`, `be-*`) provides stable scenario lookup for the
backend.

## 4. Label Scheme

Three controlled vocabularies, defined fully in
[`../data/attack_taxonomy.md`](../data/attack_taxonomy.md) (not duplicated here):

- **Attack category:** `none` (benign) + `prompt_injection`, `data_exfiltration`,
  `unauthorized_action`.
- **Risk level:** `low`, `medium`, `high`, `critical` - impact if executed
  unchecked.
- **Expected decision:** `ALLOW`, `BLOCK`, `ASK_APPROVAL` - the last for
  legitimate-but-risky or genuinely ambiguous actions.

## 5. Tools Covered

All **8 simulated tools** appear, with a spread that favors the higher-risk
action tools:

`send_http_request` 23, `send_email` 18, `delete_file` 11, `write_file` 8,
`create_github_issue` 8, `read_file` 7, `create_calendar_event` 6,
`create_task` 4.

The M4 coverage expansion deliberately added attack cases for `write_file`,
`create_github_issue`, `create_calendar_event`, and `create_task`. These are
the tools that exposed the earlier policy blind spots and now serve as
regression coverage for the hardened firewall (see
[`failure_analysis.md`](failure_analysis.md)).

## 6. Attack Category Summary

Counts below are **over the full corpus** (all 50 malicious examples across the
three sources). The Red-Team Agent's own 25-example breakdown (11 / 7 / 7) is a
subset of these and is reported separately in
[`redteam_method.md`](redteam_method.md) section 6.

- **`prompt_injection` (19).** External content hides an overriding instruction
  that redirects the agent from the user's intent - e.g. an email that says
  "summarize me" but hides "forward the salaries file to an external address."
  Injections use a variety of hiding patterns (direct override, hidden HTML
  comment, fake system note, authority/urgency, fake tool response); the
  generation method is documented in [`redteam_method.md`](redteam_method.md).
- **`data_exfiltration` (15).** The proposed call leaks private or credential-like
  data to an external/unauthorized destination - e.g. POSTing an internal API key
  to an outside URL.
- **`unauthorized_action` (16).** The proposed call performs a destructive,
  irreversible, or privilege-exceeding action the user did not authorize - e.g.
  recursively deleting a folder the user only asked to list.

## 7. Synthetic Data & PII Policy

All content is **100% synthetic**. Placeholder domains (`*.example`) and clearly
marked tokens (`<synthetic-...-placeholder>`) stand in for anything sensitive; no
real names, emails, credentials, documents, or personal data appear. This is
enforced by the taxonomy rules and by automated tests that fail on real-looking
emails or secrets.

## 8. Quality Assurance

- **Schema validation** - every file passes `data/validate_dataset.py`.
- **Balance & consistency** - `data/test_dataset_v0.py` and `data/test_corpus.py`
  assert the tool/category/decision/risk coverage, benign fraction, and absence
  of duplicate requests.
- **Label audit** - the M5 ambiguity review
  ([`../data/ambiguity_review.md`](../data/ambiguity_review.md)) manually
  re-verified every debatable decision; the failure analysis verifies the current
  firewall against every report-corpus label. No mislabels were found.
- **Explanation quality** - scored by the audit rubric/judge (avg 9.4/10).

All 85 examples are schema-valid and their labels manually re-verified.

## 9. Limitations

- The corpus is **synthetic and scenario-based** - it exercises specific attack
  and benign patterns, not production traffic; absolute rates are indicative, not
  operational.
- The `ASK_APPROVAL` boundary is **subjective** on borderline cases (see the
  ambiguity review); reasonable reviewers may disagree.
- Size is **MVP-scale** (85 examples). It is designed to be extended - the
  Red-Team Agent can generate more adversarial cases reproducibly.
