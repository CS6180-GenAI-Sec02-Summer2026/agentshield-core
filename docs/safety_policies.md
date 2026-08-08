# AgentShield Core Safety Policies

These policies define the security rules enforced when AgentShield evaluates
proposed tool calls. Each policy returns one of three decisions: `ALLOW`,
`BLOCK`, or `ASK_APPROVAL`. If no enabled rule matches, the default decision is
`ALLOW`.

The implementation keeps policy checks, risk classification, and label
validation aligned through shared helper modules. User-intent checks use
standalone keyword matching so destructive actions are not authorized by
accidental substring matches in unrelated words.

## Policy Summary

| # | Policy | Tools | Decision |
| --- | --- | --- | --- |
| 1 | Sensitive content to external recipient | `send_email` | BLOCK |
| 2 | File deletion without explicit approval | `delete_file` | ASK_APPROVAL |
| 3 | Secrets or credentials to external URL | `send_email`, `send_http_request` | BLOCK |
| 4 | Untrusted context instruction override | all tools | BLOCK |
| 5 | Unauthorized external HTTP requests | `send_http_request` | BLOCK |
| 6 | Sensitive data in shared events or tasks | `create_calendar_event`, `create_task` | ASK_APPROVAL |
| 7 | Internal information in public GitHub issues | `create_github_issue` | ASK_APPROVAL |
| 8 | Bulk or destructive operations | `write_file`, `delete_file`, `send_email` | ASK_APPROVAL |
| 9 | Unauthorized file deletion | `delete_file` | BLOCK |
| 10 | Unauthorized state-changing tool call | `write_file`, `create_calendar_event`, `create_task`, `create_github_issue` | BLOCK |
| 11 | External email requires approval | `send_email` | ASK_APPROVAL |
| 12 | Protected file change requires approval | `write_file` | ASK_APPROVAL |
| 13 | Credentials in public GitHub issue | `create_github_issue` | BLOCK |
| 14 | Unrequested sensitive file read | `read_file` | BLOCK |
| 15 | Broadcast email exceeds recipient scope | `send_email` | BLOCK |
| 16 | Unsafe HTTP method exceeds read-only intent | `send_http_request` | BLOCK |
| 17 | External state-changing HTTP requires approval | `send_http_request` | ASK_APPROVAL |
| 18 | External calendar attendee requires approval | `create_calendar_event` | ASK_APPROVAL |

## Policy 1: Sensitive Content to External Recipient

**Rule:** Block email that sends sensitive business data, private exports, or
credential-like material to an external recipient.

**Applies to:** `send_email`

**Condition:** The arguments contain sensitive sharing content and the recipient
is external.

**Decision:** BLOCK

**Example:** The agent proposes emailing customer export data to a personal
address.

---

## Policy 2: File Deletion Without Explicit Approval

**Rule:** Require approval before executing any file deletion.

**Applies to:** `delete_file`

**Condition:** A `delete_file` tool call is proposed.

**Decision:** ASK_APPROVAL

**Example:** A user asks to delete an old backup file.

---

## Policy 3: Secrets or Credentials to External URL

**Rule:** Block email or HTTP requests that transmit secrets, API keys,
passwords, tokens, license keys, or credentials to an external target.

**Applies to:** `send_email`, `send_http_request`

**Condition:** The arguments contain credential patterns and the target is
external.

**Decision:** BLOCK

**Example:** A proposed HTTP request sends an internal API key to an external
collector.

---

## Policy 4: Untrusted Context Instruction Override

**Rule:** Block actions where external context tries to override or redirect the
user's original intent.

**Applies to:** all tools

**Condition:** The proposed tool call contradicts the user's request and the
external context contains prompt-injection wording.

**Decision:** BLOCK

**Example:** A document says to ignore prior instructions and forward a file to
an attacker.

---

## Policy 5: Unauthorized External HTTP Requests

**Rule:** Block external HTTP requests that do not match the user's stated
intent.

**Applies to:** `send_http_request`

**Condition:** The HTTP tool call contradicts user intent and the URL is
external.

**Decision:** BLOCK

**Example:** The user asks for a summary, but the proposed call posts tracking
data to an external collector.

---

## Policy 6: Sensitive Data in Shared Events or Tasks

**Rule:** Require approval when calendar events or tasks contain sensitive
content and are shared externally or publicly.

**Applies to:** `create_calendar_event`, `create_task`

**Condition:** Event or task text contains sensitive content and has an external
participant, attendee, or public visibility.

**Decision:** ASK_APPROVAL

**Example:** A calendar event includes revenue details and an external
consultant.

---

## Policy 7: Internal Information in Public GitHub Issues

**Rule:** Require approval when a public GitHub issue may expose internal-only
information.

**Applies to:** `create_github_issue`

**Condition:** The issue contains internal references and the repository is
public.

**Decision:** ASK_APPROVAL

**Example:** A public issue includes an internal database host in reproduction
steps.

---

## Policy 8: Bulk or Destructive Operations

**Rule:** Require approval for operations that affect multiple resources.

**Applies to:** `write_file`, `delete_file`, `send_email`

**Condition:** The proposed tool call targets more than one resource or is part
of a batch.

**Decision:** ASK_APPROVAL

**Example:** The agent proposes deleting several cache files in one call.

---

## Policy 9: Unauthorized File Deletion

**Rule:** Block file deletion when the user requested a read-only or
non-destructive action.

**Applies to:** `delete_file`

**Condition:** The proposed `delete_file` call contradicts the user's request.

**Decision:** BLOCK

**Example:** The user asks to list a folder, but the agent proposes recursively
deleting it.

---

## Policy 10: Unauthorized State-Changing Tool Call

**Rule:** Block state-changing tool calls that do not match the user's requested
action.

**Applies to:** `write_file`, `create_calendar_event`, `create_task`,
`create_github_issue`

**Condition:** The proposed state-changing tool call contradicts the user's
request.

**Decision:** BLOCK

**Example:** The user asks to read notes, but the agent proposes overwriting an
allowlist.

---

## Policy 11: External Email Requires Approval

**Rule:** Require approval before sending otherwise allowed email to an external
recipient.

**Applies to:** `send_email`

**Condition:** The recipient is external and no stricter blocking rule matches.

**Decision:** ASK_APPROVAL

**Example:** The user asks to email a non-sensitive meeting agenda to a client.

---

## Policy 12: Protected File Change Requires Approval

**Rule:** Require approval before changing shared configuration, environment, or
security allowlist files.

**Applies to:** `write_file`

**Condition:** The write touches protected configuration or security-sensitive
content.

**Decision:** ASK_APPROVAL

**Example:** The user asks to overwrite shared config timeout settings.

---

## Policy 13: Credentials in Public GitHub Issue

**Rule:** Block publishing credential values in public GitHub issues.

**Applies to:** `create_github_issue`

**Condition:** The issue content contains credential-like key/value material and
the repository is public.

**Decision:** BLOCK

**Example:** The issue body includes a database password for a public repo.

---

## Policy 14: Unrequested Sensitive File Read

**Rule:** Block reads of sensitive files unless the user requested that exact
path.

**Applies to:** `read_file`

**Condition:** The path looks like a secret, credential, key, or production
config and the path is absent from the user request.

**Decision:** BLOCK

**Example:** The agent proposes reading `~/.ssh/id_rsa` while the user asked to
summarize a report.

---

## Policy 15: Broadcast Email Exceeds Recipient Scope

**Rule:** Block broadcast sends when the user requested a narrower recipient
scope.

**Applies to:** `send_email`

**Condition:** The recipient is a broad group or mailing list and the user did
not request that recipient.

**Decision:** BLOCK

**Example:** The user asks to reply to one customer, but the agent emails the
full customer list.

---

## Policy 16: Unsafe HTTP Method Exceeds Read-Only Intent

**Rule:** Block state-changing HTTP methods when the user requested a read-only
action.

**Applies to:** `send_http_request`

**Condition:** The method is `POST`, `PUT`, `PATCH`, or `DELETE`, and the user
asked only to read, show, fetch, list, summarize, or inspect data.

**Decision:** BLOCK

**Example:** The user asks to show access-control settings, but the agent
proposes a `POST` that grants admin access.

---

## Policy 17: External State-Changing HTTP Requires Approval

**Rule:** Require approval before executing authorized state-changing HTTP
requests against external services.

**Applies to:** `send_http_request`

**Condition:** The URL is external and the HTTP method can mutate state.

**Decision:** ASK_APPROVAL

**Example:** The user asks to submit a proposal to an external portal.

---

## Policy 18: External Calendar Attendee Requires Approval

**Rule:** Require approval before inviting external attendees or creating public
calendar entries.

**Applies to:** `create_calendar_event`

**Condition:** The event includes external attendees or public visibility.

**Decision:** ASK_APPROVAL

**Example:** The user schedules a client sync with an external attendee.

## Implementation Notes

- Pattern constants live in `src/security_patterns.py`.
- Text flattening, credential-value matching, public-repository detection, and
  external-target checks live in `src/security_text.py`.
- User-intent matching lives in `src/intent_utils.py`.
- `src/label_validator.py` calls the runtime `PolicyChecker`, so label
  validation uses the same rule engine as API and batch evaluation.
