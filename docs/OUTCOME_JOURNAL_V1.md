# Durable action outcome journal v1

PC Executor keeps `pc_executor.action_outcome.v1` unchanged. This journal is a separate append-only persistence layer for those evidence records.

Contracts:

- record: `pc_executor.outcome_journal.record.v1`
- lookup: `pc_executor.outcome_journal.lookup.v1`
- embedded evidence: frozen `pc_executor.action_outcome.v1`

The journal exists for one recovery case: a caller may lose the process or transport after side-effect dispatch and therefore never receive the final `ActionResult`. The journal is read-only from the reconciler's perspective and never grants permission to execute an action.

## Durable transition record

Each newline-terminated JSON record contains:

- global contiguous `journal_sequence`;
- `request_id` and `action`;
- stable `execution_id` and positive `execution_attempt`;
- transition `dispatch_started` or `terminal`;
- exact embedded `pc_executor.action_outcome.v1`;
- previous-record SHA-256 plus the record's own SHA-256;
- UTC `recorded_at`.

A live side-effect attempt writes and `fsync`s provisional `unknown/dispatch_started` evidence before the input/UIA/shell adapter is called. A terminal record is appended after a completed, proven-not-started, or resolved-unknown result is available.

Each append is one canonical JSON line written with append semantics, flushed with `fsync`, and serialized per journal path inside the process. Records are never rewritten in normal operation.

## Recovery semantics

Lookup returns the last valid matching record, complete matching history, hash/integrity provenance, and a Control-compatible top-level `outcome`:

| latest durable evidence | lookup outcome |
| --- | --- |
| `completed` | `succeeded` |
| `unknown` | `unknown` |
| `not_started` | `not_dispatched` |
| `not_started/policy_blocked` | `blocked` |
| no record | `unknown` |
| any detected corruption after the safe prefix | `unknown` |

Every lookup includes `replay_authorized=false`. This journal is evidence, not an execution-authority service. In particular, an `unknown` record cannot become `reexecution_safe`; a later attempt using the same request id is blocked until external reconciliation establishes a new logical request.

A request id is bound to one action. Reuse with a conflicting action fails closed. An exact duplicate terminal append for the same execution correlation is idempotent; conflicting terminal evidence is rejected.

## Corruption and truncated tails

Scanning is strict and stops at the first invalid record. It validates version, exact fields, embedded action-outcome v1, contiguous sequence numbers, the SHA-256 chain, record hash, request/action identity and transition semantics.

A final record without a newline is reported as `truncated_tail`. Invalid newline-terminated tail JSON/version/hash is reported as `malformed_tail`; corruption before the last line is `malformed_record`.

Lookup still returns the last valid record and safe-prefix byte offset for provenance, but its effective `outcome` is forced to `unknown`. The writer refuses new attempts while corruption is present. There is no silent truncation, auto-repair, or silent promotion to completed.

## Read-only reconciliation API

Embedded callers can use:

```python
journal.lookup(
    request_id="action-id",
    action="vision.target.invoke",
    execution_attempt=1,
).to_dict()
```

or `journal.read_evidence({...})`, which accepts the snake_case request shape used by the current PC Control adapter.

The JSONL executor additionally exposes read-only:

```json
{
  "action": "outcome.lookup",
  "params": {
    "request_id": "action-id",
    "action": "vision.target.invoke",
    "execution_attempt": 1
  }
}
```

`outcome.lookup` never calls UI Automation, keyboard/mouse, clipboard, screenshot, window, or shell adapters.

For live CLI execution, `pc-executor --live` enables the platform-default durable journal. `--outcome-journal PATH` selects an explicit file. Dry-run CLI mode does not create a journal unless a path is explicitly supplied.

## Privacy boundary

Journal records contain only correlation ids, action name, fixed state/reason fields, booleans, timestamps and hashes. They never contain:

- typed text;
- clipboard or UIA value bodies;
- shell stdout/stderr;
- credentials, authentication codes or CAPTCHA answers;
- Vision target coordinates or raw mouse coordinates;
- screenshots.

Blocked sensitive-input attempts can record only their non-sensitive `not_started/policy_blocked` outcome evidence.

## Cross-repo fixture corpus

`tests/fixtures/outcome_journal_v1/` contains canonical JSONL and lookup fixtures for:

- completed;
- provisional unknown;
- not-started;
- valid prefix plus truncated tail.

`manifest.json` hashes every transport file and records consumer compatibility with:

`foto6/help-pc-2 agent/pc-control-plane @ 27ac92f38892605cdac0ca6cdc968757b1c9cb66`

`manifest.sha256` hashes the manifest itself. The manifest also pins the pre-existing frozen `action_outcome_v1` fixture hashes so journal work cannot silently change that contract.
