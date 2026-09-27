# PC Executor action outcome evidence v1

Contract version: `pc_executor.action_outcome.v1`.

This transport-neutral record describes what the Executor can prove about a side-effecting action attempt. It exists so a caller can recover from timeout, cancellation, transport loss, or process interruption without blindly executing the action again.

The record is emitted as `ActionResult.outcome_evidence` for side-effecting actions and as an audit record at the live dispatch boundary.

## Side-effecting actions

Version 1 covers:

- `vision.target.invoke`
- `uia.invoke`, `uia.focus`, `uia.set_value`
- `mouse.click`
- `keyboard.press`, `keyboard.type_text`
- `clipboard.set`
- `shell.run`

Read-only actions do not emit this record.

## States

| effect_state | Meaning | reexecution_safe | reconciliation_required |
|---|---|---:|---:|
| `not_started` | Executor has evidence that the effect did not occur. | true | false |
| `completed` | The side-effect adapter returned success and completion was observed. | false | false |
| `unknown` | Dispatch began, but no authoritative completion result was observed. The effect may or may not have happened. | false | true |

`reexecution_safe` only describes duplicate-side-effect risk. It does not override the existing error policy. For example, a stale target can be `not_started` while still requiring re-observation/re-grounding instead of replaying the same selector.

A completed action must not be executed again merely because downstream verification is stale. An unknown action must enter verification/reconciliation; it must not be automatically re-executed.

## Shape

```json
{
  "contract_version": "pc_executor.action_outcome.v1",
  "request_id": "action-1",
  "action": "vision.target.invoke",
  "effect_state": "completed",
  "dispatch_started": true,
  "completion_observed": true,
  "reexecution_safe": false,
  "reconciliation_required": false,
  "observed_at": "2026-09-27T08:00:00.000Z",
  "reason": "completed"
}
```

Validation is strict: unknown versions, extra/missing fields, non-boolean flags, unsupported actions/reasons, and inconsistent state/flag combinations fail closed.

## Dispatch evidence and crash recovery

Immediately before a live side-effect adapter call, Executor emits an `effect_dispatch` audit event containing the same v1 record with:

- `effect_state="unknown"`
- `dispatch_started=true`
- `completion_observed=false`
- `reexecution_safe=false`
- `reconciliation_required=true`
- `reason="dispatch_started"`

If the adapter returns successfully, the final ActionResult and finish audit event replace uncertainty with `completed`. Structured pre-effect failures such as `stale_target`, `ambiguous_target`, or `policy_blocked` finalize as `not_started`.

Timeout, cancellation, transient failure, or unexpected executor failure after dispatch finalize as `unknown`. A process-level interruption can leave only the durable provisional dispatch audit record; that record is intentionally conservative and requires reconciliation.

## Downstream Control Plane rule

A Control Plane consuming this contract should keep execution retry and verification retry separate:

- `not_started`: execution retry may be considered only if the existing error classification/policy permits it.
- `completed`: never execute the action again; continue post-action verification or finish.
- `unknown`: move to verification/reconciliation and retry observation only. Do not call the side-effect action again unless an explicit reconciliation policy later proves it did not happen.

Transport loss after the Control Plane has dispatched a side-effecting request but before it receives any final Executor result must be treated equivalently to `unknown`.

## Privacy

Outcome evidence never stores typed text, clipboard values, UIA values, shell stdout/stderr, credentials, CAPTCHA data, or target coordinates. It carries only correlation, state, fixed reason codes, booleans, and timestamps.


## Canonical conformance corpus

Downstream consumers can copy or hash-check these fixtures from this exact Executor head:

- `tests/fixtures/action_outcome_v1_not_started.json`
- `tests/fixtures/action_outcome_v1.json` (`completed`)
- `tests/fixtures/action_outcome_v1_unknown.json`

Consumers should parse each record strictly and reject unknown versions/fields or inconsistent flags before changing orchestration state.
