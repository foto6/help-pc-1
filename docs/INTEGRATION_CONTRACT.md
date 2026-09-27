# Integration contract: help-pc-2 / vision-2 -> PC Executor

The upstream planner/vision component proposes intent and selectors; PC Executor owns final local policy enforcement, deterministic target re-resolution, deadlines/cancellation, and side effects.

## Recommended loop

1. Read `capabilities.get` and bind planning to its attestation digest when environment/safety compatibility matters.
2. Use `screenshot.capture`, `windows.list`, and/or read-only `uia.snapshot` to observe current state.
3. Vision/planner identifies a target.
4. Use `action.preflight` for the exact logical request before side-effect dispatch when Control needs a current feasibility gate. `ready` is not an execution guarantee.
5. When last-observed process/window/target provenance must be preserved across the preflight-to-execute gap, attach optional `pc_executor.execution_context_binding.v1` to the execution request. Executor revalidates it immediately before dispatch.
6. Prefer UIA targeting. For `vision.grounded_target.v1`, call `vision.target.invoke`; the frozen transport remains unchanged and the executor re-resolves only by non-empty UIA `automation_id`.
7. Use `uia.invoke`, `uia.focus`, or `uia.set_value` for non-Vision UIA actions when supported.
8. Re-observe after the action.
9. Generic coordinate fallback remains separately gated. `vision.target.invoke` never uses `bounds_screen` or `click_point_screen` for input.

## Observation correlation

Screenshot results include `capture_id`, width/height, display geometry, `coordinate_space="physical_screen_px"`, and SHA-256. UIA snapshots include a stable snapshot id, capture time, app/window identity, display geometry, per-node physical bounds, display id, window/process correlation and deterministic JSON.

Consumers must treat observation ids/timestamps as provenance. A later action should be based on a fresh observation when the UI can change.

## Preflight contract

`pc_executor.action_preflight.v1` returns `ready`, `blocked`, `unsupported`, `stale_observation`, `ambiguous_target`, or `invalid_request` plus the current `pc_executor.capabilities.v1` attestation digest. Preflight is side-effect-free: UIA checks use only read-only observation and shell checks use only allowlist/path validation. Control must not interpret `ready` as proof that execution later succeeded, nor as retry/replay authority. See `docs/PREFLIGHT_V1.md`.

## Execution context binding

The optional binding is carried as top-level `execution_context_binding` on an execution request. A context mismatch is checked before adapter dispatch, returns `status="blocked"`, and includes `data.execution_context_validation.reason="context_mismatch"`. Because no side-effect adapter was entered, frozen action-outcome evidence remains proven `not_started` and re-execution-safe. Once adapter dispatch begins, ordinary outcome/journal reconciliation rules apply; context validation never converts post-dispatch uncertainty into retry safety.

See `docs/EXECUTION_CONTEXT_BINDING_V1.md`.

## Failure and retry contract

Every failed action includes `error_kind`. Every side-effecting action also emits versioned `pc_executor.action_outcome.v1` evidence describing whether the effect is proven `not_started`, proven `completed`, or `unknown` and therefore requires reconciliation.

| error_kind | Meaning | Retry guidance |
|---|---|---|
| transient | runtime condition may clear | execution retry only when outcome is `not_started`; `unknown` reconciles instead |
| stale_target | selector no longer resolves | re-observe and re-ground |
| ambiguous_target | selector resolves to multiple controls | refine selector; do not guess |
| policy_blocked | safety/capability boundary | do not auto-retry around policy |
| timeout | bounded operation deadline expired | retry execution only when outcome is `not_started`; post-dispatch `unknown` reconciles |
| cancelled | caller cancelled work | do not auto-retry |
| executor_failure | unexpected adapter/runtime failure | retry only with `not_started` evidence; otherwise reconcile/diagnose |

Round-1 status compatibility is preserved: policy blocks return `status="blocked"`; unexpected executor failures return `status="error"`.

Outcome evidence changes retry authority: `not_started` only proves duplicate-effect safety and still obeys `error_kind`; `completed` must never be re-executed; `unknown` must enter verification/reconciliation and may retry observation only. A transport/process loss after side-effect dispatch must be treated as `unknown`, not as an execution retry. The exact transport is documented in `docs/ACTION_OUTCOME_V1.md`.

For transport/process loss where no final `ActionResult` arrives, use the read-only outcome journal described in `docs/OUTCOME_JOURNAL_V1.md`. Current Control Plane `27ac92f38892605cdac0ca6cdc968757b1c9cb66` can consume the lookup's top-level `outcome` through its injected `readEvidence` boundary. Journal corruption or a provisional-only record must be treated as `unknown`; the journal never authorizes replay.

## Boundary rules

- Do not send credentials, secrets, authentication codes, CAPTCHA answers, or password-field content.
- Non-actionable UIA controls are policy blocked; the executor does not silently synthesize a click.
- `shell.run` accepts argv arrays only; shell command strings are not accepted.
- `E:\manhwa` is protected regardless of dry-run/live mode.
- Coordinate fallback is disabled by default and must never be inferred from Vision target coordinates.
- Use request `timeout_ms` for caller-specific tighter deadlines; cancellation is supplied out-of-band by embedding callers through `CancellationToken`.

## Audit correlation

Preserve a stable `request_id` from planner -> executor -> telemetry. Each request emits start/finish events carrying action, dry-run state, outcome and non-sensitive result metadata. Text bodies are intentionally excluded.
