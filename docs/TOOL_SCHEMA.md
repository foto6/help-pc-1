# PC Executor tool schema

Input is one JSON object per line. `request_id` is optional; `dry_run` can override the process default for one request; `timeout_ms` optionally supplies a positive per-request deadline. Side-effecting requests may additionally carry optional top-level `execution_context_binding` using `pc_executor.execution_context_binding.v1`.

~~~json
{"request_id":"uuid","action":"windows.list","params":{},"dry_run":true,"timeout_ms":5000}
~~~

## Actions

| Action | Params | Notes |
|---|---|---|
| capabilities.get | {} | Read-only deterministic `pc_executor.capabilities.v1` snapshot with safety/runtime attestation digest. |
| action.preflight | `pc_executor.action_preflight.v1` request object | Read-only feasibility/policy check; never dispatches the requested side effect. |
| outcome.lookup | {"request_id":"...","action":"...","execution_attempt":1} | Read-only durable outcome-journal lookup; never invokes side-effect adapters. |
| screenshot.capture | {} | Base64 PNG plus capture id, dimensions, display geometry, coordinate space and SHA-256. |
| windows.list | {} | Visible top-level windows in deterministic order. |
| uia.snapshot | {"window_title":"optional"} | Read-only canonical UIA observation snapshot. |
| uia.inspect | {"query": ElementQuery} | Re-resolves and refreshes current metadata. |
| uia.invoke | {"query": ElementQuery} | Requires enabled/onscreen deterministic InvokePattern. |
| uia.focus | {"query": ElementQuery} | Deterministic focus after re-resolution. |
| uia.set_value | {"query": ElementQuery,"value":"...","sensitive":false} | Requires ValuePattern; rejects password/sensitive entry. |
| vision.target.invoke | {"target": vision.grounded_target.v1} | Frozen v1 contract; automation_id only; never coordinate input. |
| mouse.click | {"x":1,"y":2,"button":"left"} | Raw fallback; disabled by default, including dry-run. |
| keyboard.press | {"key":"enter"} | Bounded single-key input. |
| keyboard.type_text | {"text":"...","sensitive":false} | Bounded input; sensitive entry rejected. |
| clipboard.get | {} | Bounded text clipboard read. |
| clipboard.set | {"text":"...","sensitive":false} | Bounded write; sensitive entry rejected. |
| shell.run | {"argv":["git","status"],"cwd":"C:\\work"} | argv-only allowlist, protected paths, cancellation/deadline, bounded stdout/stderr. |

`ElementQuery` supports `automation_id`, `name`, `control_type`, `class_name`, and `window_title`. At least one non-empty selector is required and unknown keys are rejected.

`action.preflight` returns strict `pc_executor.action_preflight.v1` with status `ready`, `blocked`, `unsupported`, `stale_observation`, `ambiguous_target`, or `invalid_request`, the current capabilities attestation digest, effective deadline budget, fixed reason metadata and a sanitized UIA actionability summary when applicable. `ready` is not an execution guarantee. See `docs/PREFLIGHT_V1.md`.

## Optional execution context binding

For side-effecting actions only, `execution_context_binding` can bind read-only process/window/target/input/shell provenance gathered before execution. Executor re-reads only the authoritative context immediately before dispatch. A mismatch never invokes the side-effect adapter and returns blocked `pc_executor.execution_context_validation.v1` evidence in `data`. The frozen action-outcome contract remains unchanged. See `docs/EXECUTION_CONTEXT_BINDING_V1.md`.

## Result shape

~~~json
{
  "request_id":"uuid",
  "action":"uia.invoke",
  "ok":false,
  "status":"stale_target",
  "started_at":"...Z",
  "finished_at":"...Z",
  "data":{},
  "error":"UIA automation_id not found: save",
  "error_kind":"stale_target",
  "dry_run":false,
  "outcome_evidence":{
    "contract_version":"pc_executor.action_outcome.v1",
    "request_id":"uuid",
    "action":"uia.invoke",
    "effect_state":"not_started",
    "dispatch_started":true,
    "completion_observed":false,
    "reexecution_safe":true,
    "reconciliation_required":false,
    "observed_at":"...Z",
    "reason":"stale_target"
  }
}
~~~

`error_kind` is one of `transient`, `stale_target`, `ambiguous_target`, `policy_blocked`, `timeout`, `cancelled`, or `executor_failure`.

Live/dry-run side-effecting actions additionally emit strict `pc_executor.action_outcome.v1` evidence. `not_started` is duplicate-effect safe, `completed` must not be re-executed, and `unknown` requires verification/reconciliation rather than execution retry. Read-only results preserve the legacy shape and omit `outcome_evidence`. See `docs/ACTION_OUTCOME_V1.md`.

When an `OutcomeJournal` is configured, side-effect transitions are also persisted as `pc_executor.outcome_journal.record.v1`. `outcome.lookup` returns `pc_executor.outcome_journal.lookup.v1`, including `outcome`, `latest_valid_evidence`, complete matching history, integrity provenance and `replay_authorized=false`. See `docs/OUTCOME_JOURNAL_V1.md`.

## Shell result metadata

Live `shell.run` additionally returns `stdout_bytes`, `stderr_bytes`, `stdout_truncated`, `stderr_truncated`, and `output_limit_bytes`. Truncation is deterministic from the beginning of each UTF-8 byte stream.

## Screenshot metadata

Live `screenshot.capture` returns `capture_id`, `width`, `height`, `coordinate_space="physical_screen_px"`, `display_geometry`, `sha256`, byte count, MIME/encoding and base64 data.

## UIA snapshot transport

`uia.snapshot` returns both a parsed `snapshot` object and `canonical_json`. Nodes carry deterministic node ids, role/name/automation id/class, enabled/offscreen state, physical bounds, display id, window/process ids and invoke/value capability flags.
