# PC Executor architecture

PC Executor is a policy-enforcing facade around replaceable Windows runtime adapters. The Round-2 runtime keeps the Round-1 dry-run and `vision.grounded_target.v1` behavior while adding deterministic re-resolution, bounded operations, richer observation transport, replay fakes, and structured failures.

## Runtime boundaries

1. `ScreenshotProvider` captures PNG bytes. The executor adds a digest-based capture id, pixel dimensions, physical-screen coordinate-space declaration, display geometry, and SHA-256.
2. `WindowEnumerator` returns visible top-level windows in deterministic order.
3. `AccessibilityAdapter` owns UI Automation inspection, snapshot, focus, invoke, and value setting.
4. `InputAdapter` owns keyboard, clipboard, and the separately gated raw coordinate fallback.
5. `SafeShellAdapter` owns argv-only subprocess execution, protected-path checks, timeout/cancellation, and bounded output.
6. `CancellationToken` plus the bounded runner wrap UIA, screenshot, window, and input operations.

Windows-specific dependencies remain lazily imported so policy, replay, request-validation, and integration tests run on non-Windows hosts.

## UIA resolution and actionability

Every UIA action re-resolves the selector from the current tree. Resolution walks the tree in deterministic breadth-first order, applies exact case-insensitive selector matching, then sorts matches by stable accessibility metadata. Zero matches are `stale_target`; multiple matches are `ambiguous_target`.

`uia.invoke` requires an enabled, onscreen control exposing `InvokePattern`. There is no implicit `Control.Click` fallback. `uia.set_value` requires `ValuePattern` and still rejects password/sensitive entry. Bounds, display id, process/window metadata, class, offscreen state and capability flags are refreshed after resolution.

## Observation snapshots

`uia.snapshot` is read-only. It returns:
- `snapshot_id` derived from canonical snapshot content;
- UTC `captured_at`;
- app/window identity;
- display geometry;
- deterministic node ids and sorted node transport;
- role/name/automation id/class/state;
- physical screen bounds and display/window/process correlation;
- invoke/value capability flags;
- `coordinate_space = physical_screen_px`.

`UIObservationSnapshot.to_json()` uses sorted keys and compact separators for deterministic replay transport. `ReplayUIAAdapter`, `ReplayScreenshotProvider`, and `ReplayInputAdapter` allow side-effect-free integration fixtures.

## Operation control

`ActionRequest.timeout_ms` optionally narrows the executor's default operation deadline. UIA resolution/invoke, screenshot capture, window enumeration, keyboard/mouse/clipboard work and Vision target invocation run through the bounded operation runner. Shell execution owns its subprocess lifecycle directly so timeout or cancellation kills the child before returning.

Shell stdout/stderr are bounded independently. Results always include original byte counts, truncation booleans and the configured byte limit.

## Structured failure model

Failures expose `error_kind`:
- `transient`
- `stale_target`
- `ambiguous_target`
- `policy_blocked`
- `timeout`
- `cancelled`
- `executor_failure`

For Round-1 compatibility, `policy_blocked` uses result `status="blocked"` and `executor_failure` uses `status="error"`; the other structured kinds are also the status value.

## Side-effect outcome evidence

Side-effecting actions carry strict `pc_executor.action_outcome.v1` evidence. The executor records a provisional `unknown` audit event immediately before live adapter dispatch, then finalizes the result as `completed`, `not_started`, or `unknown`. Structured stale/ambiguous/policy failures prove no effect; timeout/cancellation/transient/unexpected failure after dispatch remain unknown. `unknown` is deliberately non-retry-safe and requires downstream verification/reconciliation.

This evidence layer is orthogonal to UIA resolution, cancellation, and verification logic: it does not duplicate Vision semantics or Control Plane state machines. It only reports what the local Executor can prove about its own side-effect attempt.

## Safety invariants

- Default mode is dry-run.
- UIA is primary; raw `mouse.click` remains disabled unless `allow_coordinate_fallback=True` is explicit.
- `vision.target.invoke` never consumes Vision coordinates and never invokes the raw input adapter.
- No credential/sensitive text entry. Password UIA controls are rejected.
- No CAPTCHA action exists.
- Shell uses `shell=False`, a conservative executable allowlist, and rejects `E:\manhwa` plus descendants.
- No destructive filesystem/process action is exposed by the public action set.
- Audit events omit typed/clipboard/value bodies.
