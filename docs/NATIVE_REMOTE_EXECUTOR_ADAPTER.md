# Native remote transport -> current parity Executor adapter

This integration binds the authenticated `pc_remote_transport` device channel to the
current `Executor` at tool-parity head
`18a6496b24520bade8246dae0759306a00a5a372`.

It does not add a second filesystem, process, shell-session, search, or system
implementation. Remote requests are translated to current structured Executor actions
and then pass through the existing Executor preflight, outcome journal, execution-context
validation, protected-path policy, bounded execution, and audit path.

## Provenance

Transport core is carried from
`e47908e2c734984a872f3cc087731f4690d1c82c`.

The authenticated dispatcher context hook and exports are carried from adapter candidate
`30d7cb0f0571c3bd1565fd6b96c069ef64f3d9dd`. The adapter module and its tests are
rebased onto the current tool-parity contracts rather than copied blindly.

No old Executor/context-binding files from the adapter candidate are carried. No
`github_relay` RPC dependency is used.
## Capability binding

`ExecutorRemoteDispatcher.capability_manifest()` obtains
`executor.operations.capabilities_snapshot()` from the integrated head.

The complete parity capability object is embedded unchanged as `tool_parity` in the
device hello capability manifest. Its attestation digest, native parity version, schema
versions, and supported action inventory are also projected into the `executor`
summary. The transport hashes the complete manifest into the authenticated hello.

Before every dispatch the adapter recomputes the current parity manifest. Any drift from
the hello-time digest fails as `CAPABILITY_DRIFT` before Executor dispatch.

The adapter registry has import-time invariants requiring every mapped action to be in
`OPS_ACTIONS` and requiring its read-only/side-effect classification to agree with
`OPS_SIDE_EFFECT_ACTIONS`.

## Current control-to-parity mappings

Representative mappings are:

- `file.read` -> `fs.read_text`
- `file.read_bytes` -> `fs.read_bytes`
- `file.write` / `file.append` -> `fs.write_text` / `fs.append_text`
- `file.edit` -> `fs.edit_text`
- `content.search` -> `fs.search`
- `process.start` -> `process.start`
- `process.read` -> `process.read_output`
- `process.list` -> `process.managed.list`
- `process.terminate` -> `process.terminate`
- `shell.session.open/read/write/close` ->
  `shell.session.start/read/write_stdin/terminate`
- `system.process.list` -> `process.list`
- `system.process.kill` -> `system.process.kill`
- `device.health` / `device.get_config` -> `health.get` / `config.get`

The observed Desktop Commander compatibility surface therefore remains backed by the
same parity primitives documented in
`tests/fixtures/native_tool_parity_v1/desktop_commander_mapping.json`.

## Side effects and reconciliation

The transport logical request ID must equal the control request ID. The adapter passes
that ID unchanged into `ActionRequest`, Executor preflight, outcome journaling, audit,
and the returned response.

Before a remote side effect, the adapter requires the Executor durable outcome journal
and checks for prior evidence for the same request/action. Existing evidence is never
treated as permission to replay.

If dispatch may have occurred but completion cannot be proven, the adapter raises
`UnknownDispatchOutcome`. `DeviceAgent` persists/surfaces that as
`UNKNOWN_RECONCILE` with `automatic_replay=false`.
## Session, handles, streaming, and protected paths

Authenticated transport context binds each dispatch to device ID, session epoch, and
the hello-time capability digest. Process/session handles returned by current parity
actions are additionally bound to the control session and transport epoch. Stale handles
fail closed after reconnect.

Streaming parity actions are projected into bounded transport bytes. Existing transport
framing retains ordered chunks, per-chunk SHA-256, whole-stream SHA-256, and total byte
limits.

Arguments that lexically resolve to `E:\manhwa` or descendants are rejected by the
adapter before preflight. This is additive to the current Executor protected-path
enforcement; tests use only path strings and never access that location.

## Verification

Focused coverage includes exact parity hello capabilities, request-ID preservation,
capability drift, stale epochs/contexts/handles, protected-path reject-before-dispatch,
result-loss deduplication, lost-ledger reconciliation, bounded file/process streaming,
and the observed Desktop Commander file/process lifecycle.
